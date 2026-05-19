//! Import credentials exported from other password managers.
//!
//! One small RFC-4180 CSV reader feeds a header-driven column mapper
//! that recognizes the CSV exports of Chrome/Edge/Brave, Firefox,
//! Bitwarden, KeePassXC and 1Password. Bitwarden's JSON export is also
//! handled (the most common non-CSV path). Everything is parsed
//! in-process — nothing is sent anywhere, and the parsed passwords go
//! straight into the encrypted vault via the normal add path.

use crate::storage::Account;

/// One credential lifted from a foreign export, before it becomes an
/// `Account`. Same shape as `Account` but standalone so this module
/// has no GUI/session coupling.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Imported {
    pub name: String,
    pub url: String,
    pub username: String,
    pub password: String,
    pub totp_secret: String,
    pub notes: String,
}

impl From<Imported> for Account {
    fn from(i: Imported) -> Account {
        Account {
            name: i.name,
            url: i.url,
            username: i.username,
            password: i.password,
            totp_secret: i.totp_secret,
            notes: i.notes,
            history: Vec::new(),
        }
    }
}

/// Parse an exported file. Auto-detects Bitwarden JSON vs. CSV. On
/// success returns `(human format name, entries)`; on failure a
/// human-readable message suitable for showing in the GUI.
pub fn parse(input: &str) -> Result<(String, Vec<Imported>), String> {
    // Strip a UTF-8 BOM (Edge/Excel love adding one) before sniffing.
    let trimmed = input.trim_start_matches('\u{feff}').trim_start();
    if trimmed.starts_with('{') {
        parse_bitwarden_json(trimmed)
    } else {
        parse_csv_export(input)
    }
}

// ----------------------- CSV -----------------------

/// Minimal RFC-4180 reader: quoted fields, `""` escapes, commas and
/// newlines inside quotes, LF or CRLF line endings. Returns rows of
/// fields; trailing blank lines are dropped.
fn read_csv(input: &str) -> Vec<Vec<String>> {
    let input = input.trim_start_matches('\u{feff}');
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut row: Vec<String> = Vec::new();
    let mut field = String::new();
    let mut in_quotes = false;
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
        } else {
            match c {
                '"' => in_quotes = true,
                ',' => row.push(std::mem::take(&mut field)),
                '\r' => {} // swallowed; the paired \n ends the row
                '\n' => {
                    row.push(std::mem::take(&mut field));
                    rows.push(std::mem::take(&mut row));
                }
                _ => field.push(c),
            }
        }
    }
    if !field.is_empty() || !row.is_empty() {
        row.push(field);
        rows.push(row);
    }
    while rows
        .last()
        .map(|r| r.iter().all(|f| f.trim().is_empty()))
        .unwrap_or(false)
    {
        rows.pop();
    }
    rows
}

fn col(header: &[String], names: &[&str]) -> Option<usize> {
    header.iter().position(|h| {
        let h = h.trim().trim_matches('"').to_ascii_lowercase();
        names.iter().any(|n| h == *n)
    })
}

/// Host portion of a URL, no scheme / path / `www.`. Best-effort, used
/// only to synthesize a display name when the export has none.
fn host_of(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return String::new();
    }
    let s = s.split("://").last().unwrap_or(s);
    let s = s.split('/').next().unwrap_or(s);
    let s = s.split('?').next().unwrap_or(s);
    let s = s.split('@').last().unwrap_or(s); // strip user:pass@
    s.trim().trim_start_matches("www.").to_string()
}

fn name_from(url: &str, username: &str) -> String {
    let h = host_of(url);
    if !h.is_empty() {
        h
    } else {
        username.to_string()
    }
}

fn parse_csv_export(input: &str) -> Result<(String, Vec<Imported>), String> {
    let rows = read_csv(input);
    if rows.is_empty() {
        return Err("File is empty or not valid CSV.".to_string());
    }
    let header = &rows[0];
    let hl: Vec<String> = header
        .iter()
        .map(|h| h.trim().trim_matches('"').to_ascii_lowercase())
        .collect();
    let has = |n: &str| hl.iter().any(|h| h == n);

    let name_i = col(header, &["name", "title", "account", "item name"]);
    let url_i = col(
        header,
        &[
            "url",
            "urls",
            "website",
            "web site",
            "login_uri",
            "login uri",
            "uri",
        ],
    );
    let user_i = col(
        header,
        &[
            "username",
            "user name",
            "user",
            "login_username",
            "login username",
            "email",
        ],
    );
    let pass_i = col(
        header,
        &["password", "login_password", "login password", "pass"],
    );
    let notes_i = col(header, &["notes", "note", "comments", "comment"]);
    let totp_i = col(
        header,
        &[
            "otpauth",
            "totp",
            "login_totp",
            "otp",
            "2fa",
            "two-factor secret",
        ],
    );

    let pass_i = pass_i.ok_or_else(|| {
        format!(
            "Couldn't find a password column. Columns were: {}",
            header.join(", ")
        )
    })?;

    let format = if has("login_uri") || has("login_password") {
        "Bitwarden CSV"
    } else if has("httprealm") || has("formactionorigin") {
        "Firefox CSV"
    } else if has("otpauth") && has("title") {
        "1Password CSV"
    } else if has("group") && has("title") {
        "KeePassXC CSV"
    } else if has("name") && has("url") {
        "Chrome/Edge CSV"
    } else {
        "Generic CSV"
    };

    let get = |row: &[String], i: Option<usize>| -> String {
        i.and_then(|i| row.get(i))
            .map(|s| s.trim().to_string())
            .unwrap_or_default()
    };

    let mut out = Vec::new();
    for row in rows.iter().skip(1) {
        if row.iter().all(|f| f.trim().is_empty()) {
            continue;
        }
        let password = get(row, Some(pass_i));
        let username = get(row, user_i);
        let url = get(row, url_i);
        // Folder/group rows and other non-credentials have neither a
        // password nor a username — skip them quietly.
        if password.is_empty() && username.is_empty() {
            continue;
        }
        let mut name = get(row, name_i);
        if name.is_empty() {
            name = name_from(&url, &username);
        }
        out.push(Imported {
            name,
            url,
            username,
            password,
            totp_secret: get(row, totp_i),
            notes: get(row, notes_i),
        });
    }
    if out.is_empty() {
        return Err("No credentials found in the file.".to_string());
    }
    Ok((format.to_string(), out))
}

// ----------------------- Bitwarden JSON -----------------------

fn parse_bitwarden_json(input: &str) -> Result<(String, Vec<Imported>), String> {
    let v: serde_json::Value =
        serde_json::from_str(input).map_err(|e| format!("Not valid JSON: {}", e))?;
    let items = v
        .get("items")
        .and_then(|i| i.as_array())
        .ok_or("JSON has no \"items\" array — is this a Bitwarden export?")?;

    let s = |val: Option<&serde_json::Value>| -> String {
        val.and_then(|x| x.as_str()).unwrap_or("").trim().to_string()
    };

    let mut out = Vec::new();
    for it in items {
        // Bitwarden item type 1 = login. Skip secure notes (2), cards
        // (3), identities (4) — we only model logins.
        if it.get("type").and_then(|t| t.as_i64()).unwrap_or(0) != 1 {
            continue;
        }
        let name = s(it.get("name"));
        let notes = s(it.get("notes"));
        let login = it.get("login");
        let username = s(login.and_then(|l| l.get("username")));
        let password = s(login.and_then(|l| l.get("password")));
        let totp = s(login.and_then(|l| l.get("totp")));
        let url = login
            .and_then(|l| l.get("uris"))
            .and_then(|u| u.as_array())
            .and_then(|a| a.first())
            .and_then(|f| f.get("uri"))
            .and_then(|x| x.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        if password.is_empty() && username.is_empty() {
            continue;
        }
        let name = if name.is_empty() {
            name_from(&url, &username)
        } else {
            name
        };
        out.push(Imported {
            name,
            url,
            username,
            password,
            totp_secret: totp,
            notes,
        });
    }
    if out.is_empty() {
        return Err("No login items found in the Bitwarden JSON.".to_string());
    }
    Ok(("Bitwarden JSON".to_string(), out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_csv() {
        let csv = "name,url,username,password,note\n\
                   GitHub,https://github.com/login,octocat,hunter2,\n\
                   Mail,https://mail.example.com,me@example.com,s3cret,personal\n";
        let (fmt, v) = parse(csv).unwrap();
        assert_eq!(fmt, "Chrome/Edge CSV");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "GitHub");
        assert_eq!(v[0].url, "https://github.com/login");
        assert_eq!(v[0].username, "octocat");
        assert_eq!(v[0].password, "hunter2");
        assert_eq!(v[1].notes, "personal");
    }

    #[test]
    fn firefox_csv() {
        let csv = "\"url\",\"username\",\"password\",\"httpRealm\",\"formActionOrigin\",\"guid\",\"timeCreated\"\n\
                   \"https://site.test\",\"alice\",\"pw-Alice-1\",\"\",\"https://site.test\",\"{abc}\",\"123\"\n";
        let (fmt, v) = parse(csv).unwrap();
        assert_eq!(fmt, "Firefox CSV");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].username, "alice");
        assert_eq!(v[0].password, "pw-Alice-1");
        // No name column → synthesized from the URL host.
        assert_eq!(v[0].name, "site.test");
    }

    #[test]
    fn bitwarden_csv() {
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   ,,login,My Bank,important,,0,https://bank.example,j.doe,Tr0ub4dour,JBSWY3DPEHPK3PXP\n\
                   work,,login,,,,0,https://intra.example,svc,robotpw,\n";
        let (fmt, v) = parse(csv).unwrap();
        assert_eq!(fmt, "Bitwarden CSV");
        assert_eq!(v.len(), 2);
        assert_eq!(v[0].name, "My Bank");
        assert_eq!(v[0].totp_secret, "JBSWY3DPEHPK3PXP");
        // Missing name → host of login_uri.
        assert_eq!(v[1].name, "intra.example");
    }

    #[test]
    fn keepassxc_csv() {
        let csv = "\"Group\",\"Title\",\"Username\",\"Password\",\"URL\",\"Notes\",\"TOTP\"\n\
                   \"Root\",\"Router\",\"admin\",\"adminpw\",\"http://192.168.1.1\",\"LAN\",\"\"\n";
        let (fmt, v) = parse(csv).unwrap();
        assert_eq!(fmt, "KeePassXC CSV");
        assert_eq!(v[0].name, "Router");
        assert_eq!(v[0].username, "admin");
        assert_eq!(v[0].notes, "LAN");
    }

    #[test]
    fn onepassword_csv() {
        let csv = "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n\
                   Dropbox,https://dropbox.com,user@x.io,dbx-pass,otpauth://totp/x?secret=ABC,,,,my notes\n";
        let (fmt, v) = parse(csv).unwrap();
        assert_eq!(fmt, "1Password CSV");
        assert_eq!(v[0].name, "Dropbox");
        assert_eq!(v[0].totp_secret, "otpauth://totp/x?secret=ABC");
        assert_eq!(v[0].notes, "my notes");
    }

    #[test]
    fn quoted_fields_with_commas_and_newlines() {
        let csv = "name,url,username,password,note\n\
                   \"Acme, Inc.\",https://acme.test,bob,\"p,w\nline2\",\"a \"\"quote\"\"\"\n";
        let (_, v) = parse(csv).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "Acme, Inc.");
        assert_eq!(v[0].password, "p,w\nline2");
        assert_eq!(v[0].notes, "a \"quote\"");
    }

    #[test]
    fn bitwarden_json() {
        let json = r#"{
          "items": [
            {"type":1,"name":"Reddit","notes":"throwaway",
             "login":{"username":"u1","password":"pw1","totp":"SECRET",
                      "uris":[{"uri":"https://reddit.com"}]}},
            {"type":2,"name":"A secure note","notes":"not a login"},
            {"type":1,"name":"","login":{"username":"only-user","password":"p2","uris":[{"uri":"https://x.test/login"}]}}
          ]
        }"#;
        let (fmt, v) = parse(json).unwrap();
        assert_eq!(fmt, "Bitwarden JSON");
        assert_eq!(v.len(), 2); // secure note skipped
        assert_eq!(v[0].name, "Reddit");
        assert_eq!(v[0].totp_secret, "SECRET");
        assert_eq!(v[1].name, "x.test"); // name synthesized from uri host
    }

    #[test]
    fn missing_password_column_is_an_error() {
        let csv = "name,url,username\nFoo,https://foo.test,bar\n";
        assert!(parse(csv).is_err());
    }

    #[test]
    fn empty_input_is_an_error() {
        assert!(parse("").is_err());
        assert!(parse("   \n  \n").is_err());
    }

    #[test]
    fn folder_only_rows_are_skipped() {
        // Bitwarden exports include rows that are just folders: no
        // username and no password.
        let csv = "folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp\n\
                   Social,,folder,Social,,,0,,,,\n\
                   ,,login,Twitter,,,0,https://twitter.com,birdperson,tweetpw,\n";
        let (_, v) = parse(csv).unwrap();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].name, "Twitter");
    }
}
