//! Inter-process protocol for the password-manager daemon.
//!
//! ```text
//!   passwortd ──── unix socket ──── passwortctl
//!                        │
//!                        └────── (later) native-messaging host
//! ```
//!
//! Messages are NDJSON: one JSON object per line, terminated by `\n`.
//! The daemon owns the unlocked Session; clients send requests and receive
//! responses over a Unix domain socket at `$XDG_RUNTIME_DIR/passwort-manager.sock`
//! (falling back to `/tmp/passwort-manager-<UID>.sock`).
//!
//! Every accepted connection has its peer UID checked against ours via
//! `SO_PEERCRED` on Linux; same-host other-user processes are refused.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;

use serde::{Deserialize, Serialize};

use crate::session::{self, InitialState, Session};
use crate::storage;

// =================== Protocol ===================

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Returns whether the daemon currently holds an unlocked vault.
    Status,
    /// Decrypts the vault from disk with this master password and caches
    /// the unlocked session in memory. Idempotent if already unlocked.
    Unlock { password: String },
    /// Drops the in-memory session and zeros the key.
    Lock,
    /// Returns account names. `filter` is a substring match on the name.
    List {
        #[serde(default)]
        filter: Option<String>,
    },
    /// Returns the password for an account by exact name.
    Get { name: String },
    /// Upserts: updates an existing account by name, or creates a new one.
    Save { name: String, password: String },
    /// Deletes the account with the given name.
    Delete { name: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Status {
        unlocked: bool,
        account_count: usize,
    },
    Names {
        names: Vec<String>,
    },
    Credential {
        name: String,
        password: String,
    },
    Error {
        message: String,
    },
}

// =================== Socket location ===================

pub fn socket_path() -> PathBuf {
    if let Some(rt) = std::env::var_os("XDG_RUNTIME_DIR") {
        let p = PathBuf::from(rt);
        if p.is_absolute() {
            return p.join("passwort-manager.sock");
        }
    }
    let uid = unsafe { libc::getuid() };
    PathBuf::from(format!("/tmp/passwort-manager-{}.sock", uid))
}

// =================== Daemon ===================

type SharedSession = Arc<Mutex<Option<Session>>>;

pub fn run_daemon() -> std::io::Result<()> {
    let path = socket_path();

    // Detect a stale socket from a previous crashed daemon: try to connect.
    // A successful connect means another daemon is alive — refuse to start.
    if path.exists() {
        match UnixStream::connect(&path) {
            Ok(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("daemon already running at {}", path.display()),
                ));
            }
            Err(_) => {
                let _ = fs::remove_file(&path);
            }
        }
    }

    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let listener = UnixListener::bind(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;

    eprintln!("passwortd listening on {}", path.display());
    eprintln!("  vault: {}", storage::vault_path().display());

    let state: SharedSession = Arc::new(Mutex::new(None));

    for stream in listener.incoming() {
        let stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("accept error: {}", e);
                continue;
            }
        };
        if let Err(e) = verify_peer_uid(&stream) {
            eprintln!("rejecting peer: {}", e);
            continue;
        }
        let state = state.clone();
        thread::spawn(move || {
            if let Err(e) = handle_client(stream, state) {
                eprintln!("client error: {}", e);
            }
        });
    }

    Ok(())
}

#[cfg(target_os = "linux")]
fn verify_peer_uid(stream: &UnixStream) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;

    let fd = stream.as_raw_fd();
    let mut cred: libc::ucred = unsafe { std::mem::zeroed() };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let ret = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut _ as *mut libc::c_void,
            &mut len,
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    let our_uid = unsafe { libc::getuid() };
    if cred.uid != our_uid {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("peer uid {} != our uid {}", cred.uid, our_uid),
        ));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn verify_peer_uid(_stream: &UnixStream) -> std::io::Result<()> {
    // On non-Linux we rely on the socket's 0600 permissions only.
    Ok(())
}

fn handle_client(stream: UnixStream, state: SharedSession) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(()); // peer closed
        }
        let resp = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => process_request(req, &state),
            Err(e) => Response::Error {
                message: format!("bad request: {}", e),
            },
        };
        let mut payload = serde_json::to_string(&resp).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("serialize: {}", e))
        })?;
        payload.push('\n');
        writer.write_all(payload.as_bytes())?;
        writer.flush()?;
    }
}

fn process_request(req: Request, state: &Mutex<Option<Session>>) -> Response {
    match req {
        Request::Status => {
            let s = state.lock().unwrap();
            Response::Status {
                unlocked: s.is_some(),
                account_count: s.as_ref().map(|s| s.accounts.len()).unwrap_or(0),
            }
        }

        Request::Unlock { password } => {
            let mut s = state.lock().unwrap();
            if s.is_some() {
                return Response::Ok;
            }
            match session::initial_state() {
                InitialState::NeedsLogin(vault) => {
                    match session::login(&vault, password.as_bytes()) {
                        Ok(sess) => {
                            *s = Some(sess);
                            Response::Ok
                        }
                        Err(_) => Response::Error {
                            message: "wrong password".into(),
                        },
                    }
                }
                InitialState::NeedsLoginLegacy(vault) => {
                    match session::login_legacy(&vault, password.as_bytes()) {
                        Ok(sess) => {
                            *s = Some(sess);
                            Response::Ok
                        }
                        Err(_) => Response::Error {
                            message: "wrong password".into(),
                        },
                    }
                }
                InitialState::NeedsSetup(_) => Response::Error {
                    message: "vault not initialized; create one with the GUI/CLI first".into(),
                },
                InitialState::Corrupted => Response::Error {
                    message: "vault file is corrupted".into(),
                },
                InitialState::IoError(e) => Response::Error {
                    message: format!("vault io error: {}", e),
                },
            }
        }

        Request::Lock => {
            *state.lock().unwrap() = None;
            Response::Ok
        }

        Request::List { filter } => {
            let s = state.lock().unwrap();
            match s.as_ref() {
                None => locked_error(),
                Some(sess) => {
                    let names: Vec<String> = sess
                        .accounts
                        .iter()
                        .filter(|a| match filter.as_deref() {
                            Some(f) => a.name.contains(f),
                            None => true,
                        })
                        .map(|a| a.name.clone())
                        .collect();
                    Response::Names { names }
                }
            }
        }

        Request::Get { name } => {
            let s = state.lock().unwrap();
            match s.as_ref() {
                None => locked_error(),
                Some(sess) => match sess.accounts.iter().find(|a| a.name == name) {
                    Some(acc) => Response::Credential {
                        name: acc.name.clone(),
                        password: acc.password.clone(),
                    },
                    None => Response::Error {
                        message: "not found".into(),
                    },
                },
            }
        }

        Request::Save { name, password } => {
            let mut s = state.lock().unwrap();
            match s.as_mut() {
                None => locked_error(),
                Some(sess) => {
                    if let Some(idx) = sess.accounts.iter().position(|a| a.name == name) {
                        match sess.edit_account(idx, None, Some(password)) {
                            Ok(_) => Response::Ok,
                            Err(e) => Response::Error {
                                message: e.to_string(),
                            },
                        }
                    } else {
                        match sess.add_account(name, password) {
                            Ok(_) => Response::Ok,
                            Err(e) => Response::Error {
                                message: e.to_string(),
                            },
                        }
                    }
                }
            }
        }

        Request::Delete { name } => {
            let mut s = state.lock().unwrap();
            match s.as_mut() {
                None => locked_error(),
                Some(sess) => {
                    if let Some(idx) = sess.accounts.iter().position(|a| a.name == name) {
                        match sess.delete_account(idx) {
                            Ok(_) => Response::Ok,
                            Err(e) => Response::Error {
                                message: e.to_string(),
                            },
                        }
                    } else {
                        Response::Error {
                            message: "not found".into(),
                        }
                    }
                }
            }
        }
    }
}

fn locked_error() -> Response {
    Response::Error {
        message: "vault is locked; run `passwortctl unlock` first".into(),
    }
}

// =================== Control client (passwortctl) ===================

pub fn run_ctl() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    if cmd.is_empty() || cmd == "-h" || cmd == "--help" || cmd == "help" {
        print_usage();
        return Ok(());
    }

    let req = match cmd {
        "status" => Request::Status,
        "lock" => Request::Lock,
        "list" => Request::List {
            filter: args.get(2).cloned(),
        },
        "unlock" => {
            let pw = read_password("Master password: ")?;
            Request::Unlock { password: pw }
        }
        "get" => {
            let name = args
                .get(2)
                .cloned()
                .ok_or_else(|| usage_err("get <name>"))?;
            Request::Get { name }
        }
        "save" => {
            let name = args
                .get(2)
                .cloned()
                .ok_or_else(|| usage_err("save <name>"))?;
            let pw = read_password(&format!("Password for '{}': ", name))?;
            Request::Save { name, password: pw }
        }
        "delete" => {
            let name = args
                .get(2)
                .cloned()
                .ok_or_else(|| usage_err("delete <name>"))?;
            Request::Delete { name }
        }
        _ => {
            print_usage();
            std::process::exit(1);
        }
    };

    let path = socket_path();
    let stream = UnixStream::connect(&path).map_err(|e| {
        std::io::Error::new(
            e.kind(),
            format!(
                "could not connect to daemon at {} ({}). Is `passwortd` running?",
                path.display(),
                e
            ),
        )
    })?;
    let mut writer = stream.try_clone()?;
    let mut reader = BufReader::new(stream);

    let mut payload = serde_json::to_string(&req).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("serialize: {}", e))
    })?;
    payload.push('\n');
    writer.write_all(payload.as_bytes())?;
    writer.flush()?;
    drop(writer);

    let mut line = String::new();
    reader.read_line(&mut line)?;
    let resp: Response = serde_json::from_str(line.trim()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad response: {} ({:?})", e, line),
        )
    })?;

    match resp {
        Response::Ok => println!("ok"),
        Response::Status {
            unlocked,
            account_count,
        } => {
            if unlocked {
                println!("unlocked ({} account{})", account_count,
                    if account_count == 1 { "" } else { "s" });
            } else {
                println!("locked");
            }
        }
        Response::Names { names } => {
            if names.is_empty() {
                eprintln!("(no accounts match)");
            } else {
                for n in names {
                    println!("{}", n);
                }
            }
        }
        Response::Credential { name, password } => {
            println!("{}\t{}", name, password);
        }
        Response::Error { message } => {
            eprintln!("error: {}", message);
            std::process::exit(2);
        }
    }

    Ok(())
}

fn read_password(prompt: &str) -> std::io::Result<String> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        rpassword::prompt_password(prompt).map_err(|e| std::io::Error::new(e.kind(), e))
    } else {
        // Piped stdin (test/automation): can't suppress echo without a TTY.
        let mut stderr = std::io::stderr();
        let _ = stderr.write_all(prompt.as_bytes());
        let _ = stderr.flush();
        let mut s = String::new();
        std::io::stdin().read_line(&mut s)?;
        Ok(s.trim_end_matches('\n').trim_end_matches('\r').to_string())
    }
}

fn usage_err(usage: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, format!("usage: {}", usage))
}

fn print_usage() {
    eprintln!("passwortctl - control the password-manager daemon");
    eprintln!();
    eprintln!("USAGE:");
    eprintln!("    passwortctl <command> [args]");
    eprintln!();
    eprintln!("COMMANDS:");
    eprintln!("    status              Show whether the vault is unlocked");
    eprintln!("    unlock              Decrypt the vault into the daemon (prompts)");
    eprintln!("    lock                Drop the in-memory session");
    eprintln!("    list [filter]       List account names (optional substring match)");
    eprintln!("    get <name>          Print '<name>\\t<password>' for the named account");
    eprintln!("    save <name>         Create or update an account (prompts for password)");
    eprintln!("    delete <name>       Delete the named account");
}
