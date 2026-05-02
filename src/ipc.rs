//! Inter-process protocol for the password-manager daemon.
//!
//! ```text
//!   passwortd ──── unix socket ──── passwortctl
//!                        │
//!                        └────── native-messaging host (browsers)
//! ```
//!
//! Messages are NDJSON: one JSON object per line, terminated by `\n`.
//! The daemon owns the unlocked Session; clients send requests and receive
//! responses over a Unix domain socket at `$XDG_RUNTIME_DIR/passwort-manager.sock`
//! (falling back to `/tmp/passwort-manager-<UID>.sock`).
//!
//! Every accepted connection has its peer UID checked against ours via
//! `SO_PEERCRED` on Linux; same-host other-user processes are refused.
//!
//! The daemon auto-locks after a configurable idle timeout (env var
//! `PASSWORT_IDLE_TIMEOUT_SECS`, default 600 s). Setting it to 0 disables
//! auto-lock.

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::session::{self, InitialState, Session};
use crate::storage;

const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 600;
const ENV_IDLE_TIMEOUT: &str = "PASSWORT_IDLE_TIMEOUT_SECS";
const MAX_CHECK_INTERVAL: Duration = Duration::from_secs(15);
const MIN_CHECK_INTERVAL: Duration = Duration::from_millis(500);

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
    /// Returns name + username for every account (no passwords).
    /// Useful when a UI wants to show "user@site" entries before fill.
    ListEntries,
    /// Returns the credential (name, username, password) for the given name.
    Get { name: String },
    /// Upserts. Username is optional for backward compatibility.
    Save {
        name: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    /// Deletes the account with the given name.
    Delete { name: String },
}

/// Lightweight view of an account, no password attached.
#[derive(Debug, Serialize, Deserialize)]
pub struct EntryRef {
    pub name: String,
    #[serde(default)]
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Response {
    Ok,
    Status {
        unlocked: bool,
        account_count: usize,
        /// Seconds since the last vault-touching operation. Only set when unlocked.
        #[serde(skip_serializing_if = "Option::is_none")]
        idle_secs: Option<u64>,
        /// Configured auto-lock timeout in seconds. 0 means disabled. Always set.
        auto_lock_secs: u64,
    },
    Names {
        names: Vec<String>,
    },
    Entries {
        entries: Vec<EntryRef>,
    },
    Credential {
        name: String,
        #[serde(default)]
        username: String,
        password: String,
    },
    Error {
        /// Stable machine-readable code (e.g. "locked", "wrong_password",
        /// "not_found"). Lets clients branch without parsing the message.
        code: String,
        message: String,
    },
}

// Error code constants — kept in one place so clients and the daemon agree.
pub mod codes {
    pub const LOCKED: &str = "locked";
    pub const WRONG_PASSWORD: &str = "wrong_password";
    pub const NOT_FOUND: &str = "not_found";
    pub const VAULT_UNINITIALIZED: &str = "vault_uninitialized";
    pub const VAULT_CORRUPTED: &str = "vault_corrupted";
    pub const IO_ERROR: &str = "io_error";
    pub const BAD_REQUEST: &str = "bad_request";
}

fn error(code: &str, message: impl Into<String>) -> Response {
    Response::Error {
        code: code.into(),
        message: message.into(),
    }
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

fn idle_timeout() -> Duration {
    let secs = std::env::var(ENV_IDLE_TIMEOUT)
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(DEFAULT_IDLE_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

// =================== Daemon state ===================

struct DaemonState {
    session: Option<Session>,
    last_activity: Instant,
}

type SharedState = Arc<Mutex<DaemonState>>;

// =================== Daemon ===================

pub fn run_daemon() -> std::io::Result<()> {
    let path = socket_path();

    // Stale-socket detection: if the file exists, try connecting. A successful
    // connect means another daemon is alive, so refuse to start.
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

    let timeout = idle_timeout();

    eprintln!("passwortd listening on {}", path.display());
    eprintln!("  vault: {}", storage::vault_path().display());
    if timeout.as_secs() == 0 {
        eprintln!("  auto-lock: disabled");
    } else {
        eprintln!("  auto-lock: {}s idle", timeout.as_secs());
    }

    let state: SharedState = Arc::new(Mutex::new(DaemonState {
        session: None,
        last_activity: Instant::now(),
    }));

    // Background thread: lock the session if it has been idle too long.
    if timeout.as_secs() > 0 {
        let state = state.clone();
        thread::Builder::new()
            .name("auto-lock".into())
            .spawn(move || auto_lock_loop(state, timeout))?;
    }

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

fn auto_lock_loop(state: SharedState, timeout: Duration) {
    // Check ~4× per timeout window, clamped so very long timeouts still get
    // sub-minute granularity and very short timeouts don't hot-spin.
    let interval = (timeout / 4).clamp(MIN_CHECK_INTERVAL, MAX_CHECK_INTERVAL);
    loop {
        thread::sleep(interval);
        let mut s = state.lock().unwrap();
        if s.session.is_some() && s.last_activity.elapsed() >= timeout {
            s.session = None;
            eprintln!("auto-locked after {}s idle", timeout.as_secs());
        }
    }
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
    Ok(())
}

fn handle_client(stream: UnixStream, state: SharedState) -> std::io::Result<()> {
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Ok(());
        }
        let resp = match serde_json::from_str::<Request>(line.trim()) {
            Ok(req) => process_request(req, &state),
            Err(e) => error(codes::BAD_REQUEST, format!("bad request: {}", e)),
        };
        let mut payload = serde_json::to_string(&resp).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, format!("serialize: {}", e))
        })?;
        payload.push('\n');
        writer.write_all(payload.as_bytes())?;
        writer.flush()?;
    }
}

fn process_request(req: Request, state: &Mutex<DaemonState>) -> Response {
    match req {
        Request::Status => {
            let s = state.lock().unwrap();
            let unlocked = s.session.is_some();
            Response::Status {
                unlocked,
                account_count: s.session.as_ref().map(|s| s.accounts.len()).unwrap_or(0),
                idle_secs: if unlocked {
                    Some(s.last_activity.elapsed().as_secs())
                } else {
                    None
                },
                auto_lock_secs: idle_timeout().as_secs(),
            }
        }

        Request::Unlock { mut password } => {
            let mut s = state.lock().unwrap();
            if s.session.is_some() {
                s.last_activity = Instant::now();
                password.zeroize();
                return Response::Ok;
            }
            let resp = match session::initial_state() {
                InitialState::NeedsLogin(vault) => {
                    match session::login(&vault, password.as_bytes()) {
                        Ok(sess) => {
                            s.session = Some(sess);
                            s.last_activity = Instant::now();
                            Response::Ok
                        }
                        Err(_) => error(codes::WRONG_PASSWORD, "wrong password"),
                    }
                }
                InitialState::NeedsLoginLegacy(vault) => {
                    match session::login_legacy(&vault, password.as_bytes()) {
                        Ok(sess) => {
                            s.session = Some(sess);
                            s.last_activity = Instant::now();
                            Response::Ok
                        }
                        Err(_) => error(codes::WRONG_PASSWORD, "wrong password"),
                    }
                }
                InitialState::NeedsSetup(_) => error(
                    codes::VAULT_UNINITIALIZED,
                    "vault not initialized; create one with the GUI/CLI first",
                ),
                InitialState::Corrupted => {
                    error(codes::VAULT_CORRUPTED, "vault file is corrupted")
                }
                InitialState::IoError(e) => {
                    error(codes::IO_ERROR, format!("vault io error: {}", e))
                }
            };
            // Wipe the deserialized password regardless of which branch ran.
            password.zeroize();
            resp
        }

        Request::Lock => {
            let mut s = state.lock().unwrap();
            s.session = None;
            Response::Ok
        }

        Request::List { filter } => {
            let mut s = state.lock().unwrap();
            match s.session.as_ref() {
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
                    s.last_activity = Instant::now();
                    Response::Names { names }
                }
            }
        }

        Request::ListEntries => {
            let mut s = state.lock().unwrap();
            match s.session.as_ref() {
                None => locked_error(),
                Some(sess) => {
                    let entries: Vec<EntryRef> = sess
                        .accounts
                        .iter()
                        .map(|a| EntryRef {
                            name: a.name.clone(),
                            username: a.username.clone(),
                        })
                        .collect();
                    s.last_activity = Instant::now();
                    Response::Entries { entries }
                }
            }
        }

        Request::Get { name } => {
            let mut s = state.lock().unwrap();
            match s.session.as_ref() {
                None => locked_error(),
                Some(sess) => match sess.accounts.iter().find(|a| a.name == name) {
                    Some(acc) => {
                        let cred = Response::Credential {
                            name: acc.name.clone(),
                            username: acc.username.clone(),
                            password: acc.password.clone(),
                        };
                        s.last_activity = Instant::now();
                        cred
                    }
                    None => error(codes::NOT_FOUND, "not found"),
                },
            }
        }

        Request::Save {
            name,
            username,
            password,
        } => {
            let mut s = state.lock().unwrap();
            match s.session.as_mut() {
                None => locked_error(),
                Some(sess) => {
                    let result = if let Some(idx) =
                        sess.accounts.iter().position(|a| a.name == name)
                    {
                        // Only overwrite username if a non-empty one was sent;
                        // empty means "keep existing".
                        let username_opt = if username.is_empty() {
                            None
                        } else {
                            Some(username)
                        };
                        sess.edit_account(idx, None, username_opt, Some(password))
                    } else {
                        sess.add_account(name, username, password)
                    };
                    match result {
                        Ok(_) => {
                            s.last_activity = Instant::now();
                            Response::Ok
                        }
                        Err(e) => error(codes::IO_ERROR, e.to_string()),
                    }
                }
            }
        }

        Request::Delete { name } => {
            let mut s = state.lock().unwrap();
            match s.session.as_mut() {
                None => locked_error(),
                Some(sess) => {
                    if let Some(idx) = sess.accounts.iter().position(|a| a.name == name) {
                        match sess.delete_account(idx) {
                            Ok(_) => {
                                s.last_activity = Instant::now();
                                Response::Ok
                            }
                            Err(e) => error(codes::IO_ERROR, e.to_string()),
                        }
                    } else {
                        error(codes::NOT_FOUND, "not found")
                    }
                }
            }
        }
    }
}

fn locked_error() -> Response {
    error(codes::LOCKED, "vault is locked; run `passwortctl unlock` first")
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
        "entries" => Request::ListEntries,
        "unlock" => {
            let pw = read_password("Master password: ")?;
            Request::Unlock { password: pw }
        }
        "get" => {
            let name = args.get(2).cloned().ok_or_else(|| usage_err("get <name>"))?;
            Request::Get { name }
        }
        "save" => {
            let name = args
                .get(2)
                .cloned()
                .ok_or_else(|| usage_err("save <name> [<username>]"))?;
            let username = args.get(3).cloned().unwrap_or_default();
            let pw = read_password(&format!("Password for '{}': ", name))?;
            Request::Save {
                name,
                username,
                password: pw,
            }
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
            idle_secs,
            auto_lock_secs,
        } => {
            if unlocked {
                let suffix = if auto_lock_secs == 0 {
                    String::new()
                } else if let Some(idle) = idle_secs {
                    let remaining = auto_lock_secs.saturating_sub(idle);
                    format!(", auto-locks in {}s", remaining)
                } else {
                    String::new()
                };
                println!(
                    "unlocked ({} account{}{})",
                    account_count,
                    if account_count == 1 { "" } else { "s" },
                    suffix
                );
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
        Response::Entries { entries } => {
            if entries.is_empty() {
                eprintln!("(no accounts)");
            } else {
                for e in entries {
                    if e.username.is_empty() {
                        println!("{}", e.name);
                    } else {
                        println!("{}\t{}", e.name, e.username);
                    }
                }
            }
        }
        Response::Credential {
            name,
            username,
            password,
        } => {
            if username.is_empty() {
                println!("{}\t{}", name, password);
            } else {
                println!("{}\t{}\t{}", name, username, password);
            }
        }
        Response::Error { code, message } => {
            eprintln!("error [{}]: {}", code, message);
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
    eprintln!("    status              Show whether the vault is unlocked + idle / auto-lock info");
    eprintln!("    unlock              Decrypt the vault into the daemon (prompts)");
    eprintln!("    lock                Drop the in-memory session");
    eprintln!("    list [filter]       List account names (optional substring match)");
    eprintln!("    entries             List name + username for every account");
    eprintln!("    get <name>          Print '<name>\\t[<username>\\t]<password>' for the named account");
    eprintln!("    save <name> [user]  Create or update an account (prompts for password)");
    eprintln!("    delete <name>       Delete the named account");
    eprintln!();
    eprintln!("ENVIRONMENT:");
    eprintln!("    PASSWORT_IDLE_TIMEOUT_SECS  daemon auto-lock idle timeout (default 600, 0 = off)");
    eprintln!("    PASSWORT_VAULT_PATH         override vault file location");
}
