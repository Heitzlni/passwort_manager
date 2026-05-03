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

use crate::auth;
use crate::session::{self, InitialState, Session};
use crate::storage;

const DEFAULT_IDLE_TIMEOUT_SECS: u64 = 600;
const ENV_IDLE_TIMEOUT: &str = "PASSWORT_IDLE_TIMEOUT_SECS";
const MAX_CHECK_INTERVAL: Duration = Duration::from_secs(15);
const MIN_CHECK_INTERVAL: Duration = Duration::from_millis(500);

// =================== Protocol ===================

/// Outer envelope: every request optionally carries an auth_token. Status
/// and Register don't require it; everything else does.
#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope {
    #[serde(default)]
    pub auth_token: Option<String>,
    /// Optional human-readable label, sent on Register so the user knows
    /// what they're approving.
    #[serde(default)]
    pub client_label: Option<String>,
    #[serde(flatten)]
    pub op: Request,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    /// Returns whether the daemon currently holds an unlocked vault.
    /// No auth required.
    Status,
    /// Submit this client's API token + label for approval. Returns
    /// `pending_approval` (with a short_id the user must approve via
    /// `passwortctl approve`) or `ok` if it was already approved.
    /// No auth required (this IS the auth bootstrap).
    Register,
    /// Returns the current approval status of the auth_token in the
    /// envelope. No auth required.
    AuthStatus,
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
    /// Auth bootstrap response: tells the client its short_id and that
    /// it's pending user approval.
    PendingApproval {
        short_id: String,
        message: String,
    },
    /// Returned by AuthStatus.
    AuthStatusResp {
        /// "approved" / "pending" / "unknown"
        state: String,
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
    pub const CLIENT_UNAUTHORIZED: &str = "client_unauthorized";
    pub const CLIENT_PENDING: &str = "client_pending";
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
        if s.session.is_none() {
            continue;
        }
        if s.last_activity.elapsed() >= timeout {
            s.session = None;
            eprintln!("auto-locked after {}s idle", timeout.as_secs());
        } else if is_session_locked() {
            s.session = None;
            eprintln!("auto-locked: desktop session is locked");
        }
    }
}

/// Returns true if any of the current user's logind sessions reports
/// `LockedHint=yes` (screen locker engaged). systemd user services don't
/// always inherit `XDG_SESSION_ID`, so we list the user's sessions and
/// check each.
fn is_session_locked() -> bool {
    let user = match std::env::var("USER") {
        Ok(u) if !u.is_empty() => u,
        _ => return false,
    };
    let list = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend", "--no-pager"])
        .output();
    let stdout = match list {
        Ok(o) if o.status.success() => o.stdout,
        _ => return false,
    };
    let text = String::from_utf8_lossy(&stdout);
    for line in text.lines() {
        // Format: SESSION_ID UID USER SEAT TTY ...
        let mut parts = line.split_whitespace();
        let session_id = match parts.next() {
            Some(s) => s,
            None => continue,
        };
        let _uid = parts.next();
        let user_field = match parts.next() {
            Some(u) => u,
            None => continue,
        };
        if user_field != user {
            continue;
        }
        let out = std::process::Command::new("loginctl")
            .args([
                "show-session",
                session_id,
                "-p",
                "LockedHint",
                "--value",
            ])
            .output();
        if let Ok(o) = out {
            if o.status.success()
                && String::from_utf8_lossy(&o.stdout).trim() == "yes"
            {
                return true;
            }
        }
    }
    false
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
        let resp = match serde_json::from_str::<Envelope>(line.trim()) {
            Ok(env) => process_envelope(env, &state),
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

/// Top-level dispatcher: enforces auth for protected ops, lets the auth
/// bootstrap ops through unauthenticated.
fn process_envelope(env: Envelope, state: &Mutex<DaemonState>) -> Response {
    match &env.op {
        // Always-allowed ops
        Request::Status => return process_request(env.op, state),
        Request::Register => {
            let token = match env.auth_token.as_deref() {
                Some(t) if !t.is_empty() => t,
                _ => {
                    return error(
                        codes::BAD_REQUEST,
                        "Register requires auth_token in envelope",
                    )
                }
            };
            let label = env.client_label.as_deref().unwrap_or("(unlabeled client)");
            let mut list = auth::load();
            // Check if already approved → return Ok immediately.
            if auth::is_approved(&list, token) {
                return Response::Ok;
            }
            let id = match auth::record_pending(&mut list, token, label) {
                Some(id) => id,
                None => {
                    return error(codes::BAD_REQUEST, "auth_token must be valid base64")
                }
            };
            if let Err(e) = auth::save(&list) {
                return error(
                    codes::IO_ERROR,
                    format!("failed to record pending client: {}", e),
                );
            }
            Response::PendingApproval {
                short_id: id.clone(),
                message: format!(
                    "New client \"{}\" awaiting approval. Run: passwortctl approve {}",
                    label, id
                ),
            }
        }
        Request::AuthStatus => {
            let token = match env.auth_token.as_deref() {
                Some(t) if !t.is_empty() => t,
                _ => {
                    return Response::AuthStatusResp {
                        state: "unknown".into(),
                    }
                }
            };
            let list = auth::load();
            if auth::is_approved(&list, token) {
                return Response::AuthStatusResp {
                    state: "approved".into(),
                };
            }
            // Pending if its hash matches a pending entry
            if let Some(h) = auth::token_hash_hex(token) {
                let id = auth::short_id(&h);
                if list.pending.contains_key(&id) {
                    return Response::AuthStatusResp {
                        state: "pending".into(),
                    };
                }
            }
            Response::AuthStatusResp {
                state: "unknown".into(),
            }
        }
        // Everything else requires an approved token.
        _ => {
            let token = match env.auth_token.as_deref() {
                Some(t) if !t.is_empty() => t,
                _ => {
                    return error(
                        codes::CLIENT_UNAUTHORIZED,
                        "Missing auth_token. Send Register first, then ask the user to approve.",
                    )
                }
            };
            let list = auth::load();
            if !auth::is_approved(&list, token) {
                let h = auth::token_hash_hex(token);
                let pending = h
                    .as_ref()
                    .map(|hh| list.pending.contains_key(&auth::short_id(hh)))
                    .unwrap_or(false);
                let code = if pending {
                    codes::CLIENT_PENDING
                } else {
                    codes::CLIENT_UNAUTHORIZED
                };
                let msg = if pending {
                    "Client is awaiting user approval. Run `passwortctl approvals` to see and approve."
                } else {
                    "Client is not approved. Send Register first."
                };
                return error(code, msg);
            }
            process_request(env.op, state)
        }
    }
}

fn process_request(req: Request, state: &Mutex<DaemonState>) -> Response {
    match req {
        Request::Register | Request::AuthStatus => unreachable!("handled in process_envelope"),
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
                    // Match by (name, username) so a site can hold multiple
                    // accounts. Saving "github.com" / "alice" then
                    // "github.com" / "bob" creates two distinct entries;
                    // saving "github.com" / "alice" again updates that one.
                    //
                    // Special case for back-compat: if the request omitted
                    // a username (empty string) AND there's exactly one
                    // entry with this name regardless of username, update
                    // that one rather than creating an empty-username
                    // duplicate. This keeps single-entry-per-site users
                    // unsurprised.
                    let exact = sess
                        .accounts
                        .iter()
                        .position(|a| a.name == name && a.username == username);
                    let fallback = if username.is_empty() {
                        let same_name: Vec<usize> = sess
                            .accounts
                            .iter()
                            .enumerate()
                            .filter(|(_, a)| a.name == name)
                            .map(|(i, _)| i)
                            .collect();
                        if same_name.len() == 1 {
                            Some(same_name[0])
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                    let result = if let Some(idx) = exact.or(fallback) {
                        sess.edit_account(idx, None, None, Some(password), None)
                    } else {
                        sess.add_account(name, username, password, String::new())
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

// =================== Generic client helper ===================
//
// Open a one-shot connection to the daemon, send a single Request, read back
// the Response, hang up. Used by passwortctl, passwort-autotype, and the
// picker mode of the GUI binary.

pub fn rpc(req: &Request) -> std::io::Result<Response> {
    rpc_with_auth(req, None, None)
}

/// Same as `rpc` but attaches an auth_token (and optional client label
/// for Register requests) to the envelope.
pub fn rpc_with_auth(
    req: &Request,
    auth_token: Option<&str>,
    client_label: Option<&str>,
) -> std::io::Result<Response> {
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

    // Build envelope JSON manually so we can keep `req` borrowed.
    #[derive(serde::Serialize)]
    struct Out<'a> {
        #[serde(skip_serializing_if = "Option::is_none")]
        auth_token: Option<&'a str>,
        #[serde(skip_serializing_if = "Option::is_none")]
        client_label: Option<&'a str>,
        #[serde(flatten)]
        op: &'a Request,
    }
    let env = Out {
        auth_token,
        client_label,
        op: req,
    };

    let mut payload = serde_json::to_string(&env).map_err(|e| {
        std::io::Error::new(std::io::ErrorKind::Other, format!("serialize: {}", e))
    })?;
    payload.push('\n');
    writer.write_all(payload.as_bytes())?;
    writer.flush()?;
    drop(writer);

    let mut line = String::new();
    reader.read_line(&mut line)?;
    serde_json::from_str(line.trim()).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("bad response: {} ({:?})", e, line),
        )
    })
}

/// Read this client's API token from a config file. Auto-creates one
/// (random 32 bytes, base64) on first call. The file is at:
///   ~/.config/passwort-manager/<client>-token
/// Each client (passwortctl, passwort-autotype, native host) gets its
/// own so they can be approved/revoked independently.
pub fn load_or_create_token(client_name: &str) -> std::io::Result<String> {
    let dir = crate::config::config_dir();
    std::fs::create_dir_all(&dir)?;
    let path = dir.join(format!("{}-token", client_name));
    if let Ok(s) = std::fs::read_to_string(&path) {
        let s = s.trim();
        if !s.is_empty() {
            return Ok(s.to_string());
        }
    }
    let tok = crate::auth::random_token_b64();
    std::fs::write(&path, &tok)?;
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
    Ok(tok)
}

/// Convenience for clients: sends Register if necessary, then runs the
/// real request. Returns the daemon's response to the real request.
pub fn rpc_authed(client_name: &str, req: &Request) -> std::io::Result<Response> {
    let token = load_or_create_token(client_name)?;
    // Register on each call — daemon is a no-op if already approved, so
    // this is cheap and recovers gracefully if the user revoked.
    let _ = rpc_with_auth(&Request::Register, Some(&token), Some(client_name))?;
    rpc_with_auth(req, Some(&token), None)
}

// =================== Control client (passwortctl) ===================

pub fn run_ctl() -> std::io::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(|s| s.as_str()).unwrap_or("");
    if cmd.is_empty() || cmd == "-h" || cmd == "--help" || cmd == "help" {
        print_usage();
        return Ok(());
    }

    // Approval-management commands operate on the local allowlist file
    // directly (no IPC, no auth needed — the file is in the user's home).
    match cmd {
        "approvals" => return cmd_approvals(),
        "approve" => {
            let id = args.get(2).cloned().ok_or_else(|| usage_err("approve <id>"))?;
            return cmd_approve(&id);
        }
        "revoke" => {
            let id = args.get(2).cloned().ok_or_else(|| usage_err("revoke <id>"))?;
            return cmd_revoke(&id);
        }
        _ => {}
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

    let resp = rpc_authed("passwortctl", &req)?;
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
        Response::PendingApproval { short_id, message } => {
            eprintln!("pending approval (short_id={}): {}", short_id, message);
            std::process::exit(3);
        }
        Response::AuthStatusResp { state } => {
            println!("{}", state);
        }
    }

    Ok(())
}

fn cmd_approvals() -> std::io::Result<()> {
    let list = auth::load();
    if list.pending.is_empty() && list.approved.is_empty() {
        println!("(no clients registered yet)");
        return Ok(());
    }
    if !list.pending.is_empty() {
        println!("PENDING (run `passwortctl approve <id>` to grant):");
        for (id, p) in &list.pending {
            println!("  {}  {}  ({})", id, p.label, p.requested_at);
        }
    }
    if !list.approved.is_empty() {
        println!("APPROVED (run `passwortctl revoke <id>` to remove):");
        for (id, a) in &list.approved {
            println!("  {}  {}  ({})", id, a.label, a.approved_at);
        }
    }
    Ok(())
}

fn cmd_approve(id: &str) -> std::io::Result<()> {
    let mut list = auth::load();
    if !auth::approve(&mut list, id) {
        eprintln!("no pending client with id {}", id);
        std::process::exit(2);
    }
    auth::save(&list)?;
    println!("approved {}", id);
    Ok(())
}

fn cmd_revoke(id: &str) -> std::io::Result<()> {
    let mut list = auth::load();
    if !auth::revoke(&mut list, id) {
        eprintln!("no client with id {}", id);
        std::process::exit(2);
    }
    auth::save(&list)?;
    println!("revoked {}", id);
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
    eprintln!("    approvals           List pending and approved API clients");
    eprintln!("    approve <id>        Grant a pending client access to the vault");
    eprintln!("    revoke <id>         Remove a client (pending or approved)");
    eprintln!();
    eprintln!("ENVIRONMENT:");
    eprintln!("    PASSWORT_IDLE_TIMEOUT_SECS  daemon auto-lock idle timeout (default 600, 0 = off)");
    eprintln!("    PASSWORT_VAULT_PATH         override vault file location");
}
