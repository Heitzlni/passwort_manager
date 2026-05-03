//! Browser native-messaging bridge.
//!
//! Browsers spawn this binary on demand and speak to it over stdin/stdout
//! with a length-prefixed JSON protocol (4-byte little-endian length, then
//! the UTF-8 JSON body). This module reads each framed request from stdin,
//! relays the JSON to the daemon over its Unix socket as NDJSON, reads the
//! NDJSON response, and writes it back to stdout with the same length frame.
//!
//! If the daemon is unreachable, the host emits one structured error
//! response (so the extension can show a useful message) and exits.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

use serde_json::Value;

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1 MiB; browser default is also ~1 MiB.

pub fn run() -> io::Result<()> {
    let socket_path = crate::ipc::socket_path();
    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            // Tell the browser, in our own protocol, why we couldn't proceed.
            let err = serde_json::json!({
                "kind": "error",
                "code": "daemon_unavailable",
                "message": format!(
                    "could not connect to daemon at {}: {}. Is `passwortd` running?",
                    socket_path.display(),
                    e
                )
            });
            let payload = err.to_string();
            write_framed(payload.as_bytes())?;
            return Ok(());
        }
    };

    // Load this client's token. Browser-side messages don't carry an
    // auto-generated token — we attach the host's token before forwarding,
    // and Register on first run so the user can approve via passwortctl.
    let token = crate::ipc::load_or_create_token("passwort-native-host")?;

    let mut to_daemon = stream.try_clone()?;
    let mut from_daemon = BufReader::new(stream);

    // Best-effort one-shot Register so the user can approve us before any
    // real request comes in.
    {
        let reg = serde_json::json!({
            "auth_token": &token,
            "client_label": "Firefox extension (via native host)",
            "op": "register",
        });
        let s = reg.to_string() + "\n";
        let _ = to_daemon.write_all(s.as_bytes());
        let _ = to_daemon.flush();
        let mut sink = String::new();
        let _ = from_daemon.read_line(&mut sink);
    }

    let stdin = io::stdin();
    let stdout = io::stdout();
    let mut input = stdin.lock();
    let mut output = stdout.lock();

    let mut len_buf = [0u8; 4];
    loop {
        match input.read_exact(&mut len_buf) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
            Err(e) => return Err(e),
        }
        let len = u32::from_le_bytes(len_buf);
        if len > MAX_MESSAGE_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("message length {} exceeds {} byte cap", len, MAX_MESSAGE_SIZE),
            ));
        }

        let mut body = vec![0u8; len as usize];
        input.read_exact(&mut body)?;

        // Re-serialize the browser's body into an envelope that injects
        // our auth_token. Parse → mutate → re-serialize is the cleanest
        // way to keep the existing browser-side schema unchanged.
        let mut json: Value = serde_json::from_slice(&body).unwrap_or(Value::Null);
        if let Value::Object(map) = &mut json {
            map.insert("auth_token".to_string(), Value::String(token.clone()));
        }
        let payload = json.to_string();

        // Forward to daemon as NDJSON.
        to_daemon.write_all(payload.as_bytes())?;
        to_daemon.write_all(b"\n")?;
        to_daemon.flush()?;

        // Read one NDJSON response line from daemon.
        let mut response = String::new();
        let n = from_daemon.read_line(&mut response)?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "daemon closed the connection",
            ));
        }
        let payload = response.trim_end_matches(['\n', '\r']).as_bytes();
        write_framed_to(&mut output, payload)?;
    }
}

fn write_framed(body: &[u8]) -> io::Result<()> {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    write_framed_to(&mut out, body)
}

fn write_framed_to<W: Write>(out: &mut W, body: &[u8]) -> io::Result<()> {
    let len = body.len() as u32;
    out.write_all(&len.to_le_bytes())?;
    out.write_all(body)?;
    out.flush()
}
