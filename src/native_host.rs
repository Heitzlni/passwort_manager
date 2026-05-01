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

    let mut to_daemon = stream.try_clone()?;
    let mut from_daemon = BufReader::new(stream);

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

        // Forward to daemon as NDJSON.
        to_daemon.write_all(&body)?;
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
