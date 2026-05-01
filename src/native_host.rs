//! Browser native-messaging bridge.
//!
//! Browsers spawn this binary on demand and speak to it over stdin/stdout
//! with a length-prefixed JSON protocol (4-byte little-endian length, then
//! the UTF-8 JSON body). This module reads each framed request from stdin,
//! relays the JSON to the daemon over its Unix socket as NDJSON, reads the
//! NDJSON response, and writes it back to stdout with the same length frame.
//!
//! The host is stateless apart from a single open daemon connection; it
//! runs only while the browser is connected and exits when stdin closes.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;

const MAX_MESSAGE_SIZE: u32 = 1024 * 1024; // 1 MiB; browser default is also ~1 MiB.

pub fn run() -> io::Result<()> {
    let socket_path = crate::ipc::socket_path();
    let stream = UnixStream::connect(&socket_path).map_err(|e| {
        io::Error::new(
            e.kind(),
            format!(
                "could not connect to daemon at {}: {}. Is `passwortd` running?",
                socket_path.display(),
                e
            ),
        )
    })?;

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
        let resp_len = payload.len() as u32;

        output.write_all(&resp_len.to_le_bytes())?;
        output.write_all(payload)?;
        output.flush()?;
    }
}
