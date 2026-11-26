// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Automation & Remote Control Unix Socket IPC (`/tmp/pulih.sock`) for `Pulih` Recovery.
//!
//! Enables standard Android automation commands directly inside Recovery for
//! AI agents, CI scripts, and remote debugging:
//! - `screencap -p <path.png>` / `pulih screencap <path.png>`
//! - `input tap <x> <y>`
//! - `input swipe <x1> <y1> <x2> <y2>`
//! - `input keyevent <BACK|POWER|VOLUME_UP|VOLUME_DOWN|SCREENSHOT>`
//! - `pulih ui-dump` (returns live JSON of screen state + every clickable rect!)

use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::time::Duration;

pub const CONTROL_SOCK_PATH: &str = "/tmp/pulih.sock";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IpcRequest {
    Screencap(String),
    Tap(i32, i32),
    Swipe(i32, i32, i32, i32),
    Key(String),
    DumpUi,
}

impl IpcRequest {
    pub fn parse_line(line: &str) -> Result<Self, String> {
        let parts: Vec<&str> = line.trim().split_whitespace().collect();
        if parts.is_empty() {
            return Err("empty IPC command".into());
        }
        match parts[0].to_ascii_uppercase().as_str() {
            "SCREENCAP" => {
                let path = parts.get(1).copied().unwrap_or("/tmp/pulih-screen.png");
                Ok(Self::Screencap(path.to_string()))
            }
            "TAP" => {
                let x: i32 = parts.get(1).ok_or("missing x")?.parse().map_err(|_| "bad x")?;
                let y: i32 = parts.get(2).ok_or("missing y")?.parse().map_err(|_| "bad y")?;
                Ok(Self::Tap(x, y))
            }
            "SWIPE" => {
                let x1: i32 = parts.get(1).ok_or("missing x1")?.parse().map_err(|_| "bad x1")?;
                let y1: i32 = parts.get(2).ok_or("missing y1")?.parse().map_err(|_| "bad y1")?;
                let x2: i32 = parts.get(3).ok_or("missing x2")?.parse().map_err(|_| "bad x2")?;
                let y2: i32 = parts.get(4).ok_or("missing y2")?.parse().map_err(|_| "bad y2")?;
                Ok(Self::Swipe(x1, y1, x2, y2))
            }
            "KEY" => {
                let k = parts.get(1).ok_or("missing key")?.to_string();
                Ok(Self::Key(k))
            }
            "DUMP" => Ok(Self::DumpUi),
            other => Err(format!("unknown IPC verb '{other}'")),
        }
    }
}

/// Non-blocking Unix socket server owned by the live `Pulih` UI process.
pub struct IpcServer {
    listener: UnixListener,
    path: String,
}

impl IpcServer {
    pub fn bind(path: &str) -> std::io::Result<Self> {
        let _ = fs::remove_file(path);
        let listener = UnixListener::bind(path)?;
        listener.set_nonblocking(true)?;
        Ok(Self {
            listener,
            path: path.to_string(),
        })
    }

    /// Poll for one pending IPC client without blocking the 120 Hz UI loop.
    pub fn try_accept(&self) -> Option<(IpcRequest, UnixStream)> {
        match self.listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nonblocking(false);
                let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                let _ = stream.set_write_timeout(Some(Duration::from_millis(2000)));
                let mut reader = BufReader::new(&stream);
                let mut line = String::new();
                if reader.read_line(&mut line).is_ok() {
                    if let Ok(req) = IpcRequest::parse_line(&line) {
                        return Some((req, stream));
                    }
                }
                None
            }
            Err(_) => None,
        }
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// Client helper used by `screencap`, `input`, and `pulih ui-dump` CLI invocations.
pub fn send_ipc_command(sock_path: &Path, line: &str) -> Result<String, String> {
    let mut stream = UnixStream::connect(sock_path)
        .map_err(|e| format!("cannot connect to live Pulih UI ({}): {e}", sock_path.display()))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
    writeln!(stream, "{line}").map_err(|e| format!("ipc write failed: {e}"))?;
    let mut resp = String::new();
    let mut reader = BufReader::new(stream);
    let _ = std::io::Read::read_to_string(&mut reader, &mut resp);
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipc_server_and_client_roundtrip_tap_swipe_dump_screencap() {
        let sock = format!("/tmp/pulih_ipc_test_{}.sock", std::process::id());
        let srv = IpcServer::bind(&sock).unwrap();

        let sock_c = sock.clone();
        let client = std::thread::spawn(move || {
            send_ipc_command(Path::new(&sock_c), "TAP 640 2650").unwrap()
        });

        // Wait briefly for client connection
        let mut handled = false;
        for _ in 0..50 {
            if let Some((req, mut stream)) = srv.try_accept() {
                assert_eq!(req, IpcRequest::Tap(640, 2650));
                writeln!(stream, "OK").unwrap();
                handled = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        assert!(handled);
        assert_eq!(client.join().unwrap().trim(), "OK");

        assert_eq!(
            IpcRequest::parse_line("SWIPE 100 2000 1100 2000").unwrap(),
            IpcRequest::Swipe(100, 2000, 1100, 2000)
        );
        assert_eq!(
            IpcRequest::parse_line("SCREENCAP /tmp/a.png").unwrap(),
            IpcRequest::Screencap("/tmp/a.png".into())
        );
        assert_eq!(IpcRequest::parse_line("DUMP").unwrap(), IpcRequest::DumpUi);
    }
}
