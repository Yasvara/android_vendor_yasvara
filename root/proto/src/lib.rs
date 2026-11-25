// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Wire formats shared by `su` (client) and `yasvara_rootd` (daemon)
//!
//! Everything here is pure data handling (no I/O, no `unsafe`) so it is unit-tested on the
//! host and fuzzable. All integers are little-endian.
//!
//! Conversation on the daemon socket (`SOCKET_PATH` for adb shell; `PROJECTED_SOCKET_PATH` for
//! enrolled apps):
//!
//! ```text
//!   client → daemon   Request            (48-byte header + blobs, fds in SCM_RIGHTS)
//!   daemon → client   Verdict            (16 bytes; sent before anything is read)
//!   daemon → client   Ack                (16 bytes, pty master in SCM_RIGHTS if any)
//!   daemon → client   Exit               (16 bytes)
//! ```
//!
//! The client queues its request without waiting for the verdict. The daemon still decides
//! before reading a byte: an unenrolled caller's request is dropped unread, and the client reads
//! the queued verdict before the ECONNRESET that the daemon's close() leaves behind. A request
//! carries no mount namespace unless a verdict with `VF_WANTS_MNTNS` sent the client back to
//! ask again with one.

#![forbid(unsafe_code)]

pub mod bootguard;
pub mod grants;
pub mod module_config;
pub mod modules;
pub mod mounts;
pub mod sepolicy_parse;
pub mod zip;

/// Where the daemon listens. Apps cannot search `/data/misc` (SELinux), so only `shell` and
/// system_server reach it here; an enrolled app is given a bind of the same socket instead.
pub const SOCKET_PATH: &str = "/data/misc/yasvara_root/run/ctl.sock";
/// The same socket as seen from inside an enrolled app's mount namespace. Zygote binds the whole
/// `run` directory at `/system/xbin/.s` (not the socket file): the daemon creates a new socket
/// inode every time it starts, and a bound file would go stale in apps that are already running.
pub const PROJECTED_SOCKET_PATH: &str = "/system/xbin/.s/ctl.sock";
pub const MAGIC: u32 = 0x5553_4159; // "YASU"
pub const VERSION: u16 = 1;

/// Verdict `b` bit: the grant confines the caller to its own mount namespace, so the request
/// must carry a descriptor of it. Without the bit the client sends none: on Android an app
/// domain may not open `/proc/self/ns/mnt` at all (SELinux denies `read` on nsfs).
pub const VF_WANTS_MNTNS: u32 = 1 << 31;
/// Reported by `su -v` / `su -V`.
pub const VERSION_NAME: &str = "1.0";
pub const VERSION_CODE: u32 = 1;

/// Hard cap on a whole request (header + blobs).
pub const MAX_REQUEST: usize = 256 * 1024;
pub const MAX_ENV: usize = 64 * 1024;
pub const MAX_ARGS: usize = 128 * 1024;
pub const REQUEST_HEADER_LEN: usize = 48;
pub const FRAME_LEN: usize = 16;

pub const TIER_DEFAULT: u8 = 0;
pub const TIER_SHELL: u8 = 1;
pub const TIER_ROOT: u8 = 2;

pub const UID_ROOT: u32 = 0;
pub const UID_SHELL: u32 = 2000;

// Request flags.
pub const RF_INTERACTIVE: u16 = 1 << 0;
pub const RF_LOGIN: u16 = 1 << 1;
pub const RF_PRESERVE_ENV: u16 = 1 << 2;
pub const RF_MOUNT_MASTER: u16 = 1 << 3;
pub const RF_HAS_CMD: u16 = 1 << 4;
pub const RF_HAS_SHELL: u16 = 1 << 5;
pub const RF_HAS_USER: u16 = 1 << 6;
pub const RF_HAS_STDIO_FDS: u16 = 1 << 7;
pub const RF_HAS_MNTNS_FD: u16 = 1 << 8;
const RF_KNOWN: u16 = (1 << 9) - 1;

// Frame kinds.
pub const KIND_VERDICT: u8 = 1;
pub const KIND_ACK: u8 = 2;
pub const KIND_EXIT: u8 = 3;

pub const STATUS_OK: u8 = 0;
pub const STATUS_DENIED: u8 = 1;

/// Why a request was refused (Verdict.reason) or failed (Ack.reason).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Reason {
    None = 0,
    NotEnrolled = 1,
    Frozen = 2,
    Expired = 3,
    Locked = 4,
    Busy = 5,
    Disabled = 6,
    Internal = 7,
    BadRequest = 8,
    Tier = 9,
    Spawn = 10,
}

impl Reason {
    pub fn from_u8(v: u8) -> Reason {
        match v {
            0 => Reason::None,
            1 => Reason::NotEnrolled,
            2 => Reason::Frozen,
            3 => Reason::Expired,
            4 => Reason::Locked,
            5 => Reason::Busy,
            6 => Reason::Disabled,
            8 => Reason::BadRequest,
            9 => Reason::Tier,
            10 => Reason::Spawn,
            _ => Reason::Internal,
        }
    }

    /// The line `su` prints. Kept short; the hint tells the owner where to fix it.
    pub fn message(self) -> &'static str {
        match self {
            Reason::None => "ok",
            Reason::NotEnrolled => "permission denied: this app is not enrolled (open Akar in Laras)",
            Reason::Frozen => "permission denied: root is frozen",
            Reason::Expired => "permission denied: the grant has expired",
            Reason::Locked => "permission denied: unlock the device first",
            Reason::Busy => "too many requests, try again",
            Reason::Disabled => "root is off (enable it in Akar)",
            Reason::Internal => "internal error",
            Reason::BadRequest => "bad request",
            Reason::Tier => "permission denied: the grant does not allow this tier or namespace",
            Reason::Spawn => "could not start the shell",
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Reason::None => "ok",
            Reason::NotEnrolled => "not_enrolled",
            Reason::Frozen => "frozen",
            Reason::Expired => "expired",
            Reason::Locked => "locked",
            Reason::Busy => "busy",
            Reason::Disabled => "disabled",
            Reason::Internal => "internal",
            Reason::BadRequest => "bad_request",
            Reason::Tier => "tier",
            Reason::Spawn => "spawn",
        }
    }
}

/// The 16-byte frame the daemon sends: Verdict, Ack and Exit share one layout.
///
/// ```text
///  0  u32 magic   4  u8 kind   5  u8 status   6  u8 reason   7  u8 aux
///  8  u32 a      12  u32 b
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub kind: u8,
    pub status: u8,
    pub reason: u8,
    pub aux: u8,
    pub a: u32,
    pub b: u32,
}

impl Frame {
    /// Verdict: `aux` is the highest tier the grant allows, `a` the protocol version,
    /// `b` the grant flags.
    pub fn verdict(proceed: bool, reason: Reason, max_tier: u8, flags: u32) -> Frame {
        Frame {
            kind: KIND_VERDICT,
            status: if proceed { STATUS_OK } else { STATUS_DENIED },
            reason: reason as u8,
            aux: max_tier,
            a: VERSION as u32,
            b: flags,
        }
    }

    /// Ack: `aux` bit 0 says a pty master travels with this frame, `a` is the child pid.
    pub fn ack(ok: bool, reason: Reason, pid: u32, has_pty: bool) -> Frame {
        Frame {
            kind: KIND_ACK,
            status: if ok { STATUS_OK } else { STATUS_DENIED },
            reason: reason as u8,
            aux: has_pty as u8,
            a: pid,
            b: 0,
        }
    }

    /// Exit: `a` is the exit code (128 + signal when killed), `aux` is 1 if signalled.
    pub fn exit(code: i32, signalled: bool) -> Frame {
        Frame { kind: KIND_EXIT, status: STATUS_OK, reason: 0, aux: signalled as u8, a: code as u32, b: 0 }
    }

    pub fn encode(&self) -> [u8; FRAME_LEN] {
        let mut o = [0u8; FRAME_LEN];
        o[0..4].copy_from_slice(&MAGIC.to_le_bytes());
        o[4] = self.kind;
        o[5] = self.status;
        o[6] = self.reason;
        o[7] = self.aux;
        o[8..12].copy_from_slice(&self.a.to_le_bytes());
        o[12..16].copy_from_slice(&self.b.to_le_bytes());
        o
    }

    pub fn decode(buf: &[u8]) -> Option<Frame> {
        if buf.len() < FRAME_LEN || u32::from_le_bytes(buf[0..4].try_into().ok()?) != MAGIC {
            return None;
        }
        Some(Frame {
            kind: buf[4],
            status: buf[5],
            reason: buf[6],
            aux: buf[7],
            a: u32::from_le_bytes(buf[8..12].try_into().ok()?),
            b: u32::from_le_bytes(buf[12..16].try_into().ok()?),
        })
    }

    pub fn is_ok(&self) -> bool {
        self.status == STATUS_OK
    }
}

/// A parsed request. Strings are raw bytes: a path or command need not be UTF-8.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Request {
    pub flags: u16,
    pub target_uid: u32,
    pub tier: u8,
    pub rows: u16,
    pub cols: u16,
    pub umask: u32,
    pub shell: Vec<u8>,
    pub cmd: Vec<u8>,
    pub cwd: Vec<u8>,
    /// The caller's own `/proc/self/cgroup`, as text.
    pub cgroup: Vec<u8>,
    /// `KEY=VALUE` entries.
    pub env: Vec<Vec<u8>>,
    /// Arguments after the command (`$0 $1 …` of `sh -c cmd a b`).
    pub args: Vec<Vec<u8>>,
}

impl Request {
    pub fn has(&self, flag: u16) -> bool {
        self.flags & flag != 0
    }

    /// Serialises to header + blobs (the caller sends fds separately).
    pub fn encode(&self) -> Vec<u8> {
        fn join(v: &[Vec<u8>]) -> Vec<u8> {
            let mut o = Vec::new();
            for e in v {
                o.extend_from_slice(e);
                o.push(0);
            }
            o
        }
        let env = join(&self.env);
        let args = join(&self.args);
        let mut o = Vec::with_capacity(
            REQUEST_HEADER_LEN + self.shell.len() + self.cmd.len() + self.cwd.len()
                + self.cgroup.len() + env.len() + args.len(),
        );
        o.extend_from_slice(&MAGIC.to_le_bytes());
        o.extend_from_slice(&VERSION.to_le_bytes());
        o.extend_from_slice(&self.flags.to_le_bytes());
        o.extend_from_slice(&self.target_uid.to_le_bytes());
        o.push(self.tier);
        o.push(0);
        o.extend_from_slice(&self.rows.to_le_bytes());
        o.extend_from_slice(&self.cols.to_le_bytes());
        o.extend_from_slice(&0u16.to_le_bytes());
        o.extend_from_slice(&self.umask.to_le_bytes());
        for len in [self.shell.len(), self.cmd.len(), self.cwd.len(), self.cgroup.len(), env.len(), args.len()] {
            o.extend_from_slice(&(len as u32).to_le_bytes());
        }
        debug_assert_eq!(o.len(), REQUEST_HEADER_LEN);
        o.extend_from_slice(&self.shell);
        o.extend_from_slice(&self.cmd);
        o.extend_from_slice(&self.cwd);
        o.extend_from_slice(&self.cgroup);
        o.extend_from_slice(&env);
        o.extend_from_slice(&args);
        o
    }
}

/// Lengths announced by a request header; read exactly [`BlobLens::total`] more bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlobLens {
    pub shell: usize,
    pub cmd: usize,
    pub cwd: usize,
    pub cgroup: usize,
    pub env: usize,
    pub args: usize,
}

impl BlobLens {
    pub fn total(&self) -> usize {
        self.shell + self.cmd + self.cwd + self.cgroup + self.env + self.args
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseError {
    Short,
    Magic,
    Version,
    Flags,
    Tier,
    TooBig,
    Layout,
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

/// Validates the fixed header and returns what follows it. Nothing is allocated from sizes
/// before they are bounded here.
pub fn parse_header(h: &[u8]) -> Result<(Request, BlobLens), ParseError> {
    if h.len() < REQUEST_HEADER_LEN {
        return Err(ParseError::Short);
    }
    if u32_at(h, 0) != MAGIC {
        return Err(ParseError::Magic);
    }
    if u16_at(h, 4) != VERSION {
        return Err(ParseError::Version);
    }
    let flags = u16_at(h, 6);
    if flags & !RF_KNOWN != 0 {
        return Err(ParseError::Flags);
    }
    let tier = h[12];
    if tier > TIER_ROOT {
        return Err(ParseError::Tier);
    }
    let lens = BlobLens {
        shell: u32_at(h, 24) as usize,
        cmd: u32_at(h, 28) as usize,
        cwd: u32_at(h, 32) as usize,
        cgroup: u32_at(h, 36) as usize,
        env: u32_at(h, 40) as usize,
        args: u32_at(h, 44) as usize,
    };
    // Each field is below 4 GiB, so the sum of six fits in usize on 64-bit; still checked.
    let total = [lens.shell, lens.cmd, lens.cwd, lens.cgroup, lens.env, lens.args]
        .iter()
        .try_fold(0usize, |acc, &n| acc.checked_add(n))
        .ok_or(ParseError::TooBig)?;
    if total > MAX_REQUEST - REQUEST_HEADER_LEN
        || lens.env > MAX_ENV
        || lens.args > MAX_ARGS
        || lens.shell > 4096
        || lens.cwd > 4096
        || lens.cgroup > 8192
        || lens.cmd > MAX_ARGS
    {
        return Err(ParseError::TooBig);
    }
    let req = Request {
        flags,
        target_uid: u32_at(h, 8),
        tier,
        rows: u16_at(h, 14),
        cols: u16_at(h, 16),
        umask: u32_at(h, 20),
        ..Request::default()
    };
    Ok((req, lens))
}

fn split_nul(blob: &[u8]) -> Result<Vec<Vec<u8>>, ParseError> {
    if blob.is_empty() {
        return Ok(Vec::new());
    }
    if *blob.last().unwrap() != 0 {
        return Err(ParseError::Layout);
    }
    Ok(blob[..blob.len() - 1].split(|&c| c == 0).map(|s| s.to_vec()).collect())
}

/// Fills the blobs of `req` from `body`, which must be exactly `lens.total()` bytes.
pub fn parse_body(req: &mut Request, lens: &BlobLens, body: &[u8]) -> Result<(), ParseError> {
    if body.len() != lens.total() {
        return Err(ParseError::Short);
    }
    let mut at = 0usize;
    let mut take = |n: usize| {
        let s = &body[at..at + n];
        at += n;
        s
    };
    req.shell = take(lens.shell).to_vec();
    req.cmd = take(lens.cmd).to_vec();
    req.cwd = take(lens.cwd).to_vec();
    req.cgroup = take(lens.cgroup).to_vec();
    let env = take(lens.env);
    let args = take(lens.args);
    for s in [&req.shell, &req.cmd, &req.cwd] {
        if s.contains(&0) {
            return Err(ParseError::Layout);
        }
    }
    req.env = split_nul(env)?.into_iter().filter(|e| e.contains(&b'=')).collect();
    req.args = split_nul(args)?;
    if req.has(RF_HAS_CMD) && req.cmd.is_empty() {
        // A command was announced but is empty.
        return Err(ParseError::Layout);
    }
    Ok(())
}

/// Convenience for tests and fuzzing: header + body in one buffer.
pub fn parse_request(buf: &[u8]) -> Result<Request, ParseError> {
    let (mut req, lens) = parse_header(buf)?;
    let body = buf.get(REQUEST_HEADER_LEN..).ok_or(ParseError::Short)?;
    parse_body(&mut req, &lens, body)?;
    Ok(req)
}

/// Resolves what `su <user>` may name without a passwd database.
pub fn parse_user(s: &str) -> Option<u32> {
    if let Ok(n) = s.parse::<u32>() {
        return Some(n);
    }
    Some(match s {
        "root" => 0,
        "system" => 1000,
        "radio" => 1001,
        "bluetooth" => 1002,
        "graphics" => 1003,
        "input" => 1004,
        "audio" => 1005,
        "camera" => 1006,
        "log" => 1007,
        "shell" => 2000,
        _ => return None,
    })
}

/// Cgroups the child may adopt from the caller's `/proc/self/cgroup` (scheduling class only,
/// never the per-process lifecycle group). Returns `(controller dir, group path)` pairs.
pub fn scheduling_cgroups(text: &[u8]) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    let Ok(text) = std::str::from_utf8(text) else { return out };
    for line in text.lines() {
        let mut it = line.splitn(3, ':');
        let (Some(_), Some(ctl), Some(path)) = (it.next(), it.next(), it.next()) else { continue };
        let dir = match ctl {
            "cpu" => "/dev/cpuctl",
            "cpuset" => "/dev/cpuset",
            "blkio" => "/dev/blkio",
            _ => continue,
        };
        if path_is_safe(path) {
            out.push((dir, path.to_string()));
        }
    }
    out
}

/// `/` or `/a/b-c_d`: absolute, no `..`, no empty or odd components.
fn path_is_safe(p: &str) -> bool {
    if p == "/" {
        return true;
    }
    p.starts_with('/')
        && p.len() < 256
        && p[1..].split('/').all(|c| {
            !c.is_empty()
                && c != "."
                && c != ".."
                && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-' || b == b'.')
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Request {
        Request {
            flags: RF_HAS_CMD | RF_PRESERVE_ENV | RF_HAS_STDIO_FDS,
            target_uid: 0,
            tier: TIER_ROOT,
            rows: 24,
            cols: 80,
            umask: 0o22,
            shell: b"/system/bin/sh".to_vec(),
            cmd: b"id; echo $0".to_vec(),
            cwd: b"/data/local/tmp".to_vec(),
            cgroup: b"3:cpuset:/top-app\n2:cpu:/top-app\n0::/apps/uid_1/pid_2\n".to_vec(),
            env: vec![b"A=1".to_vec(), b"PATH=/a:/b".to_vec()],
            args: vec![b"x".to_vec(), b"y z".to_vec()],
        }
    }

    #[test]
    fn frame_roundtrip() {
        for f in [
            Frame::verdict(true, Reason::None, TIER_ROOT, 5),
            Frame::verdict(false, Reason::NotEnrolled, 0, 0),
            Frame::ack(true, Reason::None, 4242, true),
            Frame::exit(-1, true),
        ] {
            assert_eq!(Frame::decode(&f.encode()), Some(f));
        }
        assert_eq!(Frame::decode(&[0u8; 16]), None);
        assert_eq!(Frame::decode(&[1u8; 3]), None);
    }

    #[test]
    fn request_roundtrip() {
        let mut want = sample();
        let got = parse_request(&want.encode()).unwrap();
        assert_eq!(got, want);
        want.args.clear();
        want.env.clear();
        assert_eq!(parse_request(&want.encode()).unwrap(), want);
    }

    #[test]
    fn rejects_bad_headers() {
        let good = sample().encode();
        assert_eq!(parse_request(&good[..10]), Err(ParseError::Short));
        let mut b = good.clone();
        b[0] ^= 1;
        assert_eq!(parse_request(&b), Err(ParseError::Magic));
        let mut b = good.clone();
        b[4] = 9;
        assert_eq!(parse_request(&b), Err(ParseError::Version));
        let mut b = good.clone();
        b[7] = 0x80; // unknown flag bits
        assert_eq!(parse_request(&b), Err(ParseError::Flags));
        let mut b = good.clone();
        b[12] = 3;
        assert_eq!(parse_request(&b), Err(ParseError::Tier));
        // A length that overflows the cap is refused before any allocation.
        let mut b = good.clone();
        b[40..44].copy_from_slice(&u32::MAX.to_le_bytes());
        assert_eq!(parse_request(&b), Err(ParseError::TooBig));
        // Truncated body.
        assert_eq!(parse_request(&good[..good.len() - 1]), Err(ParseError::Short));
    }

    #[test]
    fn blob_layout_checks() {
        let mut r = sample();
        r.cmd = b"a\0b".to_vec();
        assert_eq!(parse_request(&r.encode()), Err(ParseError::Layout));
        // Env entry without '=' is dropped, not fatal.
        let mut r = sample();
        r.env = vec![b"NOEQUALS".to_vec(), b"K=V".to_vec()];
        assert_eq!(parse_request(&r.encode()).unwrap().env, vec![b"K=V".to_vec()]);
    }

    /// A cheap, deterministic fuzz: random and mutated buffers must never panic, and anything
    /// accepted must re-encode to something that parses to the same request.
    #[test]
    fn parser_survives_garbage() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut next = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        let good = sample().encode();
        for round in 0..20_000 {
            let mut buf = if round % 3 == 0 {
                (0..(next() % 400) as usize).map(|_| next() as u8).collect::<Vec<u8>>()
            } else {
                good.clone()
            };
            if round % 3 != 0 {
                for _ in 0..(1 + next() % 6) {
                    let at = (next() as usize) % buf.len();
                    buf[at] = next() as u8;
                }
                if next() % 4 == 0 {
                    let cut = (next() as usize) % buf.len();
                    buf.truncate(cut);
                }
            }
            if let Ok(req) = parse_request(&buf) {
                assert_eq!(parse_request(&req.encode()), Ok(req));
            }
            let _ = Frame::decode(&buf);
            let _ = scheduling_cgroups(&buf);
        }
    }

    #[test]
    fn users() {
        assert_eq!(parse_user("0"), Some(0));
        assert_eq!(parse_user("shell"), Some(2000));
        assert_eq!(parse_user("10195"), Some(10195));
        assert_eq!(parse_user("nobody-here"), None);
    }

    #[test]
    fn cgroup_adoption_is_scheduling_only_and_path_safe() {
        let text = b"3:cpuset:/top-app\n2:cpu:/top-app\n1:blkio:/foreground\n0::/apps/uid_1/pid_2\n\
                     4:cpu:/../../etc\n5:cpu:/a//b\n6:memory:/x\n";
        let got = scheduling_cgroups(text);
        assert_eq!(
            got,
            vec![
                ("/dev/cpuset", "/top-app".to_string()),
                ("/dev/cpuctl", "/top-app".to_string()),
                ("/dev/blkio", "/foreground".to_string()),
            ]
        );
        assert_eq!(scheduling_cgroups(b"2:cpu:/\n"), vec![("/dev/cpuctl", "/".to_string())]);
        assert!(scheduling_cgroups(&[0xff, 0xfe]).is_empty());
    }
}
