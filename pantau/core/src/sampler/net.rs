// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-alloc unified network sampler:
//! 1. Single `pread("/proc/net/dev")` separating **Wi-Fi** (`wlan*`), **Mobile Data** (`rmnet*`,
//!    `ccmni*`, `wwan*`, `pdp*`), **Ethernet**, and **VPN** (`tun*`/`wg*`, flagged without
//!    double-counting throughput).
//! 2. Passive kernel `TCP_INFO` RTT / jitter / retransmit reader via `AF_NETLINK`
//!    `NETLINK_SOCK_DIAG` (`SOCK_DIAG_BY_FAMILY`) — zero ICMP `ping` subprocesses, zero wakeups,
//!    preferring `focused_uid` established non-loopback sockets.
//! 3. Pushes every sample into `SnapshotCopy::hist` (`net_wifi_rx_kbps`, `net_cell_rx_kbps`,
//!    `net_tx_kbps`, `net_rtt_ms`) for the unified 1-graph HUD & Pentas UI.

use core::ffi::c_int;
use core::mem::size_of;
use core::ptr;

use crate::abi::{SnapshotCopy, LINK_CELL, LINK_ETH, LINK_VPN, LINK_WIFI};
use crate::sys::{close_fd, open_ro_cstr, pread_zero, RawFd};

const AF_INET: u8 = 2;
const AF_INET6: u8 = 10;
const AF_NETLINK: c_int = 16;
const SOCK_DGRAM: c_int = 2;
const SOCK_NONBLOCK: c_int = 0o4000;
const SOCK_CLOEXEC: c_int = 0o2000000;
const NETLINK_SOCK_DIAG: c_int = 4;

const IPPROTO_TCP: u8 = 6;
const TCP_ESTABLISHED_MASK: u32 = 1 << 1;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_DUMP: u16 = 0x0300;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const INET_DIAG_INFO: u16 = 2;
const INET_DIAG_EXT_INFO: u8 = 1 << (INET_DIAG_INFO - 1);

// Linux UAPI `struct tcp_info` byte offsets (verified against bionic/libc/kernel/uapi/linux/tcp.h).
const TCPI_OFF_LAST_RECV: usize = 52;
const TCPI_OFF_RTT: usize = 68;
const TCPI_OFF_RTTVAR: usize = 72;
const TCPI_OFF_TOTAL_RETRANS: usize = 100;
const TCPI_MIN_LEN: usize = 104;

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct NlMsgHdr {
    nlmsg_len: u32,
    nlmsg_type: u16,
    nlmsg_flags: u16,
    nlmsg_seq: u32,
    nlmsg_pid: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct InetDiagSockId {
    sport: u16,
    dport: u16,
    src: [u32; 4],
    dst: [u32; 4],
    if_idx: u32,
    cookie: [u32; 2],
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct InetDiagReqV2 {
    sdiag_family: u8,
    sdiag_protocol: u8,
    idiag_ext: u8,
    pad: u8,
    idiag_states: u32,
    id: InetDiagSockId,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct InetDiagMsg {
    idiag_family: u8,
    idiag_state: u8,
    idiag_timer: u8,
    idiag_retrans: u8,
    id: InetDiagSockId,
    idiag_expires: u32,
    idiag_rqueue: u32,
    idiag_wqueue: u32,
    idiag_uid: u32,
    idiag_inode: u32,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct NlDiagRequest {
    hdr: NlMsgHdr,
    req: InetDiagReqV2,
}

#[repr(C)]
#[derive(Copy, Clone, Default)]
struct NlAttr {
    nla_len: u16,
    nla_type: u16,
}

const _: () = assert!(size_of::<NlMsgHdr>() == 16);
const _: () = assert!(size_of::<InetDiagReqV2>() == 56);
const _: () = assert!(size_of::<InetDiagMsg>() == 72);
const _: () = assert!(size_of::<NlDiagRequest>() == 72);

extern "C" {
    fn socket(domain: c_int, ty: c_int, protocol: c_int) -> c_int;
    fn send(fd: c_int, buf: *const core::ffi::c_void, len: usize, flags: c_int) -> isize;
    fn recv(fd: c_int, buf: *mut core::ffi::c_void, len: usize, flags: c_int) -> isize;
}

/// Parsed byte totals from `/proc/net/dev` split by transport class.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct NetDevRaw {
    pub wifi_rx: u64,
    pub wifi_tx: u64,
    pub cell_rx: u64,
    pub cell_tx: u64,
    pub eth_rx: u64,
    pub eth_tx: u64,
    pub vpn_active: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum IfaceKind {
    Wifi,
    Cell,
    Eth,
    Vpn,
    Ignore,
}

fn classify_iface(name: &[u8]) -> IfaceKind {
    if name == b"lo"
        || name.starts_with(b"dummy")
        || name.starts_with(b"ip_vti")
        || name.starts_with(b"ip6_vti")
        || name.starts_with(b"sit")
        || name.starts_with(b"rmnet_ipa")
        || name.starts_with(b"p2p")
    {
        return IfaceKind::Ignore;
    }
    if name.starts_with(b"tun") || name.starts_with(b"wg") || name.starts_with(b"ppp") {
        return IfaceKind::Vpn;
    }
    if name.starts_with(b"wlan") || name.starts_with(b"swlan") || name.starts_with(b"wlp") {
        return IfaceKind::Wifi;
    }
    if name.starts_with(b"rmnet")
        || name.starts_with(b"ccmni")
        || name.starts_with(b"wwan")
        || name.starts_with(b"pdp")
        || name.starts_with(b"seth_lte")
        || name.starts_with(b"ril")
    {
        return IfaceKind::Cell;
    }
    if name.starts_with(b"eth")
        || name.starts_with(b"usb")
        || name.starts_with(b"rndis")
        || name.starts_with(b"enp")
        || name.starts_with(b"eno")
    {
        return IfaceKind::Eth;
    }
    IfaceKind::Ignore
}

/// Zero-alloc single-pass parser for `/proc/net/dev`.
pub fn parse_proc_net_dev(buf: &[u8]) -> NetDevRaw {
    let mut out = NetDevRaw::default();
    let mut line_no = 0usize;
    for line in buf.split(|&b| b == b'\n') {
        line_no += 1;
        if line_no <= 2 || line.is_empty() {
            continue;
        }
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let mut name = &line[..colon];
        while let Some(&b) = name.first() {
            if b == b' ' || b == b'\t' {
                name = &name[1..];
            } else {
                break;
            }
        }
        let kind = classify_iface(name);
        if kind == IfaceKind::Ignore {
            continue;
        }
        // Columns after ':':
        //   0:rx_bytes 1:rx_pkts 2:rx_errs 3:rx_drop 4..7:... 8:tx_bytes
        let rest = &line[colon + 1..];
        let mut rx_bytes = 0u64;
        let mut tx_bytes = 0u64;
        let mut col = 0usize;
        let mut i = 0usize;
        while i < rest.len() && col <= 8 {
            while i < rest.len() && (rest[i] == b' ' || rest[i] == b'\t') {
                i += 1;
            }
            if i >= rest.len() {
                break;
            }
            let mut val = 0u64;
            let start = i;
            while i < rest.len() && rest[i].is_ascii_digit() {
                val = val.saturating_mul(10).saturating_add((rest[i] - b'0') as u64);
                i += 1;
            }
            if i > start {
                if col == 0 {
                    rx_bytes = val;
                } else if col == 8 {
                    tx_bytes = val;
                }
                col += 1;
            } else {
                // Skip non-digit token cleanly.
                while i < rest.len() && rest[i] != b' ' && rest[i] != b'\t' {
                    i += 1;
                }
            }
        }
        match kind {
            IfaceKind::Wifi => {
                out.wifi_rx = out.wifi_rx.saturating_add(rx_bytes);
                out.wifi_tx = out.wifi_tx.saturating_add(tx_bytes);
            }
            IfaceKind::Cell => {
                out.cell_rx = out.cell_rx.saturating_add(rx_bytes);
                out.cell_tx = out.cell_tx.saturating_add(tx_bytes);
            }
            IfaceKind::Eth => {
                out.eth_rx = out.eth_rx.saturating_add(rx_bytes);
                out.eth_tx = out.eth_tx.saturating_add(tx_bytes);
            }
            IfaceKind::Vpn => {
                if rx_bytes > 0 || tx_bytes > 0 {
                    out.vpn_active = true;
                }
            }
            IfaceKind::Ignore => {}
        }
    }
    out
}

pub struct NetSampler {
    fd_net_dev: RawFd,
    fd_sock_diag: RawFd,
    primed: bool,
    prev: NetDevRaw,
    prev_ns: u64,
    wifi_sess_bytes: u64,
    cell_sess_bytes: u64,
    prev_retrans: u64,
    retrans_primed: bool,
    diag_seq: u32,
}

impl Default for NetSampler {
    fn default() -> Self {
        Self::new()
    }
}

impl NetSampler {
    pub fn new() -> Self {
        let fd_net_dev = open_ro_cstr(b"/proc/net/dev\0");
        // SAFETY: standard non-blocking netlink socket creation; graceful -1 fallback if denied.
        let fd_sock_diag = unsafe {
            socket(AF_NETLINK, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, NETLINK_SOCK_DIAG)
        };
        let mut s = Self {
            fd_net_dev,
            fd_sock_diag,
            primed: false,
            prev: NetDevRaw::default(),
            prev_ns: 0,
            wifi_sess_bytes: 0,
            cell_sess_bytes: 0,
            prev_retrans: 0,
            retrans_primed: false,
            diag_seq: 1,
        };
        let mut buf = [0u8; 4096];
        if let Some(raw) = pread_zero(s.fd_net_dev, &mut buf) {
            s.prev = parse_proc_net_dev(raw);
            s.primed = true;
        }
        s
    }

    pub fn reset_session(&mut self) {
        self.wifi_sess_bytes = 0;
        self.cell_sess_bytes = 0;
    }

    /// Samples unified Wi-Fi + Mobile Data throughput + passive kernel TCP RTT (0 heap allocs!).
    pub fn sample(
        &mut self,
        tick: u32,
        focused_uid: u32,
        now_ns: u64,
        io_buf: &mut [u8],
        snap: &mut SnapshotCopy,
    ) {
        let Some(raw) = pread_zero(self.fd_net_dev, io_buf) else {
            return;
        };
        let cur = parse_proc_net_dev(raw);
        let dt_ms = if self.prev_ns > 0 {
            now_ns.saturating_sub(self.prev_ns) / 1_000_000
        } else {
            1000
        }
        .max(1);

        if self.primed && self.prev_ns > 0 {
            let dw_rx = cur.wifi_rx.saturating_sub(self.prev.wifi_rx);
            let dw_tx = cur.wifi_tx.saturating_sub(self.prev.wifi_tx);
            let dc_rx = cur.cell_rx.saturating_sub(self.prev.cell_rx);
            let dc_tx = cur.cell_tx.saturating_sub(self.prev.cell_tx);
            let de_rx = cur.eth_rx.saturating_sub(self.prev.eth_rx);
            let de_tx = cur.eth_tx.saturating_sub(self.prev.eth_tx);

            self.wifi_sess_bytes = self.wifi_sess_bytes.saturating_add(dw_rx + dw_tx);
            self.cell_sess_bytes = self.cell_sess_bytes.saturating_add(dc_rx + dc_tx);

            let rate = |bytes: u64| -> u32 {
                bytes.saturating_mul(1000).checked_div(dt_ms).unwrap_or(0).min(u32::MAX as u64) as u32
            };

            let w_rx = rate(dw_rx);
            let w_tx = rate(dw_tx);
            let c_rx = rate(dc_rx);
            let c_tx = rate(dc_tx);
            let e_rx = rate(de_rx);
            let e_tx = rate(de_tx);

            snap.net.wifi_rx_bps = w_rx;
            snap.net.wifi_tx_bps = w_tx;
            snap.net.cell_rx_bps = c_rx;
            snap.net.cell_tx_bps = c_tx;
            snap.net.rx_bps = w_rx.saturating_add(c_rx).saturating_add(e_rx);
            snap.net.tx_bps = w_tx.saturating_add(c_tx).saturating_add(e_tx);
            snap.net.wifi_session_kb = (self.wifi_sess_bytes / 1024).min(u32::MAX as u64) as u32;
            snap.net.cell_session_kb = (self.cell_sess_bytes / 1024).min(u32::MAX as u64) as u32;

            // Keep event-driven transport bits from PentasService, and augment with live traffic.
            let mut lmask = snap.net.link_type & !(LINK_VPN);
            if w_rx > 0 || w_tx > 0 {
                lmask |= LINK_WIFI;
            }
            if c_rx > 0 || c_tx > 0 {
                lmask |= LINK_CELL;
            }
            if e_rx > 0 || e_tx > 0 {
                lmask |= LINK_ETH;
            }
            if cur.vpn_active {
                lmask |= LINK_VPN;
            }
            snap.net.link_type = lmask;

            // Passive TCP RTT/jitter/retrans from kernel via netlink sock_diag (every tick or 0.5 Hz).
            if self.fd_sock_diag >= 0 && (tick == 0 || tick % 2 == 0) {
                self.sample_tcp_rtt(focused_uid, dt_ms, io_buf, snap);
            }

            let rtt_ms = (snap.net.tcp_rtt_us / 1000).min(u16::MAX as u32) as u16;
            snap.hist.push_net(w_rx / 1024, c_rx / 1024, snap.net.tx_bps / 1024, rtt_ms);
        } else {
            // Even on the very first prime tick, update VPN flag and probe TCP RTT immediately!
            if cur.vpn_active {
                snap.net.link_type |= LINK_VPN;
            }
            if self.fd_sock_diag >= 0 {
                self.sample_tcp_rtt(focused_uid, 1000, io_buf, snap);
            }
        }

        self.prev = cur;
        self.prev_ns = now_ns;
        self.primed = true;
    }

    fn sample_tcp_rtt(
        &mut self,
        focused_uid: u32,
        dt_ms: u64,
        io_buf: &mut [u8],
        snap: &mut SnapshotCopy,
    ) {
        let mut best_uid_rtt = u32::MAX;
        let mut best_uid_var = 0u32;
        let mut best_any_rtt = u32::MAX;
        let mut best_any_var = 0u32;
        let mut total_retrans = 0u64;

        for family in [AF_INET, AF_INET6] {
            self.diag_seq = self.diag_seq.wrapping_add(1);
            let req = NlDiagRequest {
                hdr: NlMsgHdr {
                    nlmsg_len: size_of::<NlDiagRequest>() as u32,
                    nlmsg_type: SOCK_DIAG_BY_FAMILY,
                    nlmsg_flags: NLM_F_REQUEST | NLM_F_DUMP,
                    nlmsg_seq: self.diag_seq,
                    nlmsg_pid: 0,
                },
                req: InetDiagReqV2 {
                    sdiag_family: family,
                    sdiag_protocol: IPPROTO_TCP,
                    idiag_ext: INET_DIAG_EXT_INFO,
                    pad: 0,
                    idiag_states: TCP_ESTABLISHED_MASK,
                    id: InetDiagSockId::default(),
                },
            };

            // SAFETY: valid netlink socket and stack-allocated request struct.
            let sent = unsafe {
                send(
                    self.fd_sock_diag,
                    (&req as *const NlDiagRequest) as *const core::ffi::c_void,
                    size_of::<NlDiagRequest>(),
                    0,
                )
            };
            if sent < 0 {
                continue;
            }

            // Cap iterations so a noisy device never stalls the tick loop.
            for _ in 0..8 {
                // SAFETY: `io_buf` is valid writable scratch memory.
                let n = unsafe {
                    recv(
                        self.fd_sock_diag,
                        io_buf.as_mut_ptr() as *mut core::ffi::c_void,
                        io_buf.len(),
                        0,
                    )
                };
                if n <= 0 {
                    break;
                }
                let data = &io_buf[..n as usize];
                let mut off = 0usize;
                let mut done = false;
                while off + size_of::<NlMsgHdr>() <= data.len() {
                    // SAFETY: bounds checked above.
                    let hdr = unsafe {
                        ptr::read_unaligned(data.as_ptr().add(off) as *const NlMsgHdr)
                    };
                    let msg_len = hdr.nlmsg_len as usize;
                    if msg_len < size_of::<NlMsgHdr>() || off + msg_len > data.len() {
                        done = true;
                        break;
                    }
                    if hdr.nlmsg_type == NLMSG_DONE || hdr.nlmsg_type == NLMSG_ERROR {
                        done = true;
                        break;
                    }
                    if hdr.nlmsg_type == SOCK_DIAG_BY_FAMILY
                        && msg_len >= size_of::<NlMsgHdr>() + size_of::<InetDiagMsg>()
                    {
                        let m_off = off + size_of::<NlMsgHdr>();
                        // SAFETY: bounds checked above.
                        let dmsg = unsafe {
                            ptr::read_unaligned(data.as_ptr().add(m_off) as *const InetDiagMsg)
                        };
                        if !is_loopback(dmsg.idiag_family, &dmsg.id.dst) {
                            let attrs = &data[m_off + size_of::<InetDiagMsg>()..off + msg_len];
                            if let Some((rtt, rttvar, retr, last_recv_ms)) = parse_diag_tcp_info(attrs) {
                                total_retrans = total_retrans.saturating_add(retr as u64);
                                // Prefer recently active sockets (< 60s idle) with plausible RTT.
                                if rtt > 200 && rtt < 10_000_000 && last_recv_ms < 60_000 {
                                    if focused_uid >= 10_000 && dmsg.idiag_uid == focused_uid {
                                        if rtt < best_uid_rtt {
                                            best_uid_rtt = rtt;
                                            best_uid_var = rttvar;
                                        }
                                    }
                                    if rtt < best_any_rtt {
                                        best_any_rtt = rtt;
                                        best_any_var = rttvar;
                                    }
                                }
                            }
                        }
                    }
                    off += (msg_len + 3) & !3;
                }
                if done {
                    break;
                }
            }
        }

        if best_uid_rtt < u32::MAX {
            snap.net.tcp_rtt_us = best_uid_rtt;
            snap.net.tcp_rttvar_us = best_uid_var;
        } else if best_any_rtt < u32::MAX {
            snap.net.tcp_rtt_us = best_any_rtt;
            snap.net.tcp_rttvar_us = best_any_var;
        }

        if self.retrans_primed && total_retrans >= self.prev_retrans {
            let dr = total_retrans - self.prev_retrans;
            snap.net.tcp_retrans_s =
                ((dr.saturating_mul(1000)) / dt_ms.max(1)).min(u16::MAX as u64) as u16;
        }
        self.prev_retrans = total_retrans;
        self.retrans_primed = true;
    }
}

impl Drop for NetSampler {
    fn drop(&mut self) {
        close_fd(self.fd_net_dev);
        close_fd(self.fd_sock_diag);
    }
}

fn is_loopback(family: u8, dst: &[u32; 4]) -> bool {
    if family == AF_INET {
        let b = dst[0].to_ne_bytes();
        b[0] == 127 || dst[0] == 0
    } else if family == AF_INET6 {
        // ::1 in network byte order
        dst[0] == 0 && dst[1] == 0 && dst[2] == 0 && u32::from_be(dst[3]) <= 1
    } else {
        true
    }
}

fn read_u32_ne(b: &[u8], off: usize) -> u32 {
    u32::from_ne_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn parse_diag_tcp_info(attrs: &[u8]) -> Option<(u32, u32, u32, u32)> {
    let mut off = 0usize;
    while off + size_of::<NlAttr>() <= attrs.len() {
        // SAFETY: bounds verified.
        let a = unsafe { ptr::read_unaligned(attrs.as_ptr().add(off) as *const NlAttr) };
        let alen = a.nla_len as usize;
        if alen < size_of::<NlAttr>() || off + alen > attrs.len() {
            break;
        }
        if a.nla_type == INET_DIAG_INFO {
            let payload = &attrs[off + size_of::<NlAttr>()..off + alen];
            if payload.len() >= TCPI_MIN_LEN {
                let last_recv = read_u32_ne(payload, TCPI_OFF_LAST_RECV);
                let rtt = read_u32_ne(payload, TCPI_OFF_RTT);
                let rttvar = read_u32_ne(payload, TCPI_OFF_RTTVAR);
                let retr = read_u32_ne(payload, TCPI_OFF_TOTAL_RETRANS);
                return Some((rtt, rttvar, retr, last_recv));
            }
        }
        off += (alen + 3) & !3;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const GOLDEN_NET_DEV: &[u8] = b"\
Inter-|   Receive                                                |  Transmit
 face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed
    lo: 1234567   1000    0    0    0     0          0         0  1234567   1000    0    0    0     0       0          0
 wlan0: 42000000  32000   0    0    0     0          0         0  6500000  15000   0    0    0     0       0          0
rmnet_data0: 18500000 14000 0 0 0 0 0 0 2100000 4000 0 0 0 0 0 0
rmnet_ipa0: 99999999 10000 0 0 0 0 0 0 99999999 10000 0 0 0 0 0 0
  tun0: 15000000  11000   0    0    0     0          0         0  1800000   3000   0    0    0     0       0          0
";

    #[test]
    fn golden_proc_net_dev_separates_wifi_cell_and_vpn() {
        let parsed = parse_proc_net_dev(GOLDEN_NET_DEV);
        assert_eq!(parsed.wifi_rx, 42_000_000);
        assert_eq!(parsed.wifi_tx, 6_500_000);
        assert_eq!(parsed.cell_rx, 18_500_000);
        assert_eq!(parsed.cell_tx, 2_100_000);
        assert!(parsed.vpn_active);
        // rmnet_ipa0 & lo & tun0 must NOT be double-counted into wifi/cell!
        assert_eq!(parsed.eth_rx, 0);
    }
}
