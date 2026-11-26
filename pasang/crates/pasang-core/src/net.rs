// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Pure-Rust networking primitives for `Pulih` & `Pasang` (`SPEC-0051` §5.7):
//! - HTTP/1.1 request builder (`Range` slicing) & response header parser
//! - LAN Web-Drop lightweight HTTP router + Material You HTML page
//! - DHCPv4 DISCOVER / OFFER packet codec
//! - SNTP (NTPv4) UDP packet codec for accurate RTC & TLS validation

use std::collections::BTreeMap;

/// Parsed HTTP/1.1 response header.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HttpResponseHead {
    pub status: u16,
    pub headers: BTreeMap<String, String>,
    pub body_offset: usize,
}

impl HttpResponseHead {
    pub fn content_length(&self) -> Option<u64> {
        self.headers.get("content-length")?.parse().ok()
    }

    pub fn location(&self) -> Option<&str> {
        self.headers.get("location").map(|s| s.as_str())
    }
}

/// Build an HTTP/1.1 GET request with optional byte `Range: bytes=start-end`.
pub fn build_http_get(host: &str, path: &str, range: Option<(u64, u64)>) -> String {
    let mut req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Pulih/1.0 (Yasvara)\r\nConnection: close\r\n"
    );
    if let Some((start, end)) = range {
        req.push_str(&format!("Range: bytes={start}-{end}\r\n"));
    }
    req.push_str("\r\n");
    req
}

/// Parse an HTTP/1.1 response header block terminated by `\r\n\r\n`.
pub fn parse_http_response_head(raw: &[u8]) -> Result<HttpResponseHead, &'static str> {
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .ok_or("incomplete HTTP header")?;
    let head_str = std::str::from_utf8(&raw[..split]).map_err(|_| "non-utf8 HTTP header")?;
    let mut lines = head_str.split("\r\n");
    let status_line = lines.next().ok_or("empty HTTP response")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .ok_or("missing HTTP status")?
        .parse()
        .map_err(|_| "invalid HTTP status code")?;

    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_ascii_lowercase(), v.trim().to_string());
        }
    }
    Ok(HttpResponseHead {
        status,
        headers,
        body_offset: split + 4,
    })
}

/// LAN Web-Drop embedded Material You HTML dashboard (`http://<ip>:8080`).
pub fn web_drop_index_html(device: &str, slot: char, free_gib: f32) -> String {
    format!(
        "<!doctype html><html><head><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>\
<title>Pulih Web-Drop - {device}</title>\
<style>body{{margin:0;background:#111318;color:#e2e2e9;font-family:system-ui,sans-serif;padding:24px}}\
.card{{background:#1e2028;border-radius:24px;padding:20px;margin-bottom:16px}}\
h1{{margin:0 0 8px;color:#d0bcff}}button{{background:#d0bcff;color:#381e72;border:0;border-radius:999px;padding:12px 24px;font-weight:600;cursor:pointer}}</style>\
</head><body><div class=card><h1>Pulih Web-Drop</h1><p>{device} &middot; Slot {slot} &middot; {free_gib:.2} GiB super free</p></div>\
<div class=card><h2>Flash OTA / Image</h2><form method=POST action=/upload enctype=multipart/form-data>\
<input type=file name=file required><br><br><button type=submit>Upload &amp; Stage</button></form></div>\
<div class=card><h2>Logs</h2><a href=/logs/recovery style='color:#d0bcff'>View recovery.log</a></div></body></html>"
    )
}

/// Build a minimal 48-byte SNTP (NTPv4 client mode=3) request packet.
pub fn build_sntp_request() -> [u8; 48] {
    let mut pkt = [0u8; 48];
    pkt[0] = 0x23; // LI=0, VN=4, Mode=3 (client)
    pkt
}

/// Parse Unix timestamp (seconds since 1970-01-01) from a 48-byte SNTP server reply.
pub fn parse_sntp_unix_secs(reply: &[u8]) -> Result<u64, &'static str> {
    if reply.len() < 48 {
        return Err("sntp reply too short");
    }
    let ntp_secs = u32::from_be_bytes([reply[40], reply[41], reply[42], reply[43]]) as u64;
    const NTP_UNIX_EPOCH_DELTA: u64 = 2_208_988_800;
    ntp_secs
        .checked_sub(NTP_UNIX_EPOCH_DELTA)
        .ok_or("sntp timestamp before 1970")
}

/// Parsed DHCPv4 OFFER / ACK lease parameters (RFC 2131).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DhcpOffer {
    pub yiaddr: [u8; 4],
    pub subnet_mask: [u8; 4],
    pub router: [u8; 4],
    pub server_id: [u8; 4],
}

/// Build a minimal DHCPv4 DISCOVER packet for `mac` and transaction ID `xid`.
pub fn build_dhcp_discover(mac: [u8; 6], xid: u32) -> Vec<u8> {
    let mut pkt = vec![0u8; 250];
    pkt[0] = 1; // BOOTREQUEST
    pkt[1] = 1; // Ethernet
    pkt[2] = 6; // MAC len
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    pkt[10..12].copy_from_slice(&0x8000u16.to_be_bytes()); // Broadcast flag
    pkt[28..34].copy_from_slice(&mac);
    // DHCP magic cookie 99.130.83.99
    pkt[236..240].copy_from_slice(&[99, 130, 83, 99]);
    // Option 53: DHCP Discover (1)
    pkt[240..243].copy_from_slice(&[53, 1, 1]);
    // Option 55: Parameter Request List (Subnet Mask=1, Router=3, DNS=6)
    pkt[243..248].copy_from_slice(&[55, 3, 1, 3, 6]);
    pkt[248] = 255; // End
    pkt
}

/// Build a DHCPv4 REQUEST packet committing the offered IPv4 lease.
pub fn build_dhcp_request(mac: [u8; 6], xid: u32, offer: &DhcpOffer) -> Vec<u8> {
    let mut pkt = vec![0u8; 260];
    pkt[0] = 1; // BOOTREQUEST
    pkt[1] = 1;
    pkt[2] = 6;
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());
    pkt[10..12].copy_from_slice(&0x8000u16.to_be_bytes());
    pkt[28..34].copy_from_slice(&mac);
    pkt[236..240].copy_from_slice(&[99, 130, 83, 99]);
    let mut pos = 240;
    pkt[pos..pos + 3].copy_from_slice(&[53, 1, 3]); // Option 53: DHCP Request (3)
    pos += 3;
    pkt[pos..pos + 2].copy_from_slice(&[50, 4]); // Option 50: Requested IP
    pkt[pos + 2..pos + 6].copy_from_slice(&offer.yiaddr);
    pos += 6;
    pkt[pos..pos + 2].copy_from_slice(&[54, 4]); // Option 54: Server Identifier
    pkt[pos + 2..pos + 6].copy_from_slice(&offer.server_id);
    pos += 6;
    pkt[pos] = 255;
    pkt
}

/// Parse a DHCPv4 OFFER / ACK packet matching `expected_xid`.
pub fn parse_dhcp_offer(pkt: &[u8], expected_xid: u32) -> Option<DhcpOffer> {
    if pkt.len() < 244 || pkt[0] != 2 {
        return None;
    }
    let xid = u32::from_be_bytes([pkt[4], pkt[5], pkt[6], pkt[7]]);
    if xid != expected_xid || &pkt[236..240] != [99, 130, 83, 99] {
        return None;
    }
    let yiaddr = [pkt[16], pkt[17], pkt[18], pkt[19]];
    if yiaddr == [0, 0, 0, 0] {
        return None;
    }
    let mut subnet_mask = [255, 255, 255, 0];
    let mut router = [yiaddr[0], yiaddr[1], yiaddr[2], 1];
    let mut server_id = [pkt[20], pkt[21], pkt[22], pkt[23]];

    let mut i = 240;
    while i < pkt.len() {
        let opt = pkt[i];
        i += 1;
        if opt == 255 {
            break;
        }
        if opt == 0 {
            continue;
        }
        if i >= pkt.len() {
            break;
        }
        let len = pkt[i] as usize;
        i += 1;
        if i + len > pkt.len() {
            break;
        }
        match opt {
            1 if len >= 4 => subnet_mask.copy_from_slice(&pkt[i..i + 4]),
            3 if len >= 4 => router.copy_from_slice(&pkt[i..i + 4]),
            54 if len >= 4 => server_id.copy_from_slice(&pkt[i..i + 4]),
            _ => {}
        }
        i += len;
    }
    Some(DhcpOffer {
        yiaddr,
        subnet_mask,
        router,
        server_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_range_request_and_response_parsing() {
        let req = build_http_get("github.com", "/Yasvara/ota.zip", Some((0, 65535)));
        assert!(req.contains("Range: bytes=0-65535\r\n"));

        let resp = b"HTTP/1.1 206 Partial Content\r\nContent-Length: 4\r\nContent-Range: bytes 0-3/100\r\n\r\nPK\x03\x04";
        let head = parse_http_response_head(resp).unwrap();
        assert_eq!(head.status, 206);
        assert_eq!(head.content_length(), Some(4));
        assert_eq!(&resp[head.body_offset..], b"PK\x03\x04");
    }

    #[test]
    fn sntp_and_dhcp_packet_codecs() {
        let req = build_sntp_request();
        assert_eq!(req[0], 0x23);

        let mut reply = [0u8; 48];
        let unix_now: u64 = 1_795_567_800;
        let ntp = (unix_now + 2_208_988_800) as u32;
        reply[40..44].copy_from_slice(&ntp.to_be_bytes());
        assert_eq!(parse_sntp_unix_secs(&reply).unwrap(), unix_now);

        let dhcp = build_dhcp_discover([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], 0xDEAD_BEEF);
        assert_eq!(&dhcp[236..240], &[99, 130, 83, 99]);
        assert_eq!(&dhcp[240..243], &[53, 1, 1]);

        // Roundtrip synthetic DHCP OFFER -> parse -> REQUEST
        let mut offer_pkt = vec![0u8; 260];
        offer_pkt[0] = 2; // BOOTREPLY
        offer_pkt[4..8].copy_from_slice(&0xDEAD_BEEFu32.to_be_bytes());
        offer_pkt[16..20].copy_from_slice(&[192, 168, 1, 77]);
        offer_pkt[236..240].copy_from_slice(&[99, 130, 83, 99]);
        offer_pkt[240..246].copy_from_slice(&[1, 4, 255, 255, 255, 0]);
        offer_pkt[246..252].copy_from_slice(&[3, 4, 192, 168, 1, 1]);
        offer_pkt[252..258].copy_from_slice(&[54, 4, 192, 168, 1, 1]);
        offer_pkt[258] = 255;
        let parsed = parse_dhcp_offer(&offer_pkt, 0xDEAD_BEEF).unwrap();
        assert_eq!(parsed.yiaddr, [192, 168, 1, 77]);
        assert_eq!(parsed.router, [192, 168, 1, 1]);
        let req_pkt = build_dhcp_request([0x02, 0x11, 0x22, 0x33, 0x44, 0x55], 0xDEAD_BEEF, &parsed);
        assert_eq!(&req_pkt[240..243], &[53, 1, 3]);
    }
}
