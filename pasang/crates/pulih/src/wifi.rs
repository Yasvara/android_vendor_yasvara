// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Lazy Zero-Bloat Wi-Fi 7 (`WCN7750`) + `wpa_supplicant` Scanner/Connector
//! + Pure-Rust DHCPv4 + Saved Android Wi-Fi Importer + ADB-over-Wi-Fi `:5555`
//! + LAN Web-Drop + `Jelajah Fast` Native BoringSSL HTTPS Browser (`SPEC-0051` §5.7–5.8).
//!
//! 0 bytes added to `recovery.img`: all WCN7750 modules, WPSS firmware, and
//! `wpa_supplicant` are mapped read-only from `super`/`modem` on demand!

use crate::super_mount::{expose_firmware_by_prefix, load_module_with_deps, mount_super_ro};
use pasang_core::html::{parse_html, ParsedPage};
use pasang_core::net::{
    build_dhcp_discover, build_dhcp_request, build_http_get, parse_dhcp_offer,
    parse_http_response_head, web_drop_index_html,
};
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::path::Path;
use std::process::Command;
use std::time::Duration;

#[cfg(target_os = "android")]
extern "C" {
    fn pulih_http_fetch(
        url: *const std::ffi::c_char,
        out_buf: *mut u8,
        out_cap: usize,
        out_len: *mut usize,
        err_buf: *mut u8,
        err_cap: usize,
    ) -> i32;
}

const VENDOR_LD_PATH: &str = "/mnt/vendor_ro/lib64:/mnt/system_ro/system/lib64:/system/lib64";
const WPA_CTRL_DIR: &str = "/tmp/wpa_ctrl";
const WPA_CONF_PATH: &str = "/tmp/wpa_supplicant.conf";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WifiState {
    Off,
    LoadingModules,
    Scanning,
    Connected,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SavedWifiNetwork {
    pub ssid: String,
    pub psk: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedWifi {
    pub ssid: String,
    pub rssi_dbm: i32,
    pub secured: bool,
}

#[derive(Clone, Debug)]
pub struct WifiManager {
    pub state: WifiState,
    pub ro_vendor_mounted: bool,
    pub active_slot_suffix: String,
    pub ssid: Option<String>,
    pub ip_addr: Option<String>,
    pub adb_wifi_port: Option<u16>,
    pub web_drop_port: Option<u16>,
    pub saved_networks: Vec<SavedWifiNetwork>,
    pub scanned_networks: Vec<ScannedWifi>,
    pub status_detail: String,
}

impl Default for WifiManager {
    fn default() -> Self {
        Self {
            state: WifiState::Off,
            ro_vendor_mounted: false,
            active_slot_suffix: "_a".into(),
            ssid: None,
            ip_addr: None,
            adb_wifi_port: None,
            web_drop_port: None,
            saved_networks: Vec::new(),
            scanned_networks: Vec::new(),
            status_detail: "Wi-Fi 7 OFF (0 B ramdisk bloat)".into(),
        }
    }
}

impl WifiManager {
    /// Mount `vendor_dlkm` / `system_dlkm` / `vendor` / `system` / `modem` RO, boot WCN7750 WPSS
    /// firmware, bring up `wlan0`, and launch `wpa_supplicant`!
    pub fn enable_lazy(&mut self) -> Result<String, String> {
        let suf = self.active_slot_suffix.as_str();
        if let Ok(fresh) = mount_super_ro("vendor_dlkm", suf, "/vendor_dlkm") {
            if fresh {
                self.ro_vendor_mounted = true;
            }
        }
        let _ = mount_super_ro("system_dlkm", suf, "/system_dlkm");
        let _ = mount_super_ro("vendor", suf, "/mnt/vendor_ro");
        let _ = mount_super_ro("system", suf, "/mnt/system_ro");

        // Mount modem partition RO with exact firmware_file SELinux context (verified live on onyx!)
        let _ = fs::create_dir_all("/vendor/firmware_mnt");
        let _ = fs::create_dir_all("/firmware");
        if !Path::new("/vendor/firmware_mnt/image").is_dir() {
            let modem_dev = format!("/dev/block/by-name/modem{suf}");
            let _ = Command::new("/system/bin/mount")
                .args([
                    "-t",
                    "vfat",
                    "-o",
                    "ro,context=u:object_r:firmware_file:s0",
                    &modem_dev,
                    "/vendor/firmware_mnt",
                ])
                .status();
        }
        if !Path::new("/vendor/etc").exists() {
            let _ = std::os::unix::fs::symlink("/mnt/vendor_ro/etc", "/vendor/etc");
        }
        if !Path::new("/vendor/firmware").exists() {
            let _ = std::os::unix::fs::symlink("/mnt/vendor_ro/firmware", "/vendor/firmware");
        }
        if !Path::new("/firmware/image").exists() {
            let _ = std::os::unix::fs::symlink("/vendor/firmware_mnt/image", "/firmware/image");
        }
        if !Path::new("/lib/firmware/wcn7750").exists()
            && Path::new("/vendor/firmware_mnt/image/wcn7750").is_dir()
        {
            let _ = std::os::unix::fs::symlink(
                "/vendor/firmware_mnt/image/wcn7750",
                "/lib/firmware/wcn7750",
            );
        }
        let _ = expose_firmware_by_prefix(
            Path::new("/mnt/vendor_ro/firmware"),
            &["wlan", "wcn", "kiwi", "peach", "bdwlan", "amss"],
        );

        if !Path::new("/sys/class/net/wlan0").is_dir() {
            self.state = WifiState::LoadingModules;
            let mod_dirs: &[&Path] = &[
                Path::new("/vendor_dlkm/lib/modules"),
                Path::new("/system_dlkm/lib/modules"),
                Path::new("/lib/modules"),
            ];
            if let Err(e) = load_module_with_deps("qca_cld3_wcn7750.ko", mod_dirs) {
                self.state = WifiState::Off;
                self.status_detail = format!("WCN7750 load: {e}");
                return Err(self.status_detail.clone());
            }
            // Boot WCN7750 WPSS remoteproc & turn on QCA CLD3 driver -> creates wlan0!
            let _ = fs::write("/sys/kernel/icnss/wpss_boot", "1");
            std::thread::sleep(Duration::from_millis(800));
            let _ = fs::write("/dev/wlan", "ON");
            for _ in 0..20 {
                if Path::new("/sys/class/net/wlan0").is_dir() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(150));
            }
        }

        if !Path::new("/sys/class/net/wlan0").is_dir() {
            self.state = WifiState::Off;
            self.status_detail = "WCN7750 loaded but wlan0 did not appear".into();
            return Err(self.status_detail.clone());
        }

        let _ = Command::new("/system/bin/ifconfig")
            .args(["wlan0", "up"])
            .status();
        self.ensure_wpa_supplicant();
        let _ = self.scan_networks();

        self.state = WifiState::Scanning;
        self.status_detail = format!(
            "wlan0 UP (WCN7750) - {} network(s) found",
            self.scanned_networks.len()
        );
        Ok(self.status_detail.clone())
    }

    fn ensure_wpa_supplicant(&self) {
        if Path::new(&format!("{WPA_CTRL_DIR}/wlan0")).exists() {
            return;
        }
        let _ = fs::create_dir_all(WPA_CTRL_DIR);
        let _ = fs::write(
            WPA_CONF_PATH,
            format!("ctrl_interface={WPA_CTRL_DIR}\nupdate_config=1\n"),
        );
        let bin = "/mnt/vendor_ro/bin/hw/wpa_supplicant";
        if Path::new(bin).exists() {
            let _ = Command::new(bin)
                .env("LD_LIBRARY_PATH", VENDOR_LD_PATH)
                .args(["-B", "-iwlan0", "-Dnl80211", "-c", WPA_CONF_PATH])
                .status();
            std::thread::sleep(Duration::from_millis(400));
        }
    }

    fn wpa_cli(&self, args: &[&str]) -> Option<String> {
        let bin = "/mnt/vendor_ro/bin/wpa_cli";
        if !Path::new(bin).exists() {
            return None;
        }
        let out = Command::new(bin)
            .env("LD_LIBRARY_PATH", VENDOR_LD_PATH)
            .args(["-p", WPA_CTRL_DIR, "-i", "wlan0"])
            .args(args)
            .output()
            .ok()?;
        Some(String::from_utf8_lossy(&out.stdout).to_string())
    }

    /// Scan nearby Wi-Fi networks via `wpa_cli`.
    pub fn scan_networks(&mut self) -> Vec<ScannedWifi> {
        self.ensure_wpa_supplicant();
        let _ = self.wpa_cli(&["scan"]);
        std::thread::sleep(Duration::from_millis(900));
        let Some(raw) = self.wpa_cli(&["scan_results"]) else {
            return self.scanned_networks.clone();
        };
        let mut seen = Vec::new();
        for line in raw.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() >= 5 {
                let rssi = cols[2].trim().parse::<i32>().unwrap_or(-90);
                let flags = cols[3];
                let ssid = cols[4].trim().to_string();
                if ssid.is_empty() || seen.iter().any(|x: &ScannedWifi| x.ssid == ssid) {
                    continue;
                }
                seen.push(ScannedWifi {
                    ssid,
                    rssi_dbm: rssi,
                    secured: flags.contains("WPA") || flags.contains("WEP") || flags.contains("SAE"),
                });
            }
        }
        seen.sort_by(|a, b| b.rssi_dbm.cmp(&a.rssi_dbm));
        self.scanned_networks = seen.clone();
        seen
    }

    /// Connect to an SSID (WPA2/WPA3 PSK or Open) + obtain IPv4 via pure-Rust DHCPv4!
    pub fn connect_network(&mut self, ssid: &str, psk: &str) -> Result<String, String> {
        self.ensure_wpa_supplicant();
        let _ = self.wpa_cli(&["remove_network", "all"]);
        let net_id = self
            .wpa_cli(&["add_network"])
            .map(|s| s.trim().to_string())
            .filter(|s| s.chars().all(|c| c.is_ascii_digit()) && !s.is_empty())
            .ok_or_else(|| "wpa_supplicant not running (is Wi-Fi 7 ON?)".to_string())?;

        let quoted_ssid = format!("\"{ssid}\"");
        let _ = self.wpa_cli(&["set_network", &net_id, "ssid", &quoted_ssid]);
        if psk.is_empty() {
            let _ = self.wpa_cli(&["set_network", &net_id, "key_mgmt", "NONE"]);
        } else {
            let quoted_psk = format!("\"{psk}\"");
            let _ = self.wpa_cli(&["set_network", &net_id, "psk", &quoted_psk]);
        }
        let _ = self.wpa_cli(&["enable_network", &net_id]);
        let _ = self.wpa_cli(&["select_network", &net_id]);

        // Wait up to 8s for WPA handshake completion
        let mut associated = false;
        for _ in 0..20 {
            if let Some(st) = self.wpa_cli(&["status"]) {
                if st.contains("wpa_state=COMPLETED") {
                    associated = true;
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(400));
        }
        if !associated {
            self.status_detail = format!("Auth timeout for '{ssid}' (check password)");
            return Err(self.status_detail.clone());
        }

        // Acquire IPv4 + default gateway via built-in pure-Rust DHCPv4!
        let ip = self.acquire_dhcp_ipv4()?;
        self.ssid = Some(ssid.to_string());
        self.ip_addr = Some(ip.clone());
        self.state = WifiState::Connected;
        self.status_detail = format!("Connected: {ssid} ({ip})");
        Ok(self.status_detail.clone())
    }

    fn acquire_dhcp_ipv4(&self) -> Result<String, String> {
        let mac_str = fs::read_to_string("/sys/class/net/wlan0/address")
            .unwrap_or_else(|_| "02:00:00:00:00:01".into());
        let mut mac = [0x02u8, 0, 0, 0, 0, 1];
        for (i, hex) in mac_str.trim().split(':').take(6).enumerate() {
            if let Ok(b) = u8::from_str_radix(hex, 16) {
                mac[i] = b;
            }
        }
        let xid = 0x5956_7750u32;
        let discover = build_dhcp_discover(mac, xid);

        let sock = UdpSocket::bind("0.0.0.0:68")
            .or_else(|_| UdpSocket::bind("0.0.0.0:0"))
            .map_err(|e| format!("DHCP socket failed: {e}"))?;
        let _ = sock.set_broadcast(true);
        let _ = sock.set_read_timeout(Some(Duration::from_secs(3)));

        let mut buf = [0u8; 1024];
        for _ in 0..3 {
            let _ = sock.send_to(&discover, "255.255.255.255:67");
            if let Ok((n, _)) = sock.recv_from(&mut buf) {
                if let Some(offer) = parse_dhcp_offer(&buf[..n], xid) {
                    // Send RFC 2131 DHCP REQUEST so router commits the IPv4 lease
                    let req = build_dhcp_request(mac, xid, &offer);
                    let _ = sock.send_to(&req, "255.255.255.255:67");
                    let _ = sock.recv_from(&mut buf);
                    let ip_s = format!(
                        "{}.{}.{}.{}",
                        offer.yiaddr[0], offer.yiaddr[1], offer.yiaddr[2], offer.yiaddr[3]
                    );
                    let mask_s = format!(
                        "{}.{}.{}.{}",
                        offer.subnet_mask[0],
                        offer.subnet_mask[1],
                        offer.subnet_mask[2],
                        offer.subnet_mask[3]
                    );
                    let gw_s = format!(
                        "{}.{}.{}.{}",
                        offer.router[0], offer.router[1], offer.router[2], offer.router[3]
                    );
                    let _ = Command::new("/system/bin/ifconfig")
                        .args(["wlan0", &ip_s, "netmask", &mask_s, "up"])
                        .status();
                    let _ = Command::new("/system/bin/route")
                        .args(["add", "default", "gw", &gw_s, "dev", "wlan0"])
                        .status();
                    let _ = fs::write("/etc/resolv.conf", "nameserver 1.1.1.1\nnameserver 8.8.8.8\n");
                    return Ok(ip_s);
                }
            }
        }
        Err("DHCP lease timeout on wlan0".into())
    }

    /// Safe teardown required before flashing any partition on the active slot.
    pub fn teardown_for_active_slot_flash(&mut self) {
        let _ = self.wpa_cli(&["terminate"]);
        let _ = fs::write("/dev/wlan", "OFF");
        self.adb_wifi_port = None;
        self.web_drop_port = None;
        self.ssid = None;
        self.ip_addr = None;
        if self.ro_vendor_mounted {
            let _ = Command::new("/system/bin/umount").arg("/vendor_dlkm").status();
            self.ro_vendor_mounted = false;
        }
        self.state = WifiState::Off;
        self.status_detail = "Wi-Fi 7 OFF".into();
    }

    pub fn enable_adb_over_wifi(&mut self) -> Result<u16, &'static str> {
        if self.state != WifiState::Connected {
            return Err("connect to Wi-Fi before enabling ADB over Wi-Fi");
        }
        let _ = Command::new("/system/bin/setprop")
            .args(["service.adb.tcp.port", "5555"])
            .status();
        let _ = Command::new("/system/bin/setprop")
            .args(["ctl.restart", "adbd"])
            .status();
        self.adb_wifi_port = Some(5555);
        Ok(5555)
    }

    pub fn web_drop_homepage(&self, device: &str, slot: char, free_gib: f32) -> String {
        web_drop_index_html(device, slot, free_gib)
    }
}

/// Parse saved Wi-Fi SSID + PSK entries from Android's `WifiConfigStore.xml`
/// (`/data/misc/apexdata/com.android.wifi/WifiConfigStore.xml`) in pure Rust.
pub fn parse_android_wifi_config_xml(xml: &str) -> Vec<SavedWifiNetwork> {
    let mut out = Vec::new();
    for block in xml.split("<WifiConfiguration>").skip(1) {
        let Some(end) = block.find("</WifiConfiguration>") else {
            continue;
        };
        let cfg = &block[..end];
        let ssid = extract_xml_string(cfg, "SSID")
            .map(|s| s.replace("&quot;", "\"").trim_matches('"').to_string());
        let psk = extract_xml_string(cfg, "PreSharedKey")
            .map(|s| s.replace("&quot;", "\"").trim_matches('"').to_string())
            .unwrap_or_default();
        if let Some(s) = ssid {
            if !s.is_empty() && !out.iter().any(|n: &SavedWifiNetwork| n.ssid == s) {
                out.push(SavedWifiNetwork { ssid: s, psk });
            }
        }
    }
    out
}

fn extract_xml_string(xml: &str, name_attr: &str) -> Option<String> {
    let needle = format!("<string name=\"{name_attr}\">");
    let start = xml.find(&needle)? + needle.len();
    let rest = &xml[start..];
    let end = rest.find("</string>")?;
    Some(rest[..end].to_string())
}

/// Curated 1-tap `Jelajah Fast` bookmarks (`SPEC-0051` §5.8).
pub const DEFAULT_BOOKMARKS: &[(&str, &str)] = &[
    ("Start", "pulih://home"),
    ("Yasvara", "https://github.com/Yasvara"),
    ("Devices", "https://github.com/Yasvara-Devices"),
    ("DDG Lite", "https://lite.duckduckgo.com/lite/"),
];

/// Render an HTML document into `Jelajah Fast`'s structured page model.
pub fn parse_jelajah_page(html: &str) -> ParsedPage {
    parse_html(html)
}

/// Built-in offline start page so `Jelajah Fast` renders immediately even without Wi-Fi!
pub fn builtin_jelajah_home_html() -> &'static str {
    r#"<!doctype html><html><head><title>Jelajah Fast - Pulih Recovery Browser</title></head><body>
    <h1>Jelajah Fast Browser (BoringSSL TLS 1.3)</h1>
    <p>Pure-Rust zero-JS recovery browser with native BoringSSL HTTPS and built-in DNS (1.1.1.1).</p>
    <p>Turn on Wi-Fi 7 in the Wi-Fi tab to browse live HTTPS sites, search DuckDuckGo, or download OTA ZIPs.</p>
    <h2>Quick Catalogs &amp; Mirrors</h2>
    <p><a href="https://github.com/Yasvara">GitHub: Yasvara Platform Repos</a></p>
    <p><a href="https://github.com/Yasvara-Devices">GitHub: Yasvara-Devices (onyx / grus)</a></p>
    <p><a href="https://lite.duckduckgo.com/lite/">DuckDuckGo Lite Search (Zero-JS)</a></p>
    <p><a href="https://example.com/">Example.com (HTTPS Connectivity Test)</a></p>
    <p><a href="pulih://status">Pulih Local Network &amp; Hardware Status</a></p>
    </body></html>"#
}

/// Resolve relative URLs (`href="/foo"` or `href="//host/bar"`) against `base_url`.
pub fn resolve_url(base_url: &str, href: &str) -> String {
    let h = href.trim();
    if h.starts_with("http://") || h.starts_with("https://") || h.starts_with("pulih://") {
        return h.to_string();
    }
    if h.starts_with("//") {
        return format!("https:{h}");
    }
    if let Some(scheme_end) = base_url.find("://") {
        let after = &base_url[scheme_end + 3..];
        let origin_len = after.find('/').unwrap_or(after.len());
        let origin = &base_url[..scheme_end + 3 + origin_len];
        if h.starts_with('/') {
            return format!("{origin}{h}");
        }
        return format!("{origin}/{h}");
    }
    h.to_string()
}

/// Normalize user input from the URL bar: plain search words become a DuckDuckGo Lite query!
pub fn normalize_browser_input(raw: &str) -> String {
    let s = raw.trim();
    if s.is_empty() {
        return "pulih://home".into();
    }
    if s.contains("://") {
        return s.to_string();
    }
    if !s.contains(' ') && s.contains('.') {
        return format!("https://{s}");
    }
    let encoded = s.replace(' ', "+");
    format!("https://lite.duckduckgo.com/lite/?q={encoded}")
}

/// Fetch a URL for `Jelajah Fast`:
/// - `pulih://home` / `pulih://status` -> instant local pages
/// - `https://` & `http://` -> native BoringSSL TLS 1.3 + UDP DNS (`1.1.1.1`) on Android,
///   with pure-Rust HTTP/1.1 fallback!
pub fn fetch_jelajah_url(url: &str) -> Result<ParsedPage, String> {
    let trimmed = url.trim();
    if trimmed.is_empty() || trimmed == "pulih://home" {
        return Ok(parse_html(builtin_jelajah_home_html()));
    }
    if trimmed == "pulih://status" {
        let wlan_up = Path::new("/sys/class/net/wlan0").is_dir();
        let kgsl_up = Path::new("/dev/kgsl-3d0").exists();
        let html = format!(
            "<html><head><title>Pulih Live Status</title></head><body>\
            <h1>Pulih Recovery Diagnostics</h1>\
            <p>Wi-Fi 7 (wlan0): {}</p>\
            <p>Adreno GPU (/dev/kgsl-3d0): {}</p>\
            <p>TLS Engine: Native BoringSSL TLS 1.3 + Built-in UDP DNS (1.1.1.1 / 8.8.8.8)</p>\
            <p><a href=\"pulih://home\">Back to Jelajah Start Page</a></p>\
            </body></html>",
            if wlan_up { "UP" } else { "OFF (enable in Wi-Fi 7 tab)" },
            if kgsl_up { "ACTIVE (Adreno840)" } else { "OFF" },
        );
        return Ok(parse_html(&html));
    }

    #[cfg(target_os = "android")]
    if trimmed.starts_with("https://") || trimmed.starts_with("http://") {
        use std::ffi::CString;
        let c_url = CString::new(trimmed).map_err(|_| "invalid URL")?;
        let mut out_buf = vec![0u8; 512 * 1024];
        let mut out_len: usize = 0;
        let mut err_buf = vec![0u8; 256];
        let rc = unsafe {
            pulih_http_fetch(
                c_url.as_ptr(),
                out_buf.as_mut_ptr(),
                out_buf.len(),
                &mut out_len,
                err_buf.as_mut_ptr(),
                err_buf.len(),
            )
        };
        if rc == 0 {
            let body = String::from_utf8_lossy(&out_buf[..out_len]);
            let mut page = parse_html(&body);
            if page.title.is_empty() {
                page.title = trimmed.to_string();
            }
            for link in &mut page.links {
                link.href = resolve_url(trimmed, &link.href);
            }
            return Ok(page);
        }
        let end = err_buf.iter().position(|&b| b == 0).unwrap_or(err_buf.len());
        let msg = String::from_utf8_lossy(&err_buf[..end]).trim().to_string();
        return Err(if msg.is_empty() {
            format!("Fetch failed (err={rc}) - connect Wi-Fi 7 first")
        } else {
            msg
        });
    }

    if let Some(rest) = trimmed.strip_prefix("http://") {
        let (host_port, path) = match rest.find('/') {
            Some(i) => (&rest[..i], &rest[i..]),
            None => (rest, "/"),
        };
        let addr = if host_port.contains(':') {
            host_port.to_string()
        } else {
            format!("{host_port}:80")
        };
        let mut stream = TcpStream::connect(&addr)
            .map_err(|e| format!("HTTP connect {addr} failed (is Wi-Fi connected?): {e}"))?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(6)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(4)));
        let req = build_http_get(host_port, path, None);
        stream.write_all(req.as_bytes()).map_err(|e| e.to_string())?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 4096];
        while buf.len() < 256 * 1024 {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        let head = parse_http_response_head(&buf).map_err(|e| e.to_string())?;
        let body = String::from_utf8_lossy(&buf[head.body_offset..]);
        let mut page = parse_html(&body);
        for link in &mut page.links {
            link.href = resolve_url(trimmed, &link.href);
        }
        return Ok(page);
    }
    Err(format!("Connect Wi-Fi 7 first to load {trimmed}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wifi_adb_requires_connection_and_teardown_clears_vendor_mount() {
        let mut wm = WifiManager::default();
        assert!(wm.enable_adb_over_wifi().is_err());

        wm.state = WifiState::Connected;
        wm.ro_vendor_mounted = true;
        wm.ip_addr = Some("192.168.1.42".into());
        assert_eq!(wm.enable_adb_over_wifi().unwrap(), 5555);

        wm.teardown_for_active_slot_flash();
        assert_eq!(wm.state, WifiState::Off);
        assert!(!wm.ro_vendor_mounted);
        assert!(wm.adb_wifi_port.is_none());
    }

    #[test]
    fn parses_saved_android_wifi_config_xml() {
        let sample = r#"
        <WifiConfigStoreData>
          <NetworkList>
            <Network><WifiConfiguration>
              <string name="SSID">&quot;HomeWiFi7&quot;</string>
              <string name="PreSharedKey">"supersecret"</string>
            </WifiConfiguration></Network>
            <Network><WifiConfiguration>
              <string name="SSID">"CafeOpen"</string>
            </WifiConfiguration></Network>
          </NetworkList>
        </WifiConfigStoreData>"#;
        let nets = parse_android_wifi_config_xml(sample);
        assert_eq!(nets.len(), 2);
        assert_eq!(nets[0].ssid, "HomeWiFi7");
        assert_eq!(nets[0].psk, "supersecret");
        assert_eq!(nets[1].ssid, "CafeOpen");
    }

    #[test]
    fn web_drop_url_resolver_and_jelajah_builtin_home_work() {
        let wm = WifiManager::default();
        let html = wm.web_drop_homepage("onyx", 'A', 6.03);
        let page = parse_jelajah_page(&html);
        assert!(page.title.contains("Pulih Web-Drop"));
        assert!(page.links.iter().any(|l| l.href == "/logs/recovery"));

        let home = fetch_jelajah_url("pulih://home").unwrap();
        assert!(home.title.contains("Jelajah Fast"));
        assert!(home.links.len() >= 4);

        assert_eq!(
            resolve_url("https://github.com/Yasvara", "/Yasvara/android"),
            "https://github.com/Yasvara/android"
        );
        assert_eq!(
            normalize_browser_input("poco f7 doom"),
            "https://lite.duckduckgo.com/lite/?q=poco+f7+doom"
        );
        assert_eq!(
            normalize_browser_input("example.com"),
            "https://example.com"
        );
    }
}
