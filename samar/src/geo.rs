// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Coordinate input: decimal and DMS pairs, geo: URIs, map URLs and Open Location Codes.

/// Mean Earth radius (IUGG), metres.
pub const EARTH_RADIUS_M: f64 = 6_371_008.8;

pub fn valid(lat: f64, lng: f64) -> bool {
    lat.is_finite() && lng.is_finite() && (-90.0..=90.0).contains(&lat) && (-180.0..=180.0).contains(&lng)
}

/// Point reached from (lat, lng) after `distance_m` along `bearing_deg`.
pub fn destination(lat: f64, lng: f64, bearing_deg: f64, distance_m: f64) -> (f64, f64) {
    let d = distance_m / EARTH_RADIUS_M;
    let (p1, l1, b) = (lat.to_radians(), lng.to_radians(), bearing_deg.to_radians());
    let p2 = (p1.sin() * d.cos() + p1.cos() * d.sin() * b.cos()).asin();
    let l2 = l1 + (b.sin() * d.sin() * p1.cos()).atan2(d.cos() - p1.sin() * p2.sin());
    (p2.to_degrees(), normalize_lng(l2.to_degrees()))
}

/// Great-circle distance in metres.
pub fn distance(lat1: f64, lng1: f64, lat2: f64, lng2: f64) -> f64 {
    let (p1, p2) = (lat1.to_radians(), lat2.to_radians());
    let dp = p2 - p1;
    let dl = (lng2 - lng1).to_radians();
    let a = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_M * a.sqrt().min(1.0).asin()
}

/// Shifts a point by north/east offsets in metres.
pub fn offset(lat: f64, lng: f64, north_m: f64, east_m: f64) -> (f64, f64) {
    let dlat = (north_m / EARTH_RADIUS_M).to_degrees();
    let dlng = (east_m / (EARTH_RADIUS_M * lat.to_radians().cos().max(1e-6))).to_degrees();
    ((lat + dlat).clamp(-90.0, 90.0), normalize_lng(lng + dlng))
}

pub fn normalize_lng(lng: f64) -> f64 {
    let mut l = (lng + 180.0) % 360.0;
    if l < 0.0 {
        l += 360.0;
    }
    l - 180.0
}

/// Parses free-form location text. Short plus codes resolve against (ref_lat, ref_lng).
pub fn parse(text: &str, ref_lat: f64, ref_lng: f64) -> Option<(f64, f64)> {
    let t = text.trim();
    if t.is_empty() {
        return None;
    }
    let found = from_url(t)
        .or_else(|| plus_code(t, ref_lat, ref_lng))
        .or_else(|| pair(t));
    found.filter(|&(a, b)| valid(a, b))
}

fn from_url(t: &str) -> Option<(f64, f64)> {
    let lower = t.to_ascii_lowercase();
    if let Some(rest) = lower.strip_prefix("geo:") {
        let (head, query) = rest.split_once('?').unwrap_or((rest, ""));
        let head = head.split(';').next().unwrap_or("");
        if let Some(p) = decimal_pair(head).filter(|&(a, b)| a != 0.0 || b != 0.0) {
            return Some(p);
        }
        return query_value(query, &["q"]).and_then(|v| decimal_pair(v.split('(').next().unwrap_or("")));
    }
    if !(lower.starts_with("http") || lower.contains("maps") || lower.contains("@")) {
        return None;
    }
    // Place pages carry the pin as !3d<lat>!4d<lng>; the @ part is only the camera.
    if let (Some(a), Some(b)) = (lower.find("!3d"), lower.find("!4d")) {
        if let (Some(lat), Some(lng)) = (leading_number(&lower[a + 3..]), leading_number(&lower[b + 3..])) {
            return Some((lat, lng));
        }
    }
    let query = lower.split_once('?').map(|(_, q)| q).unwrap_or("");
    if let Some(p) = query_value(query, &["q", "query", "ll", "center", "destination", "daddr", "sll", "mlat"])
        .and_then(|v| decimal_pair(&percent_decode(v)))
    {
        return Some(p);
    }
    if let (Some(lat), Some(lng)) = (query_value(query, &["mlat", "lat"]), query_value(query, &["mlon", "lon", "lng"])) {
        if let (Ok(a), Ok(b)) = (lat.parse(), lng.parse()) {
            return Some((a, b));
        }
    }
    if let Some(at) = lower.find('@') {
        return decimal_pair(lower[at + 1..].split(['/', '?']).next().unwrap_or(""));
    }
    // OpenStreetMap style: #map=<zoom>/<lat>/<lng>
    if let Some(m) = lower.find("map=") {
        let parts: Vec<&str> = lower[m + 4..].split(['/', '&']).collect();
        if parts.len() >= 3 {
            if let (Ok(a), Ok(b)) = (parts[1].parse(), parts[2].parse()) {
                return Some((a, b));
            }
        }
    }
    None
}

fn query_value<'a>(query: &'a str, keys: &[&str]) -> Option<&'a str> {
    for part in query.split(['&', '#']) {
        if let Some((k, v)) = part.split_once('=') {
            if keys.contains(&k) && !v.is_empty() {
                return Some(v);
            }
        }
    }
    None
}

fn percent_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        match b[i] {
            b'%' if i + 2 < b.len() => {
                let hex = core::str::from_utf8(&b[i + 1..i + 3]).ok().and_then(|h| u8::from_str_radix(h, 16).ok());
                match hex {
                    Some(v) => {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                    None => out.push(b'%'),
                }
            }
            b'+' => out.push(b' '),
            c => out.push(c),
        }
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn leading_number(s: &str) -> Option<f64> {
    let end = s
        .char_indices()
        .find(|&(i, c)| !(c.is_ascii_digit() || c == '.' || (i == 0 && (c == '-' || c == '+'))))
        .map(|(i, _)| i)
        .unwrap_or(s.len());
    s[..end].parse().ok()
}

fn decimal_pair(s: &str) -> Option<(f64, f64)> {
    let mut nums = s.split(|c: char| c == ',' || c.is_whitespace()).filter(|p| !p.is_empty());
    let a = nums.next()?.parse().ok()?;
    let b = nums.next()?.trim_end_matches('z').parse().ok()?;
    Some((a, b))
}

/// "lat, lng", "-7.25 112.75", "7.25 S 112.75 E", "7°15'30\"S 112°45'10\"E".
fn pair(t: &str) -> Option<(f64, f64)> {
    let mut values = Vec::new();
    let mut current = Angle::default();
    let mut num = String::new();
    let flush = |num: &mut String, current: &mut Angle| -> Option<()> {
        if !num.is_empty() {
            current.push(num.parse().ok()?)?;
            num.clear();
        }
        Some(())
    };
    for c in t.chars() {
        match c {
            '0'..='9' | '.' | '-' | '+' if current.ended => {
                values.push(current.finish());
                current = Angle::default();
                if c == '-' || c == '+' {
                    current.negative = c == '-';
                } else {
                    num.push(c);
                }
            }
            '0'..='9' | '.' => num.push(c),
            '-' | '+' if num.is_empty() && current.parts == 0 => current.negative = c == '-',
            '°' | 'º' | 'd' | '\'' | '′' | '"' | '″' => {
                flush(&mut num, &mut current)?;
            }
            'N' | 'n' | 'E' | 'e' | 'S' | 's' | 'W' | 'w' => {
                flush(&mut num, &mut current)?;
                let hemi = c.to_ascii_uppercase();
                if current.parts == 0 {
                    // Prefix form: "S 7.25"
                    current.hemisphere = Some(hemi);
                } else {
                    current.hemisphere = Some(hemi);
                    values.push(current.finish());
                    current = Angle::default();
                }
            }
            ',' | ';' => {
                flush(&mut num, &mut current)?;
                if current.parts > 0 {
                    values.push(current.finish());
                    current = Angle::default();
                }
            }
            c if c.is_whitespace() => {
                flush(&mut num, &mut current)?;
                // A plain decimal ends at a space, unless a hemisphere letter follows it.
                if current.parts == 1 && !current.dms {
                    current.ended = true;
                }
            }
            _ => return None,
        }
        if matches!(c, '°' | 'º' | 'd' | '\'' | '′') {
            current.dms = true;
        }
    }
    flush(&mut num, &mut current)?;
    if current.parts > 0 {
        values.push(current.finish());
    }
    if values.len() != 2 {
        return None;
    }
    let (mut a, mut b) = (values[0], values[1]);
    // Hemisphere letters may name the axis: "112E 7S".
    if a.1 == Some('E') || a.1 == Some('W') || b.1 == Some('N') || b.1 == Some('S') {
        core::mem::swap(&mut a, &mut b);
    }
    Some((a.0, b.0))
}

#[derive(Default)]
struct Angle {
    deg: f64,
    parts: u8,
    negative: bool,
    dms: bool,
    ended: bool,
    hemisphere: Option<char>,
}

impl Angle {
    fn push(&mut self, v: f64) -> Option<()> {
        self.deg += match self.parts {
            0 => v,
            1 => v / 60.0,
            2 => v / 3600.0,
            _ => return None,
        };
        self.parts += 1;
        Some(())
    }

    fn finish(&self) -> (f64, Option<char>) {
        let neg = self.negative ^ matches!(self.hemisphere, Some('S') | Some('W'));
        (if neg { -self.deg } else { self.deg }, self.hemisphere)
    }
}

const OLC_ALPHABET: &[u8; 20] = b"23456789CFGHJMPQRVWX";
const OLC_SEPARATOR_POS: usize = 8;
const OLC_PAIR_RES: [f64; 5] = [20.0, 1.0, 0.05, 0.0025, 0.000125];

fn olc_digit(c: u8) -> Option<usize> {
    OLC_ALPHABET.iter().position(|&a| a == c.to_ascii_uppercase())
}

/// Full or short Open Location Code, optionally followed by a locality (ignored).
fn plus_code(t: &str, ref_lat: f64, ref_lng: f64) -> Option<(f64, f64)> {
    let token = t.split_whitespace().find(|w| w.contains('+'))?;
    let token = token.trim_end_matches(',');
    let sep = token.find('+')?;
    if sep > OLC_SEPARATOR_POS || sep % 2 != 0 || sep < 2 {
        return None;
    }
    let digits: Vec<u8> = token.bytes().filter(|&c| c != b'+' && c != b'0').collect();
    if digits.iter().any(|&c| olc_digit(c).is_none()) {
        return None;
    }
    if sep == OLC_SEPARATOR_POS {
        return olc_decode(&digits);
    }
    if !valid(ref_lat, ref_lng) {
        return None;
    }
    let padding = OLC_SEPARATOR_POS - sep;
    let resolution = 20f64.powi(2 - (padding / 2) as i32);
    let half = resolution / 2.0;
    let mut full = olc_encode_prefix(ref_lat, ref_lng, padding);
    full.extend_from_slice(&digits);
    let (mut lat, mut lng) = olc_decode(&full)?;
    if ref_lat + half < lat && lat - resolution >= -90.0 {
        lat -= resolution;
    } else if ref_lat - half > lat && lat + resolution <= 90.0 {
        lat += resolution;
    }
    if ref_lng + half < lng {
        lng -= resolution;
    } else if ref_lng - half > lng {
        lng += resolution;
    }
    Some((lat, normalize_lng(lng)))
}

fn olc_encode_prefix(lat: f64, lng: f64, len: usize) -> Vec<u8> {
    let mut la = lat.clamp(-90.0, 90.0 - 1e-9) + 90.0;
    let mut lo = normalize_lng(lng) + 180.0;
    let mut out = Vec::with_capacity(len);
    for res in OLC_PAIR_RES.iter().take(len / 2) {
        let dl = (la / res).floor().clamp(0.0, 19.0);
        let dg = (lo / res).floor().clamp(0.0, 19.0);
        out.push(OLC_ALPHABET[dl as usize]);
        out.push(OLC_ALPHABET[dg as usize]);
        la -= dl * res;
        lo -= dg * res;
    }
    out
}

/// Centre of the area named by a full code's digits (separator removed).
fn olc_decode(digits: &[u8]) -> Option<(f64, f64)> {
    if digits.len() < 2 {
        return None;
    }
    let (mut lat, mut lng) = (-90.0, -180.0);
    let (mut h, mut w) = (0.0, 0.0);
    for (i, pair) in digits.chunks(2).take(5).enumerate() {
        let res = OLC_PAIR_RES[i];
        lat += olc_digit(pair[0])? as f64 * res;
        h = res;
        w = res;
        if let Some(&c) = pair.get(1) {
            lng += olc_digit(c)? as f64 * res;
        }
    }
    for &c in digits.iter().skip(10) {
        let d = olc_digit(c)?;
        h /= 5.0;
        w /= 4.0;
        lat += (d / 4) as f64 * h;
        lng += (d % 4) as f64 * w;
    }
    Some((lat + h / 2.0, lng + w / 2.0))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn close(p: Option<(f64, f64)>, lat: f64, lng: f64, tol: f64) {
        let (a, b) = p.expect("parsed");
        assert!((a - lat).abs() < tol && (b - lng).abs() < tol, "got {a},{b} want {lat},{lng}");
    }

    #[test]
    fn decimal_pairs() {
        close(parse("-7.2575, 112.7521", 0.0, 0.0), -7.2575, 112.7521, 1e-9);
        close(parse("-7.2575 112.7521", 0.0, 0.0), -7.2575, 112.7521, 1e-9);
        close(parse("7.2575 S, 112.7521 E", 0.0, 0.0), -7.2575, 112.7521, 1e-9);
        close(parse("112.7521E 7.2575S", 0.0, 0.0), -7.2575, 112.7521, 1e-9);
        assert!(parse("91, 10", 0.0, 0.0).is_none());
        assert!(parse("hello", 0.0, 0.0).is_none());
    }

    #[test]
    fn dms() {
        close(parse("7°15'27\"S 112°45'07.6\"E", 0.0, 0.0), -7.2575, 112.752111, 1e-5);
        close(parse("6°10′31″S, 106°49′38″E", 0.0, 0.0), -6.175278, 106.827222, 1e-5);
    }

    #[test]
    fn map_urls() {
        close(
            parse("https://www.google.com/maps/@-7.2575,112.7521,15z", 0.0, 0.0),
            -7.2575,
            112.7521,
            1e-9,
        );
        close(
            parse(
                "https://www.google.com/maps/place/Tugu+Pahlawan/@-7.24,112.73,17z/data=!3m1!4b1!4m6!3m5!1s0x0:0x0!8m2!3d-7.2458!4d112.7378",
                0.0,
                0.0,
            ),
            -7.2458,
            112.7378,
            1e-9,
        );
        close(parse("https://maps.google.com/?q=-6.2,106.8", 0.0, 0.0), -6.2, 106.8, 1e-9);
        close(parse("https://maps.google.com/?q=-6.2%2C106.8", 0.0, 0.0), -6.2, 106.8, 1e-9);
        close(parse("geo:-6.2,106.8?z=12", 0.0, 0.0), -6.2, 106.8, 1e-9);
        close(parse("geo:0,0?q=-6.2,106.8(Monas)", 0.0, 0.0), -6.2, 106.8, 1e-9);
        close(
            parse("https://www.openstreetmap.org/#map=16/-7.2575/112.7521", 0.0, 0.0),
            -7.2575,
            112.7521,
            1e-9,
        );
    }

    #[test]
    fn plus_codes() {
        // Reference values from the Open Location Code test vectors.
        close(parse("7FG49Q00+", 0.0, 0.0), 20.375, 2.775, 1e-9);
        close(parse("8FVC9G8F+6W", 0.0, 0.0), 47.365562, 8.524813, 1e-6);
        close(parse("9G8F+6W Zurich", 47.4, 8.6), 47.365562, 8.524813, 1e-6);
        close(parse("8FVC9G8F+6WQ", 0.0, 0.0), 47.3655875, 8.524859375, 1e-6);
    }

    #[test]
    fn geodesy() {
        let (lat, lng) = destination(-7.25, 112.75, 90.0, 1000.0);
        assert!((distance(-7.25, 112.75, lat, lng) - 1000.0).abs() < 0.01);
        let (a, b) = offset(-7.25, 112.75, 10.0, 0.0);
        assert!((distance(-7.25, 112.75, a, b) - 10.0).abs() < 0.01);
        assert!((normalize_lng(190.0) + 170.0).abs() < 1e-9);
    }
}
