// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Zero-dependency RFC 5280 X.509 v3 DER parser, metadata extractor, and TBS mutator (`alloc`).
//!
//! Eliminates external `x509-cert` / `der` / `spki` / `const-oid` dependencies so `integrity-attest`
//! builds anywhere in AOSP (`vendor/`, `system/`, host) with zero visibility workarounds.

#![cfg(feature = "alloc")]

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::der::{read_elem, read_single, tlv};

// Canonical DER OID value bytes (without 0x06 tag/length).
pub const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]; // 1.2.840.10045.2.1
pub const OID_RSA_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]; // 1.2.840.113549.1.1.1
pub const OID_EC_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02]; // 1.2.840.10045.4.3.2
pub const OID_EC_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03]; // 1.2.840.10045.4.3.3
pub const OID_RSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b]; // 1.2.840.113549.1.1.11
pub const OID_P256_CURVE: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]; // 1.2.840.10045.3.1.7
pub const OID_P384_CURVE: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22]; // 1.3.132.0.34
pub const OID_ATTESTATION_EXT: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x11]; // 1.3.6.1.4.1.11129.2.1.17
pub const OID_PROVISIONING_INFO: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xd6, 0x79, 0x02, 0x01, 0x1e]; // 1.3.6.1.4.1.11129.2.1.30
pub const OID_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e]; // 2.5.29.14
pub const OID_AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23]; // 2.5.29.35

/// Pre-encoded DER `AlgorithmIdentifier` values for ECDSA-SHA256, ECDSA-SHA384, RSA-SHA256.
pub fn alg_id_ec_sha256() -> Vec<u8> {
    tlv(&[0x30], &tlv(&[0x06], OID_EC_SHA256))
}

pub fn alg_id_ec_sha384() -> Vec<u8> {
    tlv(&[0x30], &tlv(&[0x06], OID_EC_SHA384))
}

pub fn alg_id_rsa_sha256() -> Vec<u8> {
    let mut body = tlv(&[0x06], OID_RSA_SHA256);
    body.extend_from_slice(&[0x05, 0x00]); // ASN.1 NULL parameters
    tlv(&[0x30], &body)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct X509Extension {
    pub oid: Vec<u8>,
    pub critical: bool,
    pub value: Vec<u8>,
}

impl X509Extension {
    pub fn to_der(&self) -> Vec<u8> {
        let mut body = tlv(&[0x06], &self.oid);
        if self.critical {
            body.extend_from_slice(&[0x01, 0x01, 0xff]);
        }
        body.extend_from_slice(&tlv(&[0x04], &self.value));
        tlv(&[0x30], &body)
    }
}

#[derive(Clone, Debug)]
pub struct TbsCert {
    pub version_tlv: Option<Vec<u8>>,
    pub serial_tlv: Vec<u8>,
    pub serial_bytes: Vec<u8>,
    pub sig_alg_tlv: Vec<u8>,
    pub issuer_tlv: Vec<u8>,
    pub validity_tlv: Vec<u8>,
    pub not_after_ms: u64,
    pub subject_tlv: Vec<u8>,
    pub spki_tlv: Vec<u8>,
    pub issuer_uid_tlv: Option<Vec<u8>>,
    pub subject_uid_tlv: Option<Vec<u8>>,
    pub extensions: Option<Vec<X509Extension>>,
}

#[derive(Clone, Debug)]
pub struct X509Cert {
    pub tbs: TbsCert,
    pub sig_alg_tlv: Vec<u8>,
    pub signature_bytes: Vec<u8>,
}

impl X509Cert {
    pub fn from_der(der: &[u8]) -> Result<Self, &'static str> {
        let outer = read_single(der)?;
        if outer.tag != [0x30] {
            return Err("X.509 Certificate must be SEQUENCE");
        }
        let mut rest = outer.value;
        let tbs_elem = read_elem(rest)?;
        let tbs_raw = &rest[..tbs_elem.total];
        rest = &rest[tbs_elem.total..];

        let sig_alg_elem = read_elem(rest)?;
        if sig_alg_elem.tag != [0x30] {
            return Err("X.509 signatureAlgorithm must be SEQUENCE");
        }
        let sig_alg_tlv = rest[..sig_alg_elem.total].to_vec();
        rest = &rest[sig_alg_elem.total..];

        let sig_elem = read_elem(rest)?;
        if sig_elem.tag != [0x03] || sig_elem.value.is_empty() || sig_elem.value[0] != 0 {
            return Err("X.509 signatureValue must be byte-aligned BIT STRING");
        }
        let signature_bytes = sig_elem.value[1..].to_vec();
        rest = &rest[sig_elem.total..];
        if !rest.is_empty() {
            return Err("trailing bytes in X.509 Certificate");
        }

        let tbs = parse_tbs(tbs_raw)?;
        Ok(Self { tbs, sig_alg_tlv, signature_bytes })
    }

    pub fn spki_algorithm_and_curve(&self) -> Option<(Vec<u8>, Option<Vec<u8>>)> {
        let spki = read_single(&self.tbs.spki_tlv).ok()?;
        if spki.tag != [0x30] {
            return None;
        }
        let alg_seq = read_elem(spki.value).ok()?;
        if alg_seq.tag != [0x30] {
            return None;
        }
        let oid_elem = read_elem(alg_seq.value).ok()?;
        if oid_elem.tag != [0x06] {
            return None;
        }
        let rem = &alg_seq.value[oid_elem.total..];
        let param_oid = if !rem.is_empty() {
            let p = read_elem(rem).ok()?;
            if p.tag == [0x06] { Some(p.value.to_vec()) } else { None }
        } else {
            None
        };
        Some((oid_elem.value.to_vec(), param_oid))
    }

    pub fn is_ec_spki(&self) -> bool {
        self.spki_algorithm_and_curve().is_some_and(|(alg, _)| alg == OID_EC_PUBLIC_KEY)
    }

    pub fn is_rsa_spki(&self) -> bool {
        self.spki_algorithm_and_curve().is_some_and(|(alg, _)| alg == OID_RSA_PUBLIC_KEY)
    }

    pub fn find_extension(&self, oid: &[u8]) -> Option<&X509Extension> {
        self.tbs.extensions.as_ref()?.iter().find(|e| e.oid.as_slice() == oid)
    }

    pub fn count_extensions(&self, oid: &[u8]) -> usize {
        self.tbs
            .extensions
            .as_ref()
            .map_or(0, |exts| exts.iter().filter(|e| e.oid.as_slice() == oid).count())
    }

    pub fn strip_extensions(&mut self, oids: &[&[u8]]) {
        if let Some(exts) = self.tbs.extensions.as_mut() {
            exts.retain(|e| !oids.iter().any(|o| e.oid.as_slice() == *o));
            if exts.is_empty() {
                self.tbs.extensions = None;
            }
        }
    }

    pub fn format_issuer_dn(&self) -> String {
        format_name_dn(&self.tbs.issuer_tlv)
    }

    pub fn encode_signed(tbs_der: &[u8], sig_alg_tlv: &[u8], signature_bytes: &[u8]) -> Vec<u8> {
        let mut bit_str = Vec::with_capacity(1 + signature_bytes.len());
        bit_str.push(0x00); // 0 unused bits
        bit_str.extend_from_slice(signature_bytes);
        let sig_tlv = tlv(&[0x03], &bit_str);

        let mut body = Vec::with_capacity(tbs_der.len() + sig_alg_tlv.len() + sig_tlv.len());
        body.extend_from_slice(tbs_der);
        body.extend_from_slice(sig_alg_tlv);
        body.extend_from_slice(&sig_tlv);
        tlv(&[0x30], &body)
    }
}

impl TbsCert {
    pub fn to_der(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(512);
        if let Some(ref v) = self.version_tlv {
            body.extend_from_slice(v);
        }
        body.extend_from_slice(&self.serial_tlv);
        body.extend_from_slice(&self.sig_alg_tlv);
        body.extend_from_slice(&self.issuer_tlv);
        body.extend_from_slice(&self.validity_tlv);
        body.extend_from_slice(&self.subject_tlv);
        body.extend_from_slice(&self.spki_tlv);
        if let Some(ref u) = self.issuer_uid_tlv {
            body.extend_from_slice(u);
        }
        if let Some(ref u) = self.subject_uid_tlv {
            body.extend_from_slice(u);
        }
        if let Some(ref exts) = self.extensions {
            let mut seq_body = Vec::new();
            for ext in exts {
                seq_body.extend_from_slice(&ext.to_der());
            }
            let seq = tlv(&[0x30], &seq_body);
            body.extend_from_slice(&tlv(&[0xa3], &seq));
        }
        tlv(&[0x30], &body)
    }
}

fn parse_tbs(raw: &[u8]) -> Result<TbsCert, &'static str> {
    let seq = read_single(raw)?;
    if seq.tag != [0x30] {
        return Err("TBSCertificate must be SEQUENCE");
    }
    let mut rest = seq.value;

    let mut elem = read_elem(rest)?;
    let version_tlv = if elem.tag == [0xa0] {
        let v = rest[..elem.total].to_vec();
        rest = &rest[elem.total..];
        elem = read_elem(rest)?;
        Some(v)
    } else {
        None
    };

    if elem.tag != [0x02] {
        return Err("TBSCertificate serialNumber must be INTEGER");
    }
    let serial_tlv = rest[..elem.total].to_vec();
    let serial_bytes = elem.value.to_vec();
    rest = &rest[elem.total..];

    let sig_elem = read_elem(rest)?;
    if sig_elem.tag != [0x30] {
        return Err("TBSCertificate signature must be SEQUENCE");
    }
    let sig_alg_tlv = rest[..sig_elem.total].to_vec();
    rest = &rest[sig_elem.total..];

    let issuer_elem = read_elem(rest)?;
    if issuer_elem.tag != [0x30] {
        return Err("TBSCertificate issuer must be SEQUENCE");
    }
    let issuer_tlv = rest[..issuer_elem.total].to_vec();
    rest = &rest[issuer_elem.total..];

    let validity_elem = read_elem(rest)?;
    if validity_elem.tag != [0x30] {
        return Err("TBSCertificate validity must be SEQUENCE");
    }
    let validity_tlv = rest[..validity_elem.total].to_vec();
    let not_after_ms = parse_validity_not_after_ms(validity_elem.value)?;
    rest = &rest[validity_elem.total..];

    let subject_elem = read_elem(rest)?;
    if subject_elem.tag != [0x30] {
        return Err("TBSCertificate subject must be SEQUENCE");
    }
    let subject_tlv = rest[..subject_elem.total].to_vec();
    rest = &rest[subject_elem.total..];

    let spki_elem = read_elem(rest)?;
    if spki_elem.tag != [0x30] {
        return Err("TBSCertificate subjectPublicKeyInfo must be SEQUENCE");
    }
    let spki_tlv = rest[..spki_elem.total].to_vec();
    rest = &rest[spki_elem.total..];

    let mut issuer_uid_tlv = None;
    let mut subject_uid_tlv = None;
    let mut extensions = None;

    while !rest.is_empty() {
        let opt = read_elem(rest)?;
        match opt.tag {
            [0x81] => issuer_uid_tlv = Some(rest[..opt.total].to_vec()),
            [0x82] => subject_uid_tlv = Some(rest[..opt.total].to_vec()),
            [0xa3] => extensions = Some(parse_extensions(opt.value)?),
            _ => return Err("unexpected trailing field in TBSCertificate"),
        }
        rest = &rest[opt.total..];
    }

    Ok(TbsCert {
        version_tlv,
        serial_tlv,
        serial_bytes,
        sig_alg_tlv,
        issuer_tlv,
        validity_tlv,
        not_after_ms,
        subject_tlv,
        spki_tlv,
        issuer_uid_tlv,
        subject_uid_tlv,
        extensions,
    })
}

fn parse_extensions(explicit_val: &[u8]) -> Result<Vec<X509Extension>, &'static str> {
    let seq = read_single(explicit_val)?;
    if seq.tag != [0x30] {
        return Err("Extensions must be SEQUENCE");
    }
    let mut out = Vec::new();
    let mut rest = seq.value;
    while !rest.is_empty() {
        let ext_elem = read_elem(rest)?;
        if ext_elem.tag != [0x30] {
            return Err("Extension must be SEQUENCE");
        }
        let mut inner = ext_elem.value;
        let oid_elem = read_elem(inner)?;
        if oid_elem.tag != [0x06] {
            return Err("Extension extnID must be OID");
        }
        inner = &inner[oid_elem.total..];

        let mut next = read_elem(inner)?;
        let critical = if next.tag == [0x01] {
            if next.value.len() != 1 {
                return Err("Extension critical BOOLEAN malformed");
            }
            let c = next.value[0] != 0;
            inner = &inner[next.total..];
            next = read_elem(inner)?;
            c
        } else {
            false
        };
        if next.tag != [0x04] || next.total != inner.len() {
            return Err("Extension extnValue must be OCTET STRING");
        }
        out.push(X509Extension {
            oid: oid_elem.value.to_vec(),
            critical,
            value: next.value.to_vec(),
        });
        rest = &rest[ext_elem.total..];
    }
    Ok(out)
}

fn parse_validity_not_after_ms(val: &[u8]) -> Result<u64, &'static str> {
    let not_before = read_elem(val)?;
    let not_after = read_single(&val[not_before.total..])?;
    parse_asn1_time_ms(not_after.tag, not_after.value)
}

fn parse_asn1_time_ms(tag: &[u8], bytes: &[u8]) -> Result<u64, &'static str> {
    let s = core::str::from_utf8(bytes).map_err(|_| "non-UTF8 ASN.1 time")?;
    let (year, rest) = match tag {
        [0x17] => {
            // UTCTime: YYMMDDHHMMSSZ
            if s.len() != 13 || !s.ends_with('Z') {
                return Err("invalid UTCTime");
            }
            let yy: i64 = s[0..2].parse().map_err(|_| "bad UTCTime year")?;
            let year = if yy >= 50 { 1900 + yy } else { 2000 + yy };
            (year, &s[2..12])
        }
        [0x18] => {
            // GeneralizedTime: YYYYMMDDHHMMSS[.frac]Z
            if !s.ends_with('Z') || s.len() < 15 {
                return Err("invalid GeneralizedTime");
            }
            let body = &s[..s.len() - 1];
            let main = if let Some((head, frac)) = body.split_once('.') {
                if frac.is_empty() || !frac.bytes().all(|b| b.is_ascii_digit()) {
                    return Err("invalid GeneralizedTime fraction");
                }
                head
            } else {
                body
            };
            if main.len() != 14 {
                return Err("invalid GeneralizedTime");
            }
            let year: i64 = main[0..4].parse().map_err(|_| "bad GeneralizedTime year")?;
            (year, &main[4..14])
        }
        _ => return Err("unsupported ASN.1 time tag"),
    };
    let month: u32 = rest[0..2].parse().map_err(|_| "bad month")?;
    let day: u32 = rest[2..4].parse().map_err(|_| "bad day")?;
    let hour: u64 = rest[4..6].parse().map_err(|_| "bad hour")?;
    let min: u64 = rest[6..8].parse().map_err(|_| "bad minute")?;
    let sec: u64 = rest[8..10].parse().map_err(|_| "bad second")?;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || min > 59 || sec > 60 {
        return Err("time component out of range");
    }
    let days = days_from_civil(year, month, day);
    if days < 0 {
        return Ok(0);
    }
    let secs = (days as u64) * 86_400 + hour * 3600 + min * 60 + sec;
    Ok(secs.saturating_mul(1000))
}

/// Howard Hinnant's civil-from-epoch day count (1970-01-01 = day 0).
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = y - i64::from(m <= 2);
    let era = y.div_euclid(400);
    let yoe = (y - era * 400) as u64;
    let m = u64::from(m);
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + u64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + (doe as i64) - 719_468
}

/// Formats an X.500 `Name` SEQUENCE into an RFC 2253 string (e.g. `CN=Test CA,O=Google`).
pub fn format_name_dn(name_tlv: &[u8]) -> String {
    let Ok(seq) = read_single(name_tlv) else {
        return String::new();
    };
    let mut parts: Vec<String> = Vec::new();
    let mut rest = seq.value;
    while !rest.is_empty() {
        let Ok(rdn) = read_elem(rest) else {
            break;
        };
        rest = &rest[rdn.total..];
        let mut rdn_rest = rdn.value;
        let mut rdn_str = String::new();
        while !rdn_rest.is_empty() {
            let Ok(ava) = read_elem(rdn_rest) else {
                break;
            };
            rdn_rest = &rdn_rest[ava.total..];
            let Ok(oid) = read_elem(ava.value) else {
                continue;
            };
            let Ok(val) = read_elem(&ava.value[oid.total..]) else {
                continue;
            };
            let attr = match oid.value {
                [0x55, 0x04, 0x03] => "CN",
                [0x55, 0x04, 0x05] => "SERIALNUMBER",
                [0x55, 0x04, 0x06] => "C",
                [0x55, 0x04, 0x07] => "L",
                [0x55, 0x04, 0x08] => "ST",
                [0x55, 0x04, 0x0a] => "O",
                [0x55, 0x04, 0x0b] => "OU",
                [0x55, 0x04, 0x0c] => "T",
                _ => "OID",
            };
            let text = core::str::from_utf8(val.value).unwrap_or("");
            if !rdn_str.is_empty() {
                rdn_str.push('+');
            }
            rdn_str.push_str(&format!("{attr}={text}"));
        }
        if !rdn_str.is_empty() {
            parts.push(rdn_str);
        }
    }
    // RFC 2253 orders RDNs in reverse relative to DER sequence.
    parts.reverse();
    parts.join(",")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::base64;
    use alloc::vec;

    fn encode_oid_arcs(arcs: &[u32]) -> Vec<u8> {
        let mut out = vec![(arcs[0] * 40 + arcs[1]) as u8];
        for &arc in &arcs[2..] {
            let mut v = arc;
            let mut tmp = vec![(v & 0x7f) as u8];
            v >>= 7;
            while v > 0 {
                tmp.push(((v & 0x7f) as u8) | 0x80);
                v >>= 7;
            }
            tmp.reverse();
            out.extend_from_slice(&tmp);
        }
        out
    }

    #[test]
    fn oid_constants_match_rfc_arcs() {
        assert_eq!(OID_EC_PUBLIC_KEY, encode_oid_arcs(&[1, 2, 840, 10045, 2, 1]));
        assert_eq!(OID_RSA_PUBLIC_KEY, encode_oid_arcs(&[1, 2, 840, 113549, 1, 1, 1]));
        assert_eq!(OID_EC_SHA256, encode_oid_arcs(&[1, 2, 840, 10045, 4, 3, 2]));
        assert_eq!(OID_EC_SHA384, encode_oid_arcs(&[1, 2, 840, 10045, 4, 3, 3]));
        assert_eq!(OID_RSA_SHA256, encode_oid_arcs(&[1, 2, 840, 113549, 1, 1, 11]));
        assert_eq!(OID_P256_CURVE, encode_oid_arcs(&[1, 2, 840, 10045, 3, 1, 7]));
        assert_eq!(OID_P384_CURVE, encode_oid_arcs(&[1, 3, 132, 0, 34]));
        assert_eq!(OID_ATTESTATION_EXT, encode_oid_arcs(&[1, 3, 6, 1, 4, 1, 11129, 2, 1, 17]));
        assert_eq!(OID_PROVISIONING_INFO, encode_oid_arcs(&[1, 3, 6, 1, 4, 1, 11129, 2, 1, 30]));
        assert_eq!(OID_SUBJECT_KEY_ID, encode_oid_arcs(&[2, 5, 29, 14]));
        assert_eq!(OID_AUTHORITY_KEY_ID, encode_oid_arcs(&[2, 5, 29, 35]));
    }

    #[test]
    fn parses_real_x509_cert_roundtrips_tbs_and_parses_dn_and_time() {
        let pem = concat!(
            "MIIBoDCCASWgAwIBAgIUQu3dUezMEEsZdW6YPjZ5wkTkLKYwCgYIKoZIzj0EAwIw",
            "ITEfMB0GA1UEAwwWVGVzdCBQMzg0IEludGVybWVkaWF0ZTAeFw0yNjExMDUxODQ4",
            "MDhaFw0zNjExMDIxODQ4MDhaMBoxGDAWBgNVBAMMD1Rlc3QgUDI1NiBCYXRjaDBZ",
            "MBMGByqGSM49AgEGCCqGSM49AwEHA0IABEFwD3FpoMWvZFWrscSOy8sT0BkDwiFp",
            "LEqRs1iuEeZbD/6NT0rO8XRF/r6mI3MSMzvEA0Ikrc2TiLKaFTv3DjWjQjBAMB0G",
            "A1UdDgQWBBQfBk/X4kCV3wkVmgAXQg5s8nr0ijAfBgNVHSMEGDAWgBQT9nsYMaEI",
            "wxK9sytBRQSf29Mu7DAKBggqhkjOPQQDAgNpADBmAjEA+qTXB8R9SNjs+GIJ0M+P",
            "H/JIwv2CSeabODDjIVAZKkThPZyYuFX5z5PEejS386p2AjEAyIxZT2oZElVrGtZ8",
            "6w+4+w3miVuwUKgArp2FkcvANBANomLogRp1pJRtNfPmlD7H"
        );
        let der = base64::decode(pem.as_bytes()).unwrap();
        let cert = X509Cert::from_der(&der).unwrap();
        assert!(cert.is_ec_spki());
        assert_eq!(cert.spki_algorithm_and_curve().unwrap().1.as_deref(), Some(OID_P256_CURVE));
        assert_eq!(cert.format_issuer_dn(), "CN=Test P384 Intermediate");
        assert!(cert.tbs.not_after_ms > 2_000_000_000_000); // year 2036
        assert!(cert.find_extension(OID_SUBJECT_KEY_ID).is_some());
        assert!(cert.find_extension(OID_AUTHORITY_KEY_ID).is_some());
        // Byte-exact re-encoding of untouched TBS + Certificate!
        let rebuilt = X509Cert::encode_signed(
            &cert.tbs.to_der(),
            &cert.sig_alg_tlv,
            &cert.signature_bytes,
        );
        assert_eq!(rebuilt, der);
    }

    #[test]
    fn parses_generalized_time_with_and_without_fractional_seconds() {
        let plain = parse_asn1_time_ms(&[0x18], b"20500101000000Z").unwrap();
        let frac = parse_asn1_time_ms(&[0x18], b"20500101000000.123Z").unwrap();
        assert_eq!(plain, frac);
        assert!(plain > 2_500_000_000_000);
        assert!(parse_asn1_time_ms(&[0x18], b"20500101000000.Z").is_err());
        assert!(parse_asn1_time_ms(&[0x18], b"20500101000000.abcZ").is_err());
    }
}
