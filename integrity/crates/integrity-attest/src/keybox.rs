// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! Single canonical Keybox XML/PEM/chain/private-key/RKP-CBOR parser shared by `keystore2`
//! and `YasvaraAttestationService` (`libyasvara_integrity_jni`), eliminating every Java-vs-Rust
//! keybox acceptance drift. Zero external ASN.1/Base64 crate dependencies.

use std::path::Path;
use std::sync::{LazyLock, RwLock};
use std::time::Instant;

use bssl_crypto::digest::Sha256;
use bssl_crypto::ec::{P256, P384};
use bssl_crypto::ecdsa;
use bssl_crypto::rsa::{KeySize as RsaKeySize, PrivateKey as RsaPrivateKey};
use log::{info, warn};

use yasvara_integrity_core::base64;
use yasvara_integrity_core::cbor::parse_provisioning_manufacturer;
use yasvara_integrity_core::contract::{
    ATTEST_DIR, KEYBOX_ERR_BAD_CERTIFICATE, KEYBOX_ERR_CHAIN_TOO_SHORT, KEYBOX_ERR_EMPTY,
    KEYBOX_ERR_INVALID_KEYBOX, KEYBOX_ERR_NONE, KEYBOX_ERR_NOT_XML, KEYBOX_ERR_NO_CERTIFICATE,
    KEYBOX_ERR_NO_PRIVATE_KEY, KEYBOX_ERR_TOO_LARGE, KEYBOX_FILENAME, MAX_KEYBOX_BYTES,
    MAX_PROVISIONING_BYTES,
};
use yasvara_integrity_core::x509::{
    alg_id_ec_sha256, alg_id_ec_sha384, alg_id_rsa_sha256, X509Cert, OID_PROVISIONING_INFO,
};

use crate::cache::FileCache;
use crate::verify_x509_signature;

/// Supported EC batch signing keys (NIST P-256 or P-384).
#[derive(Clone)]
pub enum EcSigningKey {
    P256(ecdsa::PrivateKey<P256>),
    P384(ecdsa::PrivateKey<P384>),
}

impl EcSigningKey {
    pub fn from_der(priv_der: &[u8]) -> Option<Self> {
        if let Some(k) = ecdsa::PrivateKey::<P256>::from_der_ec_private_key(priv_der)
            .or_else(|| ecdsa::PrivateKey::<P256>::from_der_private_key_info(priv_der))
        {
            return Some(Self::P256(k));
        }
        ecdsa::PrivateKey::<P384>::from_der_ec_private_key(priv_der)
            .or_else(|| ecdsa::PrivateKey::<P384>::from_der_private_key_info(priv_der))
            .map(Self::P384)
    }

    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        match self {
            Self::P256(k) => k.to_der_private_key_info().as_ref().to_vec(),
            Self::P384(k) => k.to_der_private_key_info().as_ref().to_vec(),
        }
    }

    pub fn to_spki_der(&self) -> Vec<u8> {
        match self {
            Self::P256(k) => k.to_der_subject_public_key_info().as_ref().to_vec(),
            Self::P384(k) => k.to_der_subject_public_key_info().as_ref().to_vec(),
        }
    }

    pub fn matches_spki(&self, spki: &[u8]) -> bool {
        match self {
            Self::P256(k) => k.to_der_subject_public_key_info().as_ref() == spki,
            Self::P384(k) => k.to_der_subject_public_key_info().as_ref() == spki,
        }
    }

    pub fn sig_alg_tlv(&self) -> Vec<u8> {
        match self {
            Self::P256(_) => alg_id_ec_sha256(),
            Self::P384(_) => alg_id_ec_sha384(),
        }
    }

    pub fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        match self {
            Self::P256(k) => k.sign(tbs),
            Self::P384(k) => k.sign(tbs),
        }
    }
}

/// Unified EC/RSA signing key shared by keybox batch keys and managed `ATTEST_KEY` issuers.
#[derive(Clone)]
pub enum SigningKey {
    Ec(EcSigningKey),
    Rsa(RsaPrivateKey),
}

impl SigningKey {
    pub fn generate_ec_p256() -> Self {
        Self::Ec(EcSigningKey::P256(ecdsa::PrivateKey::<P256>::generate()))
    }

    pub fn generate_ec_p384() -> Self {
        Self::Ec(EcSigningKey::P384(ecdsa::PrivateKey::<P384>::generate()))
    }

    pub fn generate_rsa(bits: i32) -> Option<Self> {
        let size = match bits {
            2048 => RsaKeySize::Rsa2048,
            3072 => RsaKeySize::Rsa3072,
            4096 => RsaKeySize::Rsa4096,
            _ => return None,
        };
        Some(Self::Rsa(RsaPrivateKey::generate(size)))
    }

    pub fn from_pkcs8_der(der: &[u8]) -> Option<Self> {
        EcSigningKey::from_der(der)
            .map(Self::Ec)
            .or_else(|| RsaPrivateKey::from_der_private_key_info(der).map(Self::Rsa))
    }

    pub fn to_pkcs8_der(&self) -> Vec<u8> {
        match self {
            Self::Ec(k) => k.to_pkcs8_der(),
            Self::Rsa(k) => k.to_der_private_key_info().as_ref().to_vec(),
        }
    }

    pub fn to_spki_der(&self) -> Vec<u8> {
        match self {
            Self::Ec(k) => k.to_spki_der(),
            Self::Rsa(k) => k.as_public().to_der_subject_public_key_info().as_ref().to_vec(),
        }
    }

    pub fn sig_alg_tlv(&self) -> Vec<u8> {
        match self {
            Self::Ec(k) => k.sig_alg_tlv(),
            Self::Rsa(_) => alg_id_rsa_sha256(),
        }
    }

    pub fn sign(&self, tbs: &[u8]) -> Vec<u8> {
        match self {
            Self::Ec(k) => k.sign(tbs),
            Self::Rsa(k) => k.sign_pkcs1::<Sha256>(tbs),
        }
    }
}

/// Active keybox batch keys + RKP manufacturer (used by `keystore2`).
#[derive(Clone)]
pub struct KeyboxEntry {
    pub ec: Option<(EcSigningKey, Vec<Vec<u8>>)>,
    pub rsa: Option<(RsaPrivateKey, Vec<Vec<u8>>)>,
    pub rkp_manufacturer: Option<String>,
}

impl KeyboxEntry {
    pub fn signing_key_for(&self, want_ec: bool) -> Option<(SigningKey, &[Vec<u8>])> {
        match (&self.ec, &self.rsa) {
            (Some((k, chain)), Some(_)) if want_ec => Some((SigningKey::Ec(k.clone()), chain)),
            (Some(_), Some((k, chain))) if !want_ec => Some((SigningKey::Rsa(k.clone()), chain)),
            (Some((k, chain)), _) => Some((SigningKey::Ec(k.clone()), chain)),
            (_, Some((k, chain))) => Some((SigningKey::Rsa(k.clone()), chain)),
            (None, None) => None,
        }
    }
}

/// Detailed parse result returned to `YasvaraAttestationService` / Laras via JNI.
pub struct KeyboxInspection {
    pub error: i32,
    pub normalized_xml: String,
    pub public_chain_xml: String,
    pub rkp_manufacturer: String,
    pub stamp: String,
    pub info_json: String,
    pub entry: Option<KeyboxEntry>,
}

struct ParsedBlock {
    algorithm: &'static str,
    certs_der: Vec<Vec<u8>>,
    leaf_cert: X509Cert,
    has_private_key: bool,
    ec_key: Option<EcSigningKey>,
    rsa_key: Option<RsaPrivateKey>,
    rkp_manufacturer: Option<String>,
}

static GLOBAL_KEYBOX: LazyLock<RwLock<FileCache<KeyboxEntry>>> =
    LazyLock::new(|| RwLock::new(FileCache::new()));

/// Returns the currently installed keybox from `/data/misc/yasvara_attest/keybox.xml`.
pub fn current() -> Option<KeyboxEntry> {
    let path = format!("{ATTEST_DIR}/{KEYBOX_FILENAME}");
    let mut store = match GLOBAL_KEYBOX.write() {
        Ok(s) => s,
        Err(e) => {
            warn!("YasvaraKeybox: lock poisoned: {:?}", e);
            return None;
        }
    };
    let lookup = store.current(Path::new(&path), Instant::now(), parse_keybox_xml);
    if let Some(failure) = lookup.diagnostic {
        warn!(
            "YasvaraKeybox: configured keybox {} unavailable: {}; check provisioning/format, \
             init, file/parent permissions and SELinux labels/AVCs; retrying \
             (failure warnings limited to once per minute)",
            path, failure
        );
    }
    if lookup.loaded {
        if let Some(entry) = lookup.entry {
            info!(
                "YasvaraKeybox: loaded (ec_chain={:?}, rsa_chain={:?}, rkp_mfg={:?})",
                entry.ec.as_ref().map(|e| e.1.len()),
                entry.rsa.as_ref().map(|r| r.1.len()),
                entry.rkp_manufacturer,
            );
        }
    }
    lookup.entry.cloned()
}

/// Strict parser for `keystore2` runtime signing (requires at least one valid EC or RSA keypair).
pub fn parse_keybox_xml(raw: &str) -> Option<KeyboxEntry> {
    let insp = inspect_keybox(raw, true);
    if insp.error == KEYBOX_ERR_NONE { insp.entry } else { None }
}

/// Full parser + validator + metadata extractor shared by `YasvaraAttestationService` & Laras.
/// Accepts raw XML or Base64(XML). Uses identical cryptographic validation as `keystore2`.
pub fn inspect_keybox(raw: &str, require_private_key: bool) -> KeyboxInspection {
    let fail = |error: i32| KeyboxInspection {
        error,
        normalized_xml: String::new(),
        public_chain_xml: String::new(),
        rkp_manufacturer: String::new(),
        stamp: String::new(),
        info_json: String::new(),
        entry: None,
    };

    if raw.len() > MAX_KEYBOX_BYTES {
        return fail(KEYBOX_ERR_TOO_LARGE);
    }
    let trimmed = raw.trim().trim_start_matches('\u{feff}').trim();
    if trimmed.is_empty() {
        return fail(KEYBOX_ERR_EMPTY);
    }

    let xml = if trimmed.starts_with('<') {
        trimmed.to_string()
    } else {
        let Some(decoded) = base64::decode(trimmed.as_bytes()) else {
            return fail(KEYBOX_ERR_NOT_XML);
        };
        let Ok(text) = String::from_utf8(decoded) else {
            return fail(KEYBOX_ERR_NOT_XML);
        };
        let t = text.trim().trim_start_matches('\u{feff}').trim().to_string();
        if !t.starts_with('<') || t.len() > MAX_KEYBOX_BYTES {
            return fail(KEYBOX_ERR_NOT_XML);
        }
        t
    };

    if !xml.contains('<') {
        return fail(KEYBOX_ERR_NOT_XML);
    }

    let mut blocks: Vec<ParsedBlock> = Vec::new();
    let mut last_err = KEYBOX_ERR_NO_CERTIFICATE;
    let xml_lower = xml.to_ascii_lowercase();
    if xml_lower.contains("<!doctype") || xml_lower.contains("<!entity") {
        return fail(KEYBOX_ERR_NOT_XML);
    }
    let mut search_idx = 0usize;
    let mut saw_key_tag = false;

    while let Some(rel) = xml_lower[search_idx..].find("<key") {
        let key_start = search_idx + rel;
        let next_ch = xml_lower.as_bytes().get(key_start + 4).copied();
        if !matches!(next_ch, Some(b' ' | b'\t' | b'\r' | b'\n' | b'>')) {
            search_idx = key_start + 4;
            continue;
        }
        let Some(rel_close) = xml[key_start..].find('>') else {
            break;
        };
        let header = &xml_lower[key_start..key_start + rel_close];
        let content_start = key_start + rel_close + 1;
        let Some((end_start, end_after)) = find_closing_tag(&xml_lower, content_start, "</key") else {
            break;
        };
        saw_key_tag = true;
        let block = &xml[content_start..end_start];
        let block_lower = &xml_lower[content_start..end_start];
        search_idx = end_after;

        let algo = if header.contains("algorithm=\"rsa\"") || header.contains("algorithm='rsa'") {
            "rsa"
        } else if header.contains("algorithm=\"ecdsa\"")
            || header.contains("algorithm='ecdsa'")
            || header.contains("algorithm=\"ec\"")
            || header.contains("algorithm='ec'")
        {
            "ecdsa"
        } else {
            continue;
        };

        match parse_key_block(algo, block, block_lower, require_private_key) {
            Ok(parsed) => blocks.push(parsed),
            Err(code) => last_err = code,
        }
    }

    if !saw_key_tag {
        match parse_key_block("ecdsa", &xml, &xml_lower, require_private_key) {
            Ok(parsed) => blocks.push(parsed),
            Err(code) => last_err = code,
        }
    }

    if blocks.is_empty() {
        return fail(last_err);
    }
    if require_private_key && !blocks.iter().any(|b| b.has_private_key) {
        return fail(KEYBOX_ERR_NO_PRIVATE_KEY);
    }

    let mut entry = KeyboxEntry { ec: None, rsa: None, rkp_manufacturer: None };
    let mut ec_mfg: Option<String> = None;
    let mut rsa_mfg: Option<String> = None;

    for b in &blocks {
        if b.algorithm == "ecdsa" {
            if ec_mfg.is_none() {
                ec_mfg = b.rkp_manufacturer.clone();
            }
            if entry.ec.is_none() {
                if let Some(ref k) = b.ec_key {
                    entry.ec = Some((k.clone(), b.certs_der.clone()));
                }
            }
        } else {
            if rsa_mfg.is_none() {
                rsa_mfg = b.rkp_manufacturer.clone();
            }
            if entry.rsa.is_none() {
                if let Some(ref k) = b.rsa_key {
                    entry.rsa = Some((k.clone(), b.certs_der.clone()));
                }
            }
        }
    }
    let rkp_mfg = ec_mfg.or(rsa_mfg);
    entry.rkp_manufacturer = rkp_mfg.clone();

    let public_chain_xml = build_public_chain_xml(&blocks);
    let stamp = compute_keybox_stamp(&blocks);
    let info_json = build_info_json(&blocks, rkp_mfg.as_deref().unwrap_or(""));
    let has_entry = entry.ec.is_some() || entry.rsa.is_some();

    KeyboxInspection {
        error: KEYBOX_ERR_NONE,
        normalized_xml: xml,
        public_chain_xml,
        rkp_manufacturer: rkp_mfg.unwrap_or_default(),
        stamp,
        info_json,
        entry: has_entry.then_some(entry),
    }
}

fn parse_key_block(
    algo: &'static str,
    block: &str,
    block_lower: &str,
    require_private_key: bool,
) -> Result<ParsedBlock, i32> {
    let mut certs_der: Vec<Vec<u8>> = Vec::new();
    let mut saw_cert = false;
    let mut c_search = 0usize;
    while let Some(c_rel) = block_lower[c_search..].find("<certificate") {
        let c_start = c_search + c_rel;
        let next = block_lower.as_bytes().get(c_start + 12).copied();
        if !matches!(next, Some(b' ' | b'\t' | b'\r' | b'\n' | b'>')) {
            c_search = c_start + 12;
            continue;
        }
        let Some(open_end) = block[c_start..].find('>') else {
            return Err(KEYBOX_ERR_BAD_CERTIFICATE);
        };
        let content_start = c_start + open_end + 1;
        let Some((close_start, close_after)) =
            find_closing_tag(block_lower, content_start, "</certificate")
        else {
            return Err(KEYBOX_ERR_BAD_CERTIFICATE);
        };
        saw_cert = true;
        let cert_pem = &block[content_start..close_start];
        let Some(der) = extract_pem_bytes(cert_pem) else {
            return Err(KEYBOX_ERR_BAD_CERTIFICATE);
        };
        certs_der.push(der);
        c_search = close_after;
    }

    if !saw_cert {
        return Err(KEYBOX_ERR_NO_CERTIFICATE);
    }
    if certs_der.len() < 2 {
        return Err(KEYBOX_ERR_CHAIN_TOO_SHORT);
    }

    let parsed_certs = validate_and_parse_chain(&certs_der).ok_or(KEYBOX_ERR_INVALID_KEYBOX)?;
    let leaf = parsed_certs[0].clone();
    let leaf_spki = &leaf.tbs.spki_tlv;
    let leaf_is_ec = leaf.is_ec_spki();
    if (algo == "ecdsa") != leaf_is_ec {
        return Err(KEYBOX_ERR_INVALID_KEYBOX);
    }

    let priv_der = (|| -> Option<Vec<u8>> {
        let p_start = block_lower.find("<privatekey")?;
        let p_open_end = block[p_start..].find('>')? + p_start + 1;
        let (p_close, _) = find_closing_tag(block_lower, p_open_end, "</privatekey")?;
        let body = block[p_open_end..p_close].trim();
        if body.is_empty() {
            return None;
        }
        extract_pem_bytes(body)
    })();

    let mut ec_key = None;
    let mut rsa_key = None;
    let has_private_key = if let Some(p_der) = priv_der {
        if algo == "ecdsa" {
            let k = EcSigningKey::from_der(&p_der).ok_or(KEYBOX_ERR_INVALID_KEYBOX)?;
            if !k.matches_spki(leaf_spki.as_slice()) {
                return Err(KEYBOX_ERR_INVALID_KEYBOX);
            }
            ec_key = Some(k);
        } else {
            let k = RsaPrivateKey::from_der_rsa_private_key(&p_der)
                .or_else(|| RsaPrivateKey::from_der_private_key_info(&p_der))
                .ok_or(KEYBOX_ERR_INVALID_KEYBOX)?;
            if k.as_public().to_der_subject_public_key_info().as_ref() != leaf_spki.as_slice() {
                return Err(KEYBOX_ERR_INVALID_KEYBOX);
            }
            rsa_key = Some(k);
        }
        true
    } else if require_private_key {
        return Err(KEYBOX_ERR_NO_PRIVATE_KEY);
    } else {
        false
    };

    let rkp_manufacturer = extract_rkp_manufacturer(&parsed_certs);
    Ok(ParsedBlock {
        algorithm: algo,
        certs_der,
        leaf_cert: leaf,
        has_private_key,
        ec_key,
        rsa_key,
        rkp_manufacturer,
    })
}

/// Validates every certificate parses cleanly, issuer DN matches next subject DN, every
/// signature verifies under BoringSSL `X509_verify`, and a self-signed root self-verifies.
pub fn validate_and_parse_chain(chain: &[Vec<u8>]) -> Option<Vec<X509Cert>> {
    if chain.len() < 2 {
        return None;
    }
    let mut certs = Vec::with_capacity(chain.len());
    for der in chain {
        certs.push(X509Cert::from_der(der).ok()?);
    }
    for i in 0..certs.len() - 1 {
        let cert = &certs[i];
        let issuer = &certs[i + 1];
        if cert.tbs.issuer_tlv != issuer.tbs.subject_tlv {
            return None;
        }
        if cert.signature_bytes.is_empty() {
            return None;
        }
        if !verify_x509_signature(&chain[i], &chain[i + 1]) {
            return None;
        }
    }
    if let (Some(last_cert), Some(last_der)) = (certs.last(), chain.last()) {
        if last_cert.tbs.issuer_tlv == last_cert.tbs.subject_tlv
            && !verify_x509_signature(last_der, last_der)
        {
            return None;
        }
    }
    Some(certs)
}

fn extract_rkp_manufacturer(certs: &[X509Cert]) -> Option<String> {
    for cert in certs {
        let Some(ext) = cert.find_extension(OID_PROVISIONING_INFO) else {
            continue;
        };
        if ext.value.len() > MAX_PROVISIONING_BYTES {
            continue;
        }
        if let Some(mfg) = parse_provisioning_manufacturer(&ext.value) {
            return Some(mfg.to_string());
        }
    }
    None
}

fn build_public_chain_xml(blocks: &[ParsedBlock]) -> String {
    let mut out = String::from("<AndroidAttestation>");
    for b in blocks {
        out.push_str("<Key algorithm=\"");
        out.push_str(b.algorithm);
        out.push_str("\"><CertificateChain>");
        for der in &b.certs_der {
            out.push_str("<Certificate format=\"pem\">-----BEGIN CERTIFICATE-----\n");
            out.push_str(&base64::encode(der));
            out.push_str("\n-----END CERTIFICATE-----</Certificate>");
        }
        out.push_str("</CertificateChain></Key>");
    }
    out.push_str("</AndroidAttestation>");
    out
}

fn compute_keybox_stamp(blocks: &[ParsedBlock]) -> String {
    let mut data = Vec::new();
    for b in blocks {
        data.extend_from_slice(b.algorithm.as_bytes());
        for der in &b.certs_der {
            data.extend_from_slice(der);
        }
    }
    let digest = Sha256::hash(&data);
    format!("{}:{}", base64::encode(&digest), blocks.len())
}

fn build_info_json(blocks: &[ParsedBlock], rkp_mfg: &str) -> String {
    let first = &blocks[0];
    let serial_hex = format_serial_hex(&first.leaf_cert.tbs.serial_bytes);
    let issuer = first.leaf_cert.format_issuer_dn();
    let not_after_ms = first.leaf_cert.tbs.not_after_ms;

    let mut algos = String::from("[");
    for (i, b) in blocks.iter().enumerate() {
        if i > 0 {
            algos.push(',');
        }
        algos.push('"');
        algos.push_str(b.algorithm);
        algos.push('"');
    }
    algos.push(']');

    format!(
        "{{\"algorithm\":\"{}\",\"serialHex\":\"{}\",\"issuer\":\"{}\",\"notAfter\":{},\"chainLength\":{},\"hasPrivateKey\":{},\"algorithms\":{},\"keyCount\":{},\"rkpManufacturer\":\"{}\"}}",
        json_escape(first.algorithm),
        json_escape(&serial_hex),
        json_escape(&issuer),
        not_after_ms,
        first.certs_der.len(),
        first.has_private_key,
        algos,
        blocks.len(),
        json_escape(rkp_mfg),
    )
}

fn format_serial_hex(bytes: &[u8]) -> String {
    let trimmed = bytes.iter().skip_while(|&&b| b == 0).copied().collect::<Vec<u8>>();
    if trimmed.is_empty() {
        return "0".to_string();
    }
    let mut s = String::with_capacity(trimmed.len() * 2);
    for (i, b) in trimmed.iter().enumerate() {
        if i == 0 {
            s.push_str(&format!("{:x}", b));
        } else {
            s.push_str(&format!("{:02x}", b));
        }
    }
    s
}

pub fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn extract_pem_bytes(pem: &str) -> Option<Vec<u8>> {
    let mut b64 = String::with_capacity(pem.len());
    let mut in_body = false;
    for line in pem.lines() {
        let t = line.trim();
        if t.starts_with("-----BEGIN") {
            in_body = true;
            continue;
        }
        if t.starts_with("-----END") {
            break;
        }
        if in_body {
            b64.push_str(t);
        }
    }
    if b64.is_empty() {
        b64 = pem.to_string();
    }
    base64::decode(b64.as_bytes())
}

/// Finds a closing XML tag (e.g. `</key` followed by optional ASCII whitespace and `>`).
/// Returns `(tag_start, index_after_gt)`.
fn find_closing_tag(lower: &str, from: usize, prefix: &str) -> Option<(usize, usize)> {
    let bytes = lower.as_bytes();
    let mut pos = from;
    while let Some(rel) = lower[pos..].find(prefix) {
        let start = pos + rel;
        let mut idx = start + prefix.len();
        while idx < bytes.len() && matches!(bytes[idx], b' ' | b'\t' | b'\r' | b'\n') {
            idx += 1;
        }
        if bytes.get(idx) == Some(&b'>') {
            return Some((start, idx + 1));
        }
        pos = start + prefix.len();
    }
    None
}
