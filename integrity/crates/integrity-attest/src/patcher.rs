// SPDX-FileCopyrightText: The Yasvara Project
// SPDX-License-Identifier: Apache-2.0

//! X.509 attestation leaf re-signer, `PURPOSE_ATTEST_KEY` software issuer generator, and
//! hardware boot-hash extractor. Zero external ASN.1 crate dependencies.

use log::{error, info, warn};

use yasvara_integrity_core::der::{
    parse_hardware_attestation, patch_key_description, read_single, DeviceIdOverrides, PatchConfig,
};
use yasvara_integrity_core::digest::is_all_zero;
use yasvara_integrity_core::x509::{
    X509Cert, OID_ATTESTATION_EXT, OID_AUTHORITY_KEY_ID, OID_EC_PUBLIC_KEY, OID_P256_CURVE,
    OID_P384_CURVE, OID_RSA_PUBLIC_KEY, OID_SUBJECT_KEY_ID,
};

use crate::keybox::{validate_and_parse_chain, KeyboxEntry, SigningKey};

pub use yasvara_integrity_core::x509::{
    OID_ATTESTATION_EXT as ATTESTATION_EXT_OID, OID_AUTHORITY_KEY_ID as AUTHORITY_KEY_ID_OID,
    OID_SUBJECT_KEY_ID as SUBJECT_KEY_ID_OID,
};

/// Validates a hardware-attested probe chain (signatures + challenge + hardware security levels +
/// non-zero 32/64-byte boot hash) and extracts `verifiedBootHash`.
/// Deliberately does NOT enforce `notBefore`/`notAfter` so early-boot pre-NTP RTC skew or
/// expired factory roots cannot block canonical boot-digest publication.
pub fn extract_hardware_boot_hash(chain_der: &[Vec<u8>], expected_challenge: &[u8]) -> Option<Vec<u8>> {
    let certs = validate_and_parse_chain(chain_der)?;
    let leaf = certs.first()?;
    if leaf.count_extensions(OID_ATTESTATION_EXT) != 1 {
        return None;
    }
    let ext = leaf.find_extension(OID_ATTESTATION_EXT)?;
    let info = parse_hardware_attestation(&ext.value).ok()?;
    if info.challenge != expected_challenge {
        return None;
    }
    if !matches!(info.attestation_security_level, 1 | 2)
        || !matches!(info.keymaster_security_level, 1 | 2)
    {
        return None;
    }
    if !matches!(info.verified_boot_hash.len(), 32 | 64) || is_all_zero(info.verified_boot_hash) {
        return None;
    }
    Some(info.verified_boot_hash.to_vec())
}

fn replace_spki(cert: &mut X509Cert, spki_der: &[u8]) -> Option<()> {
    let elem = read_single(spki_der).ok()?;
    if elem.tag != [0x30] {
        warn!("YasvaraPatcher: replacement SPKI is not a DER SEQUENCE");
        return None;
    }
    cert.tbs.spki_tlv = spki_der.to_vec();
    cert.strip_extensions(&[OID_SUBJECT_KEY_ID, OID_AUTHORITY_KEY_ID]);
    Some(())
}

fn apply_key_description_patch(cert: &mut X509Cert, config: &PatchConfig) -> Option<()> {
    if cert.count_extensions(OID_ATTESTATION_EXT) != 1 {
        warn!("YasvaraPatcher: missing/duplicate KeyDescription extension; preserving hardware chain");
        return None;
    }
    let exts = cert.tbs.extensions.as_mut()?;
    let ext = exts.iter_mut().find(|e| e.oid.as_slice() == OID_ATTESTATION_EXT)?;
    let patched_key_desc = match patch_key_description(&ext.value, config) {
        Ok(d) => d,
        Err(e) => {
            warn!("YasvaraPatcher: refusing to re-sign: {}; preserving hardware chain", e);
            return None;
        }
    };
    info!(
        "YasvaraPatcher: real leaf attestationVersion={} attestSecLevel={} keymasterSecLevel={}",
        patched_key_desc.attestation_version,
        patched_key_desc.attestation_security_level,
        patched_key_desc.keymaster_security_level
    );
    ext.value = patched_key_desc.der;
    cert.strip_extensions(&[OID_AUTHORITY_KEY_ID]);
    Some(())
}

fn sign_tbs_and_encode(cert: &mut X509Cert, signer: &SigningKey) -> Vec<u8> {
    let sig_alg_tlv = signer.sig_alg_tlv();
    cert.tbs.sig_alg_tlv = sig_alg_tlv.clone();
    let tbs_der = cert.tbs.to_der();
    let sig_bytes = signer.sign(&tbs_der);
    X509Cert::encode_signed(&tbs_der, &sig_alg_tlv, &sig_bytes)
}

pub fn generate_matching_signing_key(
    leaf_der: &[u8],
    rsa_bits_hint: Option<i32>,
    ec_is_p384_hint: Option<bool>,
) -> Option<SigningKey> {
    let cert = X509Cert::from_der(leaf_der).ok()?;
    let (alg_oid, curve_oid) = cert.spki_algorithm_and_curve()?;
    if alg_oid.as_slice() == OID_EC_PUBLIC_KEY {
        match curve_oid.as_deref() {
            Some(c) if c == OID_P256_CURVE => Some(SigningKey::generate_ec_p256()),
            Some(c) if c == OID_P384_CURVE => Some(SigningKey::generate_ec_p384()),
            None => match ec_is_p384_hint {
                Some(false) => Some(SigningKey::generate_ec_p256()),
                Some(true) => Some(SigningKey::generate_ec_p384()),
                None => None,
            },
            Some(_) => None,
        }
    } else if alg_oid.as_slice() == OID_RSA_PUBLIC_KEY {
        SigningKey::generate_rsa(rsa_bits_hint?)
    } else {
        None
    }
}

pub fn patch_leaf_and_chain_with_spki(
    leaf_der: &[u8],
    keybox: &KeyboxEntry,
    config: &PatchConfig,
    replacement_spki: Option<&[u8]>,
) -> Option<Vec<Vec<u8>>> {
    let mut cert = X509Cert::from_der(leaf_der).ok()?;
    if let Some(spki_der) = replacement_spki {
        replace_spki(&mut cert, spki_der)?;
    }
    apply_key_description_patch(&mut cert, config)?;

    let want_ec = cert.is_ec_spki();
    let Some((signer, chain)) = keybox.signing_key_for(want_ec) else {
        error!("YasvaraPatcher: no private key in keybox");
        return None;
    };
    let batch_cert = X509Cert::from_der(chain.first()?).ok()?;
    cert.tbs.issuer_tlv = batch_cert.tbs.subject_tlv;
    let new_leaf_der = sign_tbs_and_encode(&mut cert, &signer);

    let mut new_chain = Vec::with_capacity(1 + chain.len());
    new_chain.push(new_leaf_der);
    new_chain.extend(chain.iter().cloned());
    info!(
        "YasvaraPatcher: successfully re-signed attestation leaf, total chain={}",
        new_chain.len()
    );
    Some(new_chain)
}

pub fn resign_self_signed_leaf_with_spki(leaf_der: &[u8], signer: &SigningKey) -> Option<Vec<u8>> {
    let mut cert = X509Cert::from_der(leaf_der).ok()?;
    let spki_der = signer.to_spki_der();
    replace_spki(&mut cert, &spki_der)?;
    cert.tbs.issuer_tlv = cert.tbs.subject_tlv.clone();
    let out = sign_tbs_and_encode(&mut cert, signer);
    info!("YasvaraPatcher: provisioned software-backed self-signed ATTEST_KEY leaf");
    Some(out)
}

pub fn patch_user_attested_leaf(
    leaf_der: &[u8],
    attest_cert_der: &[u8],
    issuer_signer: &SigningKey,
    config: &PatchConfig,
    replacement_spki: Option<&[u8]>,
) -> Option<Vec<u8>> {
    let mut cert = X509Cert::from_der(leaf_der).ok()?;
    let attest_cert = X509Cert::from_der(attest_cert_der).ok()?;
    if attest_cert.tbs.spki_tlv != issuer_signer.to_spki_der() {
        warn!("YasvaraPatcher: attest key cert SPKI differs from stored signing key");
        return None;
    }
    if let Some(spki_der) = replacement_spki {
        replace_spki(&mut cert, spki_der)?;
    }
    apply_key_description_patch(&mut cert, config)?;
    cert.tbs.issuer_tlv = attest_cert.tbs.subject_tlv;
    let new_leaf_der = sign_tbs_and_encode(&mut cert, issuer_signer);
    info!("YasvaraPatcher: successfully re-signed ATTEST_KEY child leaf");
    Some(new_leaf_der)
}

pub fn make_device_id_overrides(
    brand: String,
    device: String,
    product: String,
    manufacturer: String,
    model: String,
) -> DeviceIdOverrides {
    DeviceIdOverrides { brand, device, product, manufacturer, model }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keybox::{inspect_keybox, parse_keybox_xml, SigningKey};
    use crate::verify_x509_signature;
    use yasvara_integrity_core::base64;
    use yasvara_integrity_core::contract::{
        KEYBOX_ERR_INVALID_KEYBOX, KEYBOX_ERR_NONE, KEYBOX_ERR_NOT_XML, KEYBOX_ERR_NO_PRIVATE_KEY,
        TAG_ATTESTATION_ID_BRAND, TAG_ATTESTATION_ID_MODEL, TAG_ATTESTATION_ID_SERIAL,
        TAG_BOOT_PATCHLEVEL, TAG_OS_PATCHLEVEL, TAG_OS_VERSION, TAG_ROOT_OF_TRUST,
        TAG_VENDOR_PATCHLEVEL,
    };
    use yasvara_integrity_core::der::{context_tag, der_uint, tlv};
    use yasvara_integrity_core::x509::{TbsCert, X509Extension};

    fn cn_name(cn: &str) -> Vec<u8> {
        let mut ava = tlv(&[0x06], &[0x55, 0x04, 0x03]); // CN
        ava.extend_from_slice(&tlv(&[0x0c], cn.as_bytes())); // UTF8String
        tlv(&[0x30], &tlv(&[0x31], &tlv(&[0x30], &ava)))
    }

    fn validity_tlv() -> Vec<u8> {
        let mut body = tlv(&[0x17], b"260101000000Z");
        body.extend_from_slice(&tlv(&[0x17], b"360101000000Z"));
        tlv(&[0x30], &body)
    }

    fn sign_test_cert(
        serial: u32,
        issuer_dn: &[u8],
        subject_dn: &[u8],
        spki_der: &[u8],
        extensions: Option<Vec<X509Extension>>,
        signer: &SigningKey,
    ) -> Vec<u8> {
        let sig_alg_tlv = signer.sig_alg_tlv();
        let serial_bytes = der_uint(serial);
        let tbs = TbsCert {
            version_tlv: Some(vec![0xa0, 0x03, 0x02, 0x01, 0x02]), // v3
            serial_tlv: tlv(&[0x02], &serial_bytes),
            serial_bytes,
            sig_alg_tlv: sig_alg_tlv.clone(),
            issuer_tlv: issuer_dn.to_vec(),
            validity_tlv: validity_tlv(),
            not_after_ms: 0,
            subject_tlv: subject_dn.to_vec(),
            spki_tlv: spki_der.to_vec(),
            issuer_uid_tlv: None,
            subject_uid_tlv: None,
            extensions,
        };
        let tbs_der = tbs.to_der();
        let sig = signer.sign(&tbs_der);
        X509Cert::encode_signed(&tbs_der, &sig_alg_tlv, &sig)
    }

    fn build_key_description(
        challenge: &[u8],
        boot_hash: &[u8],
        attest_sec_level: u8,
        km_sec_level: u8,
    ) -> Vec<u8> {
        let rot = {
            let mut body = Vec::new();
            body.extend_from_slice(&tlv(&[0x04], &[0u8; 32])); // unlocked all-zero boot key
            body.extend_from_slice(&[0x01, 0x01, 0x00]); // deviceLocked = FALSE
            body.extend_from_slice(&[0x0a, 0x01, 0x02]); // verifiedBootState = Unverified(2)
            body.extend_from_slice(&tlv(&[0x04], boot_hash));
            tlv(&context_tag(TAG_ROOT_OF_TRUST), &tlv(&[0x30], &body))
        };
        let mut hw = Vec::new();
        hw.extend_from_slice(&rot);
        hw.extend_from_slice(&tlv(&context_tag(TAG_OS_VERSION), &tlv(&[0x02], &der_uint(150_000))));
        hw.extend_from_slice(&tlv(
            &context_tag(TAG_OS_PATCHLEVEL),
            &tlv(&[0x02], &der_uint(202501)),
        ));
        hw.extend_from_slice(&tlv(&context_tag(TAG_ATTESTATION_ID_BRAND), &tlv(&[0x04], b"POCO")));
        hw.extend_from_slice(&tlv(
            &context_tag(TAG_ATTESTATION_ID_SERIAL),
            &tlv(&[0x04], b"REAL-SERIAL-123"),
        ));
        hw.extend_from_slice(&tlv(
            &context_tag(TAG_ATTESTATION_ID_MODEL),
            &tlv(&[0x04], b"25053PC47G"),
        ));

        let mut body = Vec::new();
        body.extend_from_slice(&tlv(&[0x02], &der_uint(300))); // attestationVersion
        body.extend_from_slice(&[0x0a, 0x01, attest_sec_level]);
        body.extend_from_slice(&tlv(&[0x02], &der_uint(300))); // keymasterVersion
        body.extend_from_slice(&[0x0a, 0x01, km_sec_level]);
        body.extend_from_slice(&tlv(&[0x04], challenge));
        body.extend_from_slice(&tlv(&[0x04], b"")); // uniqueId
        body.extend_from_slice(&tlv(&[0x30], &[])); // swEnforced
        body.extend_from_slice(&tlv(&[0x30], &hw)); // hwEnforced
        tlv(&[0x30], &body)
    }

    fn pem(label: &str, der: &[u8]) -> String {
        format!("-----BEGIN {label}-----\n{}\n-----END {label}-----", base64::encode(der))
    }

    fn make_ec_keybox_xml(algo_attr: &str, close_space: bool) -> (String, SigningKey, Vec<Vec<u8>>) {
        let root_key = SigningKey::generate_ec_p384();
        let batch_key = SigningKey::generate_ec_p256();
        let root_dn = cn_name("Test Attestation Root");
        let batch_dn = cn_name("Test P256 Batch");
        let root_der = sign_test_cert(1, &root_dn, &root_dn, &root_key.to_spki_der(), None, &root_key);
        let batch_der =
            sign_test_cert(2, &root_dn, &batch_dn, &batch_key.to_spki_der(), None, &root_key);
        let sp = if close_space { " " } else { "" };
        let xml = format!(
            "<AndroidAttestation><Keybox DeviceID=\"test\"><Key algorithm=\"{algo_attr}\">\
             <PrivateKey format=\"pem\">{}</PrivateKey{sp}>\
             <CertificateChain><NumberOfCertificates>2</NumberOfCertificates>\
             <Certificate format=\"pem\">{}</Certificate{sp}>\
             <Certificate format=\"pem\">{}</Certificate{sp}>\
             </CertificateChain></Key{sp}></Keybox></AndroidAttestation>",
            pem("PRIVATE KEY", &batch_key.to_pkcs8_der()),
            pem("CERTIFICATE", &batch_der),
            pem("CERTIFICATE", &root_der),
        );
        (xml, batch_key, vec![batch_der, root_der])
    }

    fn make_rsa_keybox_xml() -> (String, SigningKey, Vec<Vec<u8>>) {
        let root_key = SigningKey::generate_rsa(2048).unwrap();
        let batch_key = SigningKey::generate_rsa(2048).unwrap();
        let root_dn = cn_name("Test RSA Root");
        let batch_dn = cn_name("Test RSA Batch");
        let root_der = sign_test_cert(10, &root_dn, &root_dn, &root_key.to_spki_der(), None, &root_key);
        let batch_der =
            sign_test_cert(11, &root_dn, &batch_dn, &batch_key.to_spki_der(), None, &root_key);
        let xml = format!(
            "<AndroidAttestation><Keybox DeviceID=\"rsa\"><Key algorithm=\"rsa\">\
             <PrivateKey format=\"pem\">{}</PrivateKey>\
             <CertificateChain>\
             <Certificate format=\"pem\">{}</Certificate>\
             <Certificate format=\"pem\">{}</Certificate>\
             </CertificateChain></Key></Keybox></AndroidAttestation>",
            pem("PRIVATE KEY", &batch_key.to_pkcs8_der()),
            pem("CERTIFICATE", &batch_der),
            pem("CERTIFICATE", &root_der),
        );
        (xml, batch_key, vec![batch_der, root_der])
    }

    fn make_hw_leaf(leaf_key: &SigningKey, boot_hash: &[u8], challenge: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let hw_ca_key = SigningKey::generate_ec_p256();
        let hw_ca_dn = cn_name("Real Hardware TEE CA");
        let leaf_dn = cn_name("Android Keystore Key");
        let hw_ca_der =
            sign_test_cert(99, &hw_ca_dn, &hw_ca_dn, &hw_ca_key.to_spki_der(), None, &hw_ca_key);
        let exts = vec![
            X509Extension { oid: OID_SUBJECT_KEY_ID.to_vec(), critical: false, value: vec![0x04, 0x02, 0xaa, 0xbb] },
            X509Extension { oid: OID_AUTHORITY_KEY_ID.to_vec(), critical: false, value: vec![0x30, 0x04, 0x80, 0x02, 0xcc, 0xdd] },
            X509Extension {
                oid: OID_ATTESTATION_EXT.to_vec(),
                critical: false,
                value: build_key_description(challenge, boot_hash, 1, 1),
            },
        ];
        let leaf_der = sign_test_cert(
            100,
            &hw_ca_dn,
            &leaf_dn,
            &leaf_key.to_spki_der(),
            Some(exts),
            &hw_ca_key,
        );
        (leaf_der, hw_ca_der)
    }

    #[test]
    fn keybox_inspect_handles_bom_ec_alias_whitespace_tags_and_rejects_dtd() {
        let (xml, _, _) = make_ec_keybox_xml("ec", true);
        let with_bom = format!("\u{feff}  {xml}");
        let insp = inspect_keybox(&with_bom, true);
        assert_eq!(insp.error, KEYBOX_ERR_NONE);
        assert!(insp.entry.is_some());
        assert!(insp.entry.as_ref().unwrap().ec.is_some());

        // Base64-encoded UTF-8 BOM XML also accepted.
        let b64 = base64::encode(with_bom.as_bytes());
        let insp_b64 = inspect_keybox(&b64, true);
        assert_eq!(insp_b64.error, KEYBOX_ERR_NONE);

        // Public-only XML accepted when require_private_key=false, rejected when true.
        let pub_only = inspect_keybox(&insp.public_chain_xml, false);
        assert_eq!(pub_only.error, KEYBOX_ERR_NONE);
        assert_eq!(inspect_keybox(&insp.public_chain_xml, true).error, KEYBOX_ERR_NO_PRIVATE_KEY);

        // DOCTYPE / ENTITY rejected (parity with Laras KeyboxPayload.kt).
        let dtd = format!("<!DOCTYPE foo>{xml}");
        assert_eq!(inspect_keybox(&dtd, true).error, KEYBOX_ERR_NOT_XML);
        let entity = format!("<!ENTITY x \"y\">{xml}");
        assert_eq!(inspect_keybox(&entity, true).error, KEYBOX_ERR_NOT_XML);

        // Mismatched private key rejected.
        let wrong_key = SigningKey::generate_ec_p256();
        let bad_xml = xml.replace(
            &xml[xml.find("-----BEGIN PRIVATE KEY-----").unwrap()
                ..xml.find("-----END PRIVATE KEY-----").unwrap() + 25],
            &pem("PRIVATE KEY", &wrong_key.to_pkcs8_der()),
        );
        assert_eq!(inspect_keybox(&bad_xml, true).error, KEYBOX_ERR_INVALID_KEYBOX);
    }

    #[test]
    fn patch_leaf_and_chain_verifies_ec_and_rsa_leaves_under_boringssl() {
        let (ec_xml, _, _) = make_ec_keybox_xml("ecdsa", false);
        let ec_kb = parse_keybox_xml(&ec_xml).expect("valid EC keybox");
        let (rsa_xml, _, _) = make_rsa_keybox_xml();
        let rsa_kb = parse_keybox_xml(&rsa_xml).expect("valid RSA keybox");

        let boot_hash = [0x42u8; 32];
        let boot_key = [0x77u8; 32];
        let ids = make_device_id_overrides(
            "google".into(),
            "bluejay".into(),
            "bluejay_beta".into(),
            "Google".into(),
            "Pixel 6a".into(),
        );
        let cfg = PatchConfig {
            canonical_boot_digest: &boot_hash,
            boot_key: Some(&boot_key),
            id_overrides: Some(&ids),
            os_version: Some(170_000),
            os_patchlevel: Some(202610),
            vendor_patchlevel: Some(20261005),
            boot_patchlevel: Some(20261005),
        };

        // 1. EC P-256 leaf signed by EC-only keybox (standard RKP path).
        let ec_leaf_key = SigningKey::generate_ec_p256();
        let (ec_leaf, _) = make_hw_leaf(&ec_leaf_key, &boot_hash, b"challenge-ec");
        let ec_chain = patch_leaf_and_chain_with_spki(&ec_leaf, &ec_kb, &cfg, None).unwrap();
        assert_eq!(ec_chain.len(), 3);
        let parsed = validate_and_parse_chain(&ec_chain).expect("EC chain BoringSSL verify");
        assert!(parsed[0].find_extension(OID_AUTHORITY_KEY_ID).is_none());
        assert!(parsed[0].find_extension(OID_SUBJECT_KEY_ID).is_some());
        let att_ext = parsed[0].find_extension(OID_ATTESTATION_EXT).unwrap();
        let info = parse_hardware_attestation(&att_ext.value).unwrap();
        assert!(info.device_locked);
        assert_eq!(info.verified_boot_state, 0);
        assert_eq!(info.verified_boot_hash, &boot_hash);
        assert_eq!(info.verified_boot_key, &boot_key);
        assert!(att_ext.value.windows(8).any(|w| w == b"Pixel 6a"));
        assert!(!att_ext.value.windows(15).any(|w| w == b"REAL-SERIAL-123"));
        // Verify vendor/boot patchlevel tags (718, 719) were inserted.
        let v_tag = context_tag(TAG_VENDOR_PATCHLEVEL);
        let b_tag = context_tag(TAG_BOOT_PATCHLEVEL);
        assert!(att_ext.value.windows(v_tag.len()).any(|w| w == v_tag.as_slice()));
        assert!(att_ext.value.windows(b_tag.len()).any(|w| w == b_tag.as_slice()));

        // 2. RSA-2048 leaf signed by EC-only P-256 keybox (cross-algorithm RKP fallback).
        let rsa_leaf_key = SigningKey::generate_rsa(2048).unwrap();
        let (rsa_leaf, _) = make_hw_leaf(&rsa_leaf_key, &boot_hash, b"challenge-rsa-ec");
        let rsa_by_ec = patch_leaf_and_chain_with_spki(&rsa_leaf, &ec_kb, &cfg, None).unwrap();
        assert_eq!(rsa_by_ec.len(), 3);
        assert!(validate_and_parse_chain(&rsa_by_ec).is_some());

        // 3. RSA-2048 leaf signed by RSA-2048 keybox.
        let rsa_by_rsa = patch_leaf_and_chain_with_spki(&rsa_leaf, &rsa_kb, &cfg, None).unwrap();
        assert_eq!(rsa_by_rsa.len(), 3);
        assert!(validate_and_parse_chain(&rsa_by_rsa).is_some());
    }

    #[test]
    fn attest_key_resign_and_child_and_boot_hash_extraction_verify_under_boringssl() {
        let boot_hash = [0x99u8; 32];
        let challenge = b"probe-challenge-1234";
        let leaf_key = SigningKey::generate_ec_p256();
        let (hw_leaf, hw_ca) = make_hw_leaf(&leaf_key, &boot_hash, challenge);

        // extract_hardware_boot_hash succeeds on valid hardware chain, rejects bad challenge/sig.
        let extracted =
            extract_hardware_boot_hash(&[hw_leaf.clone(), hw_ca.clone()], challenge).unwrap();
        assert_eq!(extracted, boot_hash);
        assert!(extract_hardware_boot_hash(&[hw_leaf.clone(), hw_ca.clone()], b"wrong").is_none());
        let mut tampered = hw_leaf.clone();
        *tampered.last_mut().unwrap() ^= 0xff;
        assert!(extract_hardware_boot_hash(&[tampered, hw_ca], challenge).is_none());

        // Self-signed software ATTEST_KEY provisioning (EC & RSA).
        let sw_issuer = SigningKey::generate_ec_p256();
        let self_signed = resign_self_signed_leaf_with_spki(&hw_leaf, &sw_issuer).unwrap();
        assert!(verify_x509_signature(&self_signed, &self_signed));

        // Child leaf signed by managed ATTEST_KEY issuer.
        let child_key = SigningKey::generate_ec_p256();
        let (child_hw_leaf, _) = make_hw_leaf(&child_key, &boot_hash, b"child-chal");
        let cfg = PatchConfig {
            canonical_boot_digest: &boot_hash,
            boot_key: None,
            id_overrides: None,
            os_version: Some(170_000),
            os_patchlevel: Some(202610),
            vendor_patchlevel: None,
            boot_patchlevel: None,
        };
        let patched_child =
            patch_user_attested_leaf(&child_hw_leaf, &self_signed, &sw_issuer, &cfg, None).unwrap();
        assert!(verify_x509_signature(&patched_child, &self_signed));
    }
}
