// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use base64::Engine;
use htr_core::crypto::{
    EcdsaKeygenParams, KeygenParams, PrivateKey, PublicKey, RsaKeygenParams, gen_keypair,
};

fn decode_b64(s: &str) -> Vec<u8> {
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

#[test]
fn parse_hardcoded_ed25519_minimal_and_nested() {
    // Minimal v1 (seed directly in privateKey OCTET)
    let ed25519_priv_min = "MCwCAQAwBQYDK2VwBCDIpVDWyqx+A57lZtRUSVZlGfh8YrCLqVeEoCcNlhstNg==";
    let ed25519_pub_spki = "MCowBQYDK2VwAyEAoxxHlHVPdXxRRxhElrr2RRXPUFIFsdvteB+Iac9NjuM=";
    let priv_min =
        PrivateKey::from_slice(&decode_b64(ed25519_priv_min)).expect("ed25519 priv minimal parse");
    let pub_spki =
        PublicKey::from_slice(&decode_b64(ed25519_pub_spki)).expect("ed25519 spki parse");
    // Roundtrip display
    let _ = priv_min.to_string();
    let _ = pub_spki.to_string();

    // Construct nested-v1 variant from the minimal one and ensure we can parse it
    let nested = ed25519_minimal_to_nested(&decode_b64(ed25519_priv_min)).expect("nested conv");
    let _priv_nested = PrivateKey::from_slice(&nested).expect("ed25519 priv nested parse");
}

#[test]
fn generate_and_roundtrip_across_algos() {
    let cases = [
        KeygenParams::Ed25519,
        KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP256Sha256),
        KeygenParams::Ecdsa(EcdsaKeygenParams::EcdsaP384Sha384),
        KeygenParams::Rsa(RsaKeygenParams::Rsa2048),
    ];
    for params in cases {
        let (privk, pubk) = gen_keypair(params).expect("keygen");
        let s = privk.to_string();
        let parsed: PrivateKey = s.parse().expect("parse priv");
        assert_eq!(parsed.to_string(), s);
        let spki = pubk.to_string();
        let parsed_pub: PublicKey = spki.parse().expect("parse pub");
        assert_eq!(parsed_pub.to_string(), spki);
    }
}

#[test]
fn ed25519_generated_is_pkcs8_v1() {
    let (privk, _pubk) = gen_keypair(KeygenParams::Ed25519).expect("keygen ed25519");
    let der = privk.to_string();
    let der = decode_b64(&der);
    assert_eq!(pkcs8_version(&der), Some(0), "expected PKCS#8 v1");
}

fn pkcs8_version(der: &[u8]) -> Option<u8> {
    // Very small DER check: SEQUENCE, [len], INTEGER version at the start of PrivateKeyInfo.
    if der.len() < 5 {
        return None;
    }
    if der[0] != 0x30 {
        return None;
    }
    // Skip length
    let mut i = 1;
    let len = der[i] as usize;
    i += 1;
    if len & 0x80 != 0 {
        let n = len & 0x7F;
        if i + n > der.len() {
            return None;
        }
        i += n;
    }
    // Return one-byte INTEGER version.
    if i + 3 > der.len() {
        return None;
    }
    (der[i] == 0x02 && der[i + 1] == 0x01).then_some(der[i + 2])
}

fn ed25519_minimal_to_nested(der: &[u8]) -> Option<Vec<u8>> {
    // Convert minimal v1 (privateKey is 32 bytes) to nested v1 (privateKey contains inner OCTET of 32 bytes)
    const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
    let idx = der
        .windows(OID_ED25519.len())
        .position(|w| w == OID_ED25519)?;
    let mut i = idx + OID_ED25519.len();
    let end = der.len();
    while i + 2 < end {
        let tag = der[i];
        i += 1;
        let mut len = der[i] as usize;
        i += 1;
        if len & 0x80 != 0 {
            let n = len & 0x7F;
            if i + n > end {
                return None;
            }
            let mut v = 0usize;
            for b in &der[i..i + n] {
                v = (v << 8) | (*b as usize);
            }
            len = v;
            i += n;
        }
        if i + len > end {
            return None;
        }
        if tag == 0x04 {
            let seed = &der[i..i + len];
            if seed.len() != 32 {
                return None;
            }
            // Rebuild PKCS#8 v1 with nested OCTET
            fn der_len(mut n: usize, out: &mut Vec<u8>) {
                if n < 128 {
                    out.push(n as u8);
                } else {
                    let mut tmp = [0u8; 8];
                    let mut k = 8;
                    while n > 0 {
                        k -= 1;
                        tmp[k] = (n & 0xFF) as u8;
                        n >>= 8;
                    }
                    out.push(0x80 | (8 - k) as u8);
                    out.extend_from_slice(&tmp[k..]);
                }
            }
            let mut alg = Vec::new();
            alg.push(0x30);
            der_len(OID_ED25519.len(), &mut alg);
            alg.extend_from_slice(OID_ED25519);
            let mut inner = Vec::new();
            inner.push(0x04);
            der_len(32, &mut inner);
            inner.extend_from_slice(seed);
            let mut privk = Vec::new();
            privk.push(0x04);
            der_len(inner.len(), &mut privk);
            privk.extend_from_slice(&inner);
            let mut body = Vec::new();
            body.extend_from_slice(&[0x02, 0x01, 0x00]);
            body.extend_from_slice(&alg);
            body.extend_from_slice(&privk);
            let mut seq = Vec::new();
            seq.push(0x30);
            der_len(body.len(), &mut seq);
            seq.extend_from_slice(&body);
            return Some(seq);
        }
        i += len;
    }
    None
}
