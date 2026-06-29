//! Hashing and ECDSA signature checking, replicating the observable behavior of the
//! `cryptography` (OpenSSL) calls made by `hathor/transaction/scripts/opcode.py`.

use ripemd::Ripemd160;
use secp256k1::ecdsa::Signature;
use secp256k1::global::SECP256K1;
use secp256k1::{Message, PublicKey};
use sha2::{Digest, Sha256};

use crate::script::{ErrorKind, EvalError};

/// sha256 digest as a fixed array.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// `get_hash160`: ripemd160(sha256(x)).
pub fn hash160(data: &[u8]) -> [u8; 20] {
    Ripemd160::digest(sha256(data)).into()
}

/// `get_checksum`: first 4 bytes of sha256(sha256(payload)), used in address encoding.
pub fn address_checksum(payload: &[u8]) -> [u8; 4] {
    let digest = sha256(&sha256(payload));
    [digest[0], digest[1], digest[2], digest[3]]
}

/// Outcome of a signature check that did not error: in `OP_CHECKSIG` an invalid signature
/// pushes `0` (it is not an error), while `OP_CHECKDATASIG` raises `OracleChecksigFailed`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigCheck {
    Valid,
    Invalid,
}

/// Replicates `op_checksig`'s pubkey + signature handling:
///
/// 1. `is_pubkey_compressed`: non-empty and first byte 0x02/0x03 (no length check) —
///    failure is a `ScriptError`, distinct from an invalid signature.
/// 2. Pubkey parse (`from_encoded_point`): wrong length or off-curve point — also `ScriptError`.
/// 3. ECDSA(SHA256) verify of `message` (hashed once more here, matching OpenSSL's verify
///    which hashes the passed data): any DER-parse or verify failure is `SigCheck::Invalid`.
///
/// DER policy: strict DER parse + unconditional low-S normalization. The bundled OpenSSL 3.x
/// used by `cryptography` parses signatures with strict DER but accepts high-S values;
/// `normalize_s` covers that one systematic divergence. The differential signature-acceptance
/// fuzz in `hathor_tests/tx/test_rust_script_verification.py` is the empirical arbiter of
/// this policy.
pub fn checksig(
    pubkey: &[u8],
    signature: &[u8],
    message: &[u8],
    op_name: &str,
) -> Result<SigCheck, EvalError> {
    if pubkey.is_empty() || !(pubkey[0] == 0x02 || pubkey[0] == 0x03) {
        let message = format!("{op_name}: pubkey is not a compressed public key");
        return Err(EvalError::new(ErrorKind::Script, message));
    }
    let Ok(public_key) = PublicKey::from_slice(pubkey) else {
        let message = format!("{op_name}: pubkey is not a public key");
        return Err(EvalError::new(ErrorKind::Script, message));
    };
    let Ok(mut sig) = Signature::from_der(signature) else {
        return Ok(SigCheck::Invalid);
    };
    sig.normalize_s();
    let digest = Message::from_digest(sha256(message));
    match SECP256K1.verify_ecdsa(digest, &sig, &public_key) {
        Ok(()) => Ok(SigCheck::Valid),
        Err(_) => Ok(SigCheck::Invalid),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Vectors generated from the Python reference (cryptography/OpenSSL).
    const PUBKEY: &str = "02bb50e2d89a4ed70663d080659fe0ad4b9bc3e06c17a227433966cb59ceee020d";
    const MESSAGE: &[u8] = b"sighash-all-data-test-vector";
    const SIG: &str = "3046022100cc12cb50151af677dc2d2bb4066dcf9b7d0a24b7afcc49ef00dd294913e30c79022100eefaa87a97bc4251a2abe762426c850527e41c787762ac392241f50ce06e3332";
    // Same (r, s) with s replaced by n - s; OpenSSL accepts it, so Rust must too.
    const SIG_HIGH_S: &str = "3045022100cc12cb50151af677dc2d2bb4066dcf9b7d0a24b7afcc49ef00dd294913e30c790220110557856843bdae5d54189dbd937af992cac06e37e5f4029d90697fefc80e0f";

    #[test]
    fn test_hash160() {
        assert_eq!(
            hash160(&from_hex(PUBKEY)).to_vec(),
            from_hex("a390bb4d6d4ab570767ef21f66c3edc1a4d69026")
        );
    }

    #[test]
    fn test_address_checksum() {
        let mut payload = vec![0x28];
        payload.extend_from_slice(&from_hex("a390bb4d6d4ab570767ef21f66c3edc1a4d69026"));
        assert_eq!(address_checksum(&payload), [0xD8, 0xEF, 0x8E, 0x36]);
    }

    #[test]
    fn test_checksig_valid() {
        let result = checksig(&from_hex(PUBKEY), &from_hex(SIG), MESSAGE, "OP_CHECKSIG");
        assert_eq!(result, Ok(SigCheck::Valid));
    }

    #[test]
    fn test_checksig_high_s_is_valid() {
        let result = checksig(
            &from_hex(PUBKEY),
            &from_hex(SIG_HIGH_S),
            MESSAGE,
            "OP_CHECKSIG",
        );
        assert_eq!(result, Ok(SigCheck::Valid));
    }

    #[test]
    fn test_checksig_wrong_message() {
        let result = checksig(
            &from_hex(PUBKEY),
            &from_hex(SIG),
            b"other message",
            "OP_CHECKSIG",
        );
        assert_eq!(result, Ok(SigCheck::Invalid));
    }

    #[test]
    fn test_checksig_trailing_garbage_rejected() {
        // OpenSSL 3.x strict-DER rejects trailing bytes; verified against the Python reference.
        let mut sig = from_hex(SIG);
        sig.push(0x00);
        let result = checksig(&from_hex(PUBKEY), &sig, MESSAGE, "OP_CHECKSIG");
        assert_eq!(result, Ok(SigCheck::Invalid));
    }

    #[test]
    fn test_checksig_garbage_der() {
        let result = checksig(
            &from_hex(PUBKEY),
            &[0x30, 0x01, 0x02],
            MESSAGE,
            "OP_CHECKSIG",
        );
        assert_eq!(result, Ok(SigCheck::Invalid));
        let result = checksig(&from_hex(PUBKEY), &[], MESSAGE, "OP_CHECKSIG");
        assert_eq!(result, Ok(SigCheck::Invalid));
    }

    #[test]
    fn test_checksig_pubkey_not_compressed() {
        for pubkey in [&b""[..], &[0x04, 0xAB][..], &[0x01][..]] {
            let err = checksig(pubkey, &from_hex(SIG), MESSAGE, "OP_CHECKSIG").unwrap_err();
            assert_eq!(err.kind, ErrorKind::Script);
            assert_eq!(
                err.message,
                "OP_CHECKSIG: pubkey is not a compressed public key"
            );
        }
    }

    #[test]
    fn test_checksig_pubkey_not_a_point() {
        // Correct prefix but wrong length.
        let err = checksig(&[0x02, 0xAB], &from_hex(SIG), MESSAGE, "OP_CHECKSIG").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Script);
        assert_eq!(err.message, "OP_CHECKSIG: pubkey is not a public key");
        // Correct prefix and length but x is not on the curve.
        let mut off_curve = vec![0x02];
        off_curve.extend_from_slice(&[0xFF; 32]);
        let err = checksig(&off_curve, &from_hex(SIG), MESSAGE, "OP_CHECKDATASIG").unwrap_err();
        assert_eq!(err.kind, ErrorKind::Script);
        assert_eq!(err.message, "OP_CHECKDATASIG: pubkey is not a public key");
    }
}
