use napi::bindgen_prelude::*;
use napi_derive::napi;
use secp256k1_zkp::{Generator, SecretKey, Tweak, ZERO_TWEAK};

use crate::error::HathorCtError;
use crate::types::COMMITMENT_SIZE;

fn to_napi_err(e: HathorCtError) -> napi::Error {
    napi::Error::from_reason(e.to_string())
}

/// Convert a napi BigInt to u64, returning an error if the value is negative or too large.
fn bigint_to_u64(value: &BigInt) -> napi::Result<u64> {
    let (signed, val, lossless) = value.get_u64();
    if signed {
        return Err(napi::Error::from_reason("value must be non-negative"));
    }
    if !lossless {
        return Err(napi::Error::from_reason("value exceeds u64 range"));
    }
    Ok(val)
}

fn parse_tweak(bytes: &[u8]) -> napi::Result<Tweak> {
    if bytes.len() != 32 {
        return Err(napi::Error::from_reason("must be 32 bytes"));
    }
    Tweak::from_slice(bytes).map_err(|e| napi::Error::from_reason(e.to_string()))
}

fn parse_secret_key(bytes: &[u8]) -> napi::Result<SecretKey> {
    if bytes.len() != 32 {
        return Err(napi::Error::from_reason("must be 32 bytes"));
    }
    SecretKey::from_slice(bytes).map_err(|e| napi::Error::from_reason(e.to_string()))
}

fn parse_generator(bytes: &[u8]) -> napi::Result<Generator> {
    if bytes.len() != 33 {
        return Err(napi::Error::from_reason("must be 33 bytes"));
    }
    crate::generators::deserialize_generator(bytes).map_err(to_napi_err)
}

/// Derive a deterministic NUMS generator for a token UID.
#[napi]
pub fn derive_asset_tag(token_uid: Buffer) -> napi::Result<Buffer> {
    if token_uid.len() != 32 {
        return Err(napi::Error::from_reason("token_uid must be 32 bytes"));
    }
    let uid: [u8; 32] = token_uid
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("token_uid must be exactly 32 bytes"))?;
    let tag = crate::generators::derive_asset_tag(&uid).map_err(to_napi_err)?;
    Ok(Buffer::from(tag.serialize().to_vec()))
}

/// Return the HTR asset tag (token_uid = [0; 32]).
#[napi]
pub fn htr_asset_tag() -> Buffer {
    let tag = crate::generators::htr_asset_tag();
    Buffer::from(tag.serialize().to_vec())
}

/// Derive a raw Tag from token UID (for surjection proofs).
#[napi]
pub fn derive_tag(token_uid: Buffer) -> napi::Result<Buffer> {
    if token_uid.len() != 32 {
        return Err(napi::Error::from_reason("token_uid must be 32 bytes"));
    }
    let uid: [u8; 32] = token_uid
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("token_uid must be exactly 32 bytes"))?;
    let tag = crate::generators::derive_tag(&uid).map_err(to_napi_err)?;
    let tag_bytes: [u8; 32] = tag.into();
    Ok(Buffer::from(tag_bytes.to_vec()))
}

/// Create a blinded asset commitment (Generator) from a Tag and blinding factor.
#[napi]
pub fn create_asset_commitment(tag_bytes: Buffer, r_asset: Buffer) -> napi::Result<Buffer> {
    if tag_bytes.len() != 32 {
        return Err(napi::Error::from_reason("tag must be 32 bytes (raw Tag)"));
    }
    let tag = secp256k1_zkp::Tag::from(
        <[u8; 32]>::try_from(tag_bytes.as_ref())
            .map_err(|_| napi::Error::from_reason("tag must be exactly 32 bytes"))?,
    );
    let tweak = parse_tweak(r_asset.as_ref())?;
    let commitment =
        crate::generators::create_asset_commitment(&tag, &tweak).map_err(to_napi_err)?;
    Ok(Buffer::from(commitment.serialize().to_vec()))
}

/// Create a Pedersen commitment.
#[napi]
pub fn create_commitment(
    amount: BigInt,
    blinding: Buffer,
    generator: Buffer,
) -> napi::Result<Buffer> {
    let amount = bigint_to_u64(&amount)?;
    let bf = parse_tweak(blinding.as_ref())?;
    let gen = parse_generator(generator.as_ref())?;
    let c = crate::pedersen::create_commitment(amount, &bf, &gen).map_err(to_napi_err)?;
    Ok(Buffer::from(c.serialize().to_vec()))
}

/// Create a trivial (zero-blinding) Pedersen commitment.
#[napi]
pub fn create_trivial_commitment(amount: BigInt, generator: Buffer) -> napi::Result<Buffer> {
    let amount = bigint_to_u64(&amount)?;
    let gen = parse_generator(generator.as_ref())?;
    let c = crate::pedersen::create_trivial_commitment(amount, &gen).map_err(to_napi_err)?;
    Ok(Buffer::from(c.serialize().to_vec()))
}

/// Verify that sum of positive commitments equals sum of negative commitments.
#[napi]
pub fn verify_commitments_sum(positive: Vec<Buffer>, negative: Vec<Buffer>) -> napi::Result<bool> {
    let pos: Vec<_> = positive
        .iter()
        .map(|b| crate::pedersen::deserialize_commitment(b.as_ref()).map_err(to_napi_err))
        .collect::<napi::Result<Vec<_>>>()?;
    let neg: Vec<_> = negative
        .iter()
        .map(|b| crate::pedersen::deserialize_commitment(b.as_ref()).map_err(to_napi_err))
        .collect::<napi::Result<Vec<_>>>()?;
    Ok(crate::pedersen::verify_commitments_sum(&pos, &neg))
}

/// Create a Borromean range proof.
#[napi]
pub fn create_range_proof(
    amount: BigInt,
    blinding: Buffer,
    commitment: Buffer,
    generator: Buffer,
    message: Option<Buffer>,
    nonce: Option<Buffer>,
) -> napi::Result<Buffer> {
    let amount = bigint_to_u64(&amount)?;
    let bf = parse_tweak(blinding.as_ref())?;
    let comm = crate::pedersen::deserialize_commitment(commitment.as_ref()).map_err(to_napi_err)?;
    let gen = parse_generator(generator.as_ref())?;
    let nonce_key = nonce
        .as_ref()
        .map(|n| parse_secret_key(n.as_ref()))
        .transpose()?;
    let msg_bytes = message.as_ref().map(|m| m.as_ref());
    let proof = crate::rangeproof::create_range_proof(
        amount,
        &bf,
        &comm,
        &gen,
        msg_bytes,
        nonce_key.as_ref(),
    )
    .map_err(to_napi_err)?;
    Ok(Buffer::from(proof.serialize().to_vec()))
}

/// Verify a Borromean range proof.
#[napi]
pub fn verify_range_proof(
    proof: Buffer,
    commitment: Buffer,
    generator: Buffer,
) -> napi::Result<bool> {
    let p = crate::rangeproof::deserialize_range_proof(proof.as_ref()).map_err(to_napi_err)?;
    let c = crate::pedersen::deserialize_commitment(commitment.as_ref()).map_err(to_napi_err)?;
    let gen = parse_generator(generator.as_ref())?;
    match crate::rangeproof::verify_range_proof(&p, &c, &gen) {
        Ok(range) => {
            if range.start < 1 {
                return Ok(false); // Reject zero-amount proofs
            }
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}

/// Rewind a Borromean range proof to recover the committed value, blinding factor, and message.
#[napi(object)]
pub struct RewindResult {
    pub value: BigInt,
    pub blinding_factor: Buffer,
    pub message: Buffer,
}

#[napi]
pub fn rewind_range_proof(
    proof: Buffer,
    commitment: Buffer,
    nonce: Buffer,
    generator: Buffer,
) -> napi::Result<RewindResult> {
    let p = crate::rangeproof::deserialize_range_proof(proof.as_ref()).map_err(to_napi_err)?;
    let c = crate::pedersen::deserialize_commitment(commitment.as_ref()).map_err(to_napi_err)?;
    let sk = parse_secret_key(nonce.as_ref())?;
    let gen = parse_generator(generator.as_ref())?;
    let (value, blinding, message) =
        crate::rangeproof::rewind_range_proof(&p, &c, &sk, &gen).map_err(to_napi_err)?;
    Ok(RewindResult {
        value: BigInt::from(value),
        blinding_factor: Buffer::from(blinding.as_ref().to_vec()),
        message: Buffer::from(message),
    })
}

/// Validate that bytes represent a valid Pedersen commitment (curve point).
#[napi]
pub fn validate_commitment(data: Buffer) -> bool {
    if data.len() != 33 {
        return false;
    }
    crate::pedersen::deserialize_commitment(data.as_ref()).is_ok()
}

/// Validate that bytes represent a valid generator (curve point).
#[napi]
pub fn validate_generator(data: Buffer) -> bool {
    if data.len() != 33 {
        return false;
    }
    crate::generators::deserialize_generator(data.as_ref()).is_ok()
}

/// Create a surjection proof.
#[napi]
pub fn create_surjection_proof(
    codomain_tag: Buffer,
    codomain_blinding_factor: Buffer,
    domain: Vec<SurjectionDomainEntry>,
) -> napi::Result<Buffer> {
    if codomain_tag.len() != 32 {
        return Err(napi::Error::from_reason("codomain_tag must be 32 bytes"));
    }
    let ct = secp256k1_zkp::Tag::from(
        <[u8; 32]>::try_from(codomain_tag.as_ref())
            .map_err(|_| napi::Error::from_reason("codomain_tag must be exactly 32 bytes"))?,
    );
    let cbf = parse_tweak(codomain_blinding_factor.as_ref())?;

    let domain_vec: Vec<(Generator, secp256k1_zkp::Tag, Tweak)> = domain
        .iter()
        .map(|entry| {
            let gen = parse_generator(entry.generator.as_ref())?;
            if entry.tag.len() != 32 {
                return Err(napi::Error::from_reason("tag must be 32 bytes"));
            }
            let tag = secp256k1_zkp::Tag::from(
                <[u8; 32]>::try_from(entry.tag.as_ref())
                    .map_err(|_| napi::Error::from_reason("tag must be exactly 32 bytes"))?,
            );
            let bf = parse_tweak(entry.blinding_factor.as_ref())?;
            Ok((gen, tag, bf))
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let proof =
        crate::surjection::create_surjection_proof(&ct, &cbf, &domain_vec).map_err(to_napi_err)?;
    Ok(Buffer::from(proof.serialize().to_vec()))
}

#[napi(object)]
pub struct SurjectionDomainEntry {
    pub generator: Buffer,
    pub tag: Buffer,
    pub blinding_factor: Buffer,
}

/// Verify a surjection proof.
#[napi]
pub fn verify_surjection_proof(
    proof: Buffer,
    codomain: Buffer,
    domain: Vec<Buffer>,
) -> napi::Result<bool> {
    let p = crate::surjection::deserialize_surjection_proof(proof.as_ref()).map_err(to_napi_err)?;
    let codomain_gen = parse_generator(codomain.as_ref())?;
    let domain_gens: Vec<Generator> = domain
        .iter()
        .map(|b| parse_generator(b.as_ref()))
        .collect::<napi::Result<Vec<_>>>()?;
    match crate::surjection::verify_surjection_proof(&p, &codomain_gen, &domain_gens) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[napi(object)]
pub struct TransparentEntry {
    pub amount: BigInt,
    pub token_uid: Buffer,
}

/// Verify the homomorphic balance equation.
#[napi]
pub fn verify_balance(
    transparent_inputs: Vec<TransparentEntry>,
    shielded_inputs: Vec<Buffer>,
    transparent_outputs: Vec<TransparentEntry>,
    shielded_outputs: Vec<Buffer>,
) -> napi::Result<bool> {
    let mut inputs = Vec::new();
    for entry in &transparent_inputs {
        let uid: [u8; 32] = entry
            .token_uid
            .as_ref()
            .try_into()
            .map_err(|_| napi::Error::from_reason("token_uid must be 32 bytes"))?;
        inputs.push(crate::balance::BalanceEntry::Transparent {
            amount: bigint_to_u64(&entry.amount)?,
            token_uid: uid,
        });
    }
    for cb in &shielded_inputs {
        let c = crate::pedersen::deserialize_commitment(cb.as_ref()).map_err(to_napi_err)?;
        inputs.push(crate::balance::BalanceEntry::Shielded {
            value_commitment: c,
        });
    }

    let mut outputs = Vec::new();
    for entry in &transparent_outputs {
        let uid: [u8; 32] = entry
            .token_uid
            .as_ref()
            .try_into()
            .map_err(|_| napi::Error::from_reason("token_uid must be 32 bytes"))?;
        outputs.push(crate::balance::BalanceEntry::Transparent {
            amount: bigint_to_u64(&entry.amount)?,
            token_uid: uid,
        });
    }
    for cb in &shielded_outputs {
        let c = crate::pedersen::deserialize_commitment(cb.as_ref()).map_err(to_napi_err)?;
        outputs.push(crate::balance::BalanceEntry::Shielded {
            value_commitment: c,
        });
    }

    crate::balance::verify_balance(&inputs, &outputs)
        .map(|()| true)
        .or_else(|e| match e {
            HathorCtError::BalanceError(_) => Ok(false),
            other => Err(to_napi_err(other)),
        })
}

/// Compute the balancing blinding factor for the last output.
#[napi]
pub fn compute_balancing_blinding_factor(
    value: BigInt,
    generator_blinding_factor: Buffer,
    inputs: Vec<BlindingEntry>,
    other_outputs: Vec<BlindingEntry>,
) -> napi::Result<Buffer> {
    let value = bigint_to_u64(&value)?;
    let gbf = parse_tweak(generator_blinding_factor.as_ref())?;

    let in_entries: Vec<(u64, Tweak, Tweak)> = inputs
        .iter()
        .map(|e| {
            Ok((
                bigint_to_u64(&e.value)?,
                parse_tweak(e.value_blinding_factor.as_ref())?,
                parse_tweak(e.generator_blinding_factor.as_ref())?,
            ))
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let out_entries: Vec<(u64, Tweak, Tweak)> = other_outputs
        .iter()
        .map(|e| {
            Ok((
                bigint_to_u64(&e.value)?,
                parse_tweak(e.value_blinding_factor.as_ref())?,
                parse_tweak(e.generator_blinding_factor.as_ref())?,
            ))
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let result =
        crate::balance::compute_balancing_blinding_factor(value, &gbf, &in_entries, &out_entries)
            .map_err(to_napi_err)?;

    Ok(Buffer::from(result.as_ref().to_vec()))
}

#[napi(object)]
pub struct BlindingEntry {
    pub value: BigInt,
    pub value_blinding_factor: Buffer,
    pub generator_blinding_factor: Buffer,
}

/// Generate a random 32-byte blinding factor (valid secp256k1 scalar).
#[napi]
pub fn generate_random_blinding_factor() -> Buffer {
    Buffer::from(crate::ecdh::generate_random_blinding_factor().to_vec())
}

/// Generate a fresh ephemeral secp256k1 key pair.
///
/// Returns (private_key_bytes: 32B, compressed_pubkey_bytes: 33B).
#[napi(object)]
pub struct EphemeralKeypair {
    pub private_key: Buffer,
    pub public_key: Buffer,
}

#[napi]
pub fn generate_ephemeral_keypair() -> EphemeralKeypair {
    let (sk_bytes, pk_bytes) = crate::ecdh::generate_ephemeral_keypair();
    EphemeralKeypair {
        private_key: Buffer::from(sk_bytes.to_vec()),
        public_key: Buffer::from(pk_bytes.to_vec()),
    }
}

/// Compute ECDH shared secret: SHA256(version_byte || x_coordinate).
///
/// Uses libsecp256k1's standard ECDH derivation.
/// Returns 32-byte shared secret.
#[napi]
pub fn derive_ecdh_shared_secret(private_key: Buffer, peer_pubkey: Buffer) -> napi::Result<Buffer> {
    let sk = crate::ecdh::parse_secret_key(private_key.as_ref()).map_err(to_napi_err)?;
    let pk = crate::ecdh::parse_public_key(peer_pubkey.as_ref()).map_err(to_napi_err)?;
    let secret = crate::ecdh::derive_ecdh_shared_secret(&sk, &pk);
    Ok(Buffer::from(secret.to_vec()))
}

/// Derive a deterministic nonce from a shared secret.
///
/// nonce = SHA256("Hathor_CT_nonce_v1" || shared_secret)
/// Returns 32-byte nonce suitable for use as a range proof nonce key.
#[napi]
pub fn derive_rewind_nonce(shared_secret: Buffer) -> napi::Result<Buffer> {
    if shared_secret.len() != 32 {
        return Err(napi::Error::from_reason("shared_secret must be 32 bytes"));
    }
    let secret: [u8; 32] = shared_secret.as_ref().try_into().unwrap();
    let nonce = crate::ecdh::derive_rewind_nonce(&secret);
    Ok(Buffer::from(nonce.to_vec()))
}

#[napi(object)]
pub struct CreatedShieldedOutput {
    pub ephemeral_pubkey: Buffer,
    pub commitment: Buffer,
    pub range_proof: Buffer,
    pub blinding_factor: Buffer,
    pub asset_commitment: Option<Buffer>,
    pub asset_blinding_factor: Option<Buffer>,
}

/// Create a FullShielded output with both value blinding factor and asset blinding factor
/// provided externally. This is needed for the last output in a FullShielded transaction
/// where the balance equation requires pre-computing the vbf using a known abf.
#[napi]
pub fn create_shielded_output_with_both_blindings(
    value: BigInt,
    recipient_pubkey: Buffer,
    token_uid: Buffer,
    value_blinding_factor: Buffer,
    asset_blinding_factor: Buffer,
) -> napi::Result<CreatedShieldedOutput> {
    let value = bigint_to_u64(&value)?;
    let tuid: [u8; 32] = token_uid
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("token_uid must be 32 bytes"))?;
    let vbf: [u8; 32] = value_blinding_factor
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("value_blinding_factor must be 32 bytes"))?;
    let abf: [u8; 32] = asset_blinding_factor
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("asset_blinding_factor must be 32 bytes"))?;

    let result = crate::ecdh::create_full_shielded_output(
        value,
        recipient_pubkey.as_ref(),
        &tuid,
        &vbf,
        &abf,
    )
    .map_err(to_napi_err)?;

    Ok(CreatedShieldedOutput {
        ephemeral_pubkey: Buffer::from(result.ephemeral_pubkey.to_vec()),
        commitment: Buffer::from(result.commitment),
        range_proof: Buffer::from(result.range_proof),
        blinding_factor: Buffer::from(result.value_blinding_factor.to_vec()),
        asset_commitment: Some(Buffer::from(result.asset_commitment)),
        asset_blinding_factor: Some(Buffer::from(result.asset_blinding_factor.to_vec())),
    })
}

/// Result of creating an AmountShielded output (amount hidden, token visible).
#[napi(object)]
pub struct CreatedAmountShieldedOutput {
    pub ephemeral_pubkey: Buffer,
    pub commitment: Buffer,
    pub range_proof: Buffer,
    pub blinding_factor: Buffer,
}

/// Create an AmountShielded output (amount hidden, token visible).
///
/// Uses `derive_asset_tag(token_uid)` as the unblinded generator.
#[napi]
pub fn create_amount_shielded_output(
    value: BigInt,
    recipient_pubkey: Buffer,
    token_uid: Buffer,
    value_blinding_factor: Buffer,
) -> napi::Result<CreatedAmountShieldedOutput> {
    let value = bigint_to_u64(&value)?;
    let tuid: [u8; 32] = token_uid
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("token_uid must be 32 bytes"))?;
    let vbf: [u8; 32] = value_blinding_factor
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("value_blinding_factor must be 32 bytes"))?;

    let result =
        crate::ecdh::create_amount_shielded_output(value, recipient_pubkey.as_ref(), &tuid, &vbf)
            .map_err(to_napi_err)?;

    Ok(CreatedAmountShieldedOutput {
        ephemeral_pubkey: Buffer::from(result.ephemeral_pubkey.to_vec()),
        commitment: Buffer::from(result.commitment),
        range_proof: Buffer::from(result.range_proof),
        blinding_factor: Buffer::from(result.value_blinding_factor.to_vec()),
    })
}

/// Result of rewinding an AmountShielded output.
#[napi(object)]
pub struct RewoundAmountShieldedOutput {
    pub value: BigInt,
    pub blinding_factor: Buffer,
}

/// Rewind an AmountShielded output to recover value and blinding factor.
#[napi]
pub fn rewind_amount_shielded_output(
    private_key: Buffer,
    ephemeral_pubkey: Buffer,
    commitment: Buffer,
    range_proof: Buffer,
    token_uid: Buffer,
) -> napi::Result<RewoundAmountShieldedOutput> {
    let tuid: [u8; 32] = token_uid
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("token_uid must be 32 bytes"))?;

    let result = crate::ecdh::rewind_amount_shielded_output(
        private_key.as_ref(),
        ephemeral_pubkey.as_ref(),
        commitment.as_ref(),
        range_proof.as_ref(),
        &tuid,
    )
    .map_err(to_napi_err)?;

    Ok(RewoundAmountShieldedOutput {
        value: BigInt::from(result.value),
        blinding_factor: Buffer::from(result.blinding_factor),
    })
}

/// Result of rewinding a FullShielded output.
#[napi(object)]
pub struct RewoundFullShieldedOutput {
    pub value: BigInt,
    pub blinding_factor: Buffer,
    pub token_uid: Buffer,
    pub asset_blinding_factor: Buffer,
}

/// Rewind a FullShielded output to recover value, blinding factor, token UID and asset blinding.
#[napi]
pub fn rewind_full_shielded_output(
    private_key: Buffer,
    ephemeral_pubkey: Buffer,
    commitment: Buffer,
    range_proof: Buffer,
    asset_commitment: Buffer,
) -> napi::Result<RewoundFullShieldedOutput> {
    let result = crate::ecdh::rewind_full_shielded_output(
        private_key.as_ref(),
        ephemeral_pubkey.as_ref(),
        commitment.as_ref(),
        range_proof.as_ref(),
        asset_commitment.as_ref(),
    )
    .map_err(to_napi_err)?;

    Ok(RewoundFullShieldedOutput {
        value: BigInt::from(result.value),
        blinding_factor: Buffer::from(result.blinding_factor),
        token_uid: Buffer::from(result.token_uid.to_vec()),
        asset_blinding_factor: Buffer::from(result.asset_blinding_factor.to_vec()),
    })
}

/// Size of a serialized Pedersen commitment.
#[napi]
pub fn get_commitment_size() -> u32 {
    COMMITMENT_SIZE as u32
}

/// Size of a serialized generator.
#[napi]
pub fn get_generator_size() -> u32 {
    crate::types::GENERATOR_SIZE as u32
}

/// The zero tweak (32 zero bytes).
#[napi]
pub fn get_zero_tweak() -> Buffer {
    Buffer::from(ZERO_TWEAK.as_ref().to_vec())
}

#[cfg(test)]
mod tests {
    //! Rust-side tests for the BigInt <-> u64 conversion at the napi boundary.
    //!
    //! End-to-end BigInt flow through the bindings (create_commitment, rewind_*, etc.)
    //! is exercised by the JS integration tests in `tests/bigint.test.mjs`, because
    //! those functions return napi `Buffer`s whose `Drop` impl links against symbols
    //! only available at runtime inside Node.js.
    use super::*;

    fn bigint_pos(words: Vec<u64>) -> BigInt {
        BigInt {
            sign_bit: false,
            words,
        }
    }

    fn bigint_neg(words: Vec<u64>) -> BigInt {
        BigInt {
            sign_bit: true,
            words,
        }
    }

    #[test]
    fn bigint_to_u64_zero() {
        assert_eq!(bigint_to_u64(&BigInt::from(0u64)).unwrap(), 0);
    }

    #[test]
    fn bigint_to_u64_small() {
        assert_eq!(bigint_to_u64(&BigInt::from(12_345u64)).unwrap(), 12_345);
    }

    #[test]
    fn bigint_to_u64_js_safe_integer_boundary() {
        // 2^53 - 1 is the largest integer JS Number can represent exactly.
        let v = (1u64 << 53) - 1;
        assert_eq!(bigint_to_u64(&BigInt::from(v)).unwrap(), v);
    }

    #[test]
    fn bigint_to_u64_above_js_safe_integer() {
        // 2^53 + 1 cannot be represented exactly as a JS Number but is exact in u64/BigInt.
        // This is the motivating case for using BigInt at the napi boundary.
        let v = (1u64 << 53) + 1;
        assert_eq!(bigint_to_u64(&BigInt::from(v)).unwrap(), v);
    }

    #[test]
    fn bigint_to_u64_i64_max() {
        // Values above i64::MAX used to be unrepresentable because the old signature was i64.
        let v = i64::MAX as u64 + 1;
        assert_eq!(bigint_to_u64(&BigInt::from(v)).unwrap(), v);
    }

    #[test]
    fn bigint_to_u64_max() {
        assert_eq!(bigint_to_u64(&BigInt::from(u64::MAX)).unwrap(), u64::MAX);
    }

    #[test]
    fn bigint_to_u64_negative_rejected() {
        let Err(err) = bigint_to_u64(&bigint_neg(vec![1])) else {
            panic!("expected error for negative BigInt");
        };
        assert!(err.reason.contains("non-negative"), "got: {}", err.reason);
    }

    #[test]
    fn bigint_to_u64_negative_large_rejected() {
        // Negative value that also spans multiple words.
        let Err(err) = bigint_to_u64(&bigint_neg(vec![5, 7])) else {
            panic!("expected error for negative BigInt");
        };
        // `signed` is checked first, so negative wins over "exceeds u64 range".
        assert!(err.reason.contains("non-negative"), "got: {}", err.reason);
    }

    #[test]
    fn bigint_to_u64_overflow_rejected() {
        // 2^64 = [0, 1] in little-endian u64 words — just past u64::MAX.
        let Err(err) = bigint_to_u64(&bigint_pos(vec![0, 1])) else {
            panic!("expected error for overflow BigInt");
        };
        assert!(
            err.reason.contains("exceeds u64 range"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn bigint_to_u64_huge_overflow_rejected() {
        // (2^64)^2 = [0, 0, 1] — three words, far beyond u64.
        let Err(err) = bigint_to_u64(&bigint_pos(vec![0, 0, 1])) else {
            panic!("expected error for overflow BigInt");
        };
        assert!(
            err.reason.contains("exceeds u64 range"),
            "got: {}",
            err.reason
        );
    }

    #[test]
    fn bigint_from_u64_round_trip() {
        // The return-value path: BigInt::from(u64) -> .get_u64() -> u64.
        // This is what rewind_* callers rely on to recover the committed value.
        for v in [
            0u64,
            1,
            12_345,
            (1u64 << 53) - 1,
            (1u64 << 53) + 1,
            i64::MAX as u64 + 1,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let (signed, recovered, lossless) = BigInt::from(v).get_u64();
            assert!(!signed, "v={v}");
            assert!(lossless, "v={v}");
            assert_eq!(recovered, v, "v={v}");
        }
    }
}
