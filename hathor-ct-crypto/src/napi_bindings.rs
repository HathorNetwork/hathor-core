use napi::bindgen_prelude::*;
use napi_derive::napi;
use secp256k1_zkp::{Generator, SecretKey, Tweak, ZERO_TWEAK};

use crate::error::HathorCtError;
use crate::types::COMMITMENT_SIZE;

fn to_napi_err(e: HathorCtError) -> napi::Error {
    napi::Error::from_reason(e.to_string())
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
pub fn create_commitment(amount: i64, blinding: Buffer, generator: Buffer) -> napi::Result<Buffer> {
    if amount < 0 {
        return Err(napi::Error::from_reason("amount must be non-negative"));
    }
    let bf = parse_tweak(blinding.as_ref())?;
    let gen = parse_generator(generator.as_ref())?;
    let c = crate::pedersen::create_commitment(amount as u64, &bf, &gen).map_err(to_napi_err)?;
    Ok(Buffer::from(c.serialize().to_vec()))
}

/// Create a trivial (zero-blinding) Pedersen commitment.
#[napi]
pub fn create_trivial_commitment(amount: i64, generator: Buffer) -> napi::Result<Buffer> {
    if amount < 0 {
        return Err(napi::Error::from_reason("amount must be non-negative"));
    }
    let gen = parse_generator(generator.as_ref())?;
    let c = crate::pedersen::create_trivial_commitment(amount as u64, &gen).map_err(to_napi_err)?;
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

/// Create a Bulletproof range proof.
#[napi]
pub fn create_range_proof(
    amount: i64,
    blinding: Buffer,
    commitment: Buffer,
    generator: Buffer,
    message: Option<Buffer>,
    nonce: Option<Buffer>,
) -> napi::Result<Buffer> {
    if amount < 0 {
        return Err(napi::Error::from_reason("amount must be non-negative"));
    }
    let bf = parse_tweak(blinding.as_ref())?;
    let comm = crate::pedersen::deserialize_commitment(commitment.as_ref()).map_err(to_napi_err)?;
    let gen = parse_generator(generator.as_ref())?;
    let nonce_key = nonce
        .as_ref()
        .map(|n| parse_secret_key(n.as_ref()))
        .transpose()?;
    let msg_bytes = message.as_ref().map(|m| m.as_ref());
    let proof = crate::rangeproof::create_range_proof(
        amount as u64,
        &bf,
        &comm,
        &gen,
        msg_bytes,
        nonce_key.as_ref(),
    )
    .map_err(to_napi_err)?;
    Ok(Buffer::from(proof.serialize().to_vec()))
}

/// Verify a Bulletproof range proof.
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

/// Rewind a Bulletproof range proof to recover the committed value, blinding factor, and message.
#[napi(object)]
pub struct RewindResult {
    pub value: i64,
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
        value: value as i64,
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
    pub amount: i64,
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
            amount: entry.amount as u64,
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
            amount: entry.amount as u64,
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
    value: i64,
    generator_blinding_factor: Buffer,
    inputs: Vec<BlindingEntry>,
    other_outputs: Vec<BlindingEntry>,
) -> napi::Result<Buffer> {
    let gbf = parse_tweak(generator_blinding_factor.as_ref())?;

    let in_entries: Vec<(u64, Tweak, Tweak)> = inputs
        .iter()
        .map(|e| {
            Ok((
                e.value as u64,
                parse_tweak(e.value_blinding_factor.as_ref())?,
                parse_tweak(e.generator_blinding_factor.as_ref())?,
            ))
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let out_entries: Vec<(u64, Tweak, Tweak)> = other_outputs
        .iter()
        .map(|e| {
            Ok((
                e.value as u64,
                parse_tweak(e.value_blinding_factor.as_ref())?,
                parse_tweak(e.generator_blinding_factor.as_ref())?,
            ))
        })
        .collect::<napi::Result<Vec<_>>>()?;

    let result = crate::balance::compute_balancing_blinding_factor(
        value as u64,
        &gbf,
        &in_entries,
        &out_entries,
    )
    .map_err(to_napi_err)?;

    Ok(Buffer::from(result.as_ref().to_vec()))
}

#[napi(object)]
pub struct BlindingEntry {
    pub value: i64,
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
    value: i64,
    recipient_pubkey: Buffer,
    token_uid: Buffer,
    value_blinding_factor: Buffer,
    asset_blinding_factor: Buffer,
) -> napi::Result<CreatedShieldedOutput> {
    if value < 0 {
        return Err(napi::Error::from_reason("value must be non-negative"));
    }
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
        value as u64, recipient_pubkey.as_ref(), &tuid, &vbf, &abf,
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
    value: i64,
    recipient_pubkey: Buffer,
    token_uid: Buffer,
    value_blinding_factor: Buffer,
) -> napi::Result<CreatedAmountShieldedOutput> {
    if value < 0 {
        return Err(napi::Error::from_reason("value must be non-negative"));
    }
    let tuid: [u8; 32] = token_uid
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("token_uid must be 32 bytes"))?;
    let vbf: [u8; 32] = value_blinding_factor
        .as_ref()
        .try_into()
        .map_err(|_| napi::Error::from_reason("value_blinding_factor must be 32 bytes"))?;

    let result = crate::ecdh::create_amount_shielded_output(
        value as u64, recipient_pubkey.as_ref(), &tuid, &vbf,
    )
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
    pub value: i64,
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
        value: result.value as i64,
        blinding_factor: Buffer::from(result.blinding_factor),
    })
}

/// Result of rewinding a FullShielded output.
#[napi(object)]
pub struct RewoundFullShieldedOutput {
    pub value: i64,
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
        value: result.value as i64,
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
