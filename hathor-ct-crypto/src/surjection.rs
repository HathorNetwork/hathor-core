use secp256k1_zkp::{Generator, SurjectionProof, Tag, Tweak, SECP256K1};

use crate::error::{HathorCtError, Result};

/// Create a surjection proof that the output asset commitment is derived from
/// one of the input asset commitments.
///
/// # Arguments
/// * `codomain_tag` - The output's raw Tag (before blinding)
/// * `codomain_blinding_factor` - The blinding factor used for the output generator
/// * `domain` - For each input: (blinded_generator, raw_tag, blinding_factor)
pub fn create_surjection_proof(
    codomain_tag: &Tag,
    codomain_blinding_factor: &Tweak,
    domain: &[(Generator, Tag, Tweak)],
) -> Result<SurjectionProof> {
    if domain.is_empty() {
        return Err(HathorCtError::SurjectionProofError(
            "domain must not be empty".into(),
        ));
    }

    let proof = SurjectionProof::new(
        SECP256K1,
        &mut rand::thread_rng(),
        *codomain_tag,
        *codomain_blinding_factor,
        domain,
    )
    .map_err(|e| HathorCtError::SurjectionProofError(e.to_string()))?;

    Ok(proof)
}

/// Verify a surjection proof that the output asset is derived from one of the input assets.
///
/// * `proof` - The surjection proof
/// * `codomain` - The output's blinded Generator
/// * `domain` - The input blinded Generators
pub fn verify_surjection_proof(
    proof: &SurjectionProof,
    codomain: &Generator,
    domain: &[Generator],
) -> Result<()> {
    if !proof.verify(SECP256K1, *codomain, domain) {
        return Err(HathorCtError::SurjectionProofError(
            "surjection proof verification failed".into(),
        ));
    }
    Ok(())
}

/// Serialize a surjection proof to bytes.
pub fn serialize_surjection_proof(proof: &SurjectionProof) -> Vec<u8> {
    proof.serialize()
}

/// Deserialize a surjection proof from bytes.
pub fn deserialize_surjection_proof(bytes: &[u8]) -> Result<SurjectionProof> {
    SurjectionProof::from_slice(bytes)
        .map_err(|e| HathorCtError::SurjectionProofError(format!("failed to deserialize: {}", e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::derive_tag;

    fn random_blinded_tag(token_uid: &[u8; 32]) -> (Generator, Tag, Tweak) {
        let tag = derive_tag(token_uid).unwrap();
        let bf = Tweak::new(&mut rand::thread_rng());
        let blinded = Generator::new_blinded(SECP256K1, tag, bf);
        (blinded, tag, bf)
    }

    #[test]
    fn test_surjection_1_input() {
        let uid = [1u8; 32];
        let (domain_gen, domain_tag, domain_bf) = random_blinded_tag(&uid);

        // Same token for codomain
        let codomain_tag = domain_tag;
        let codomain_bf = Tweak::new(&mut rand::thread_rng());
        let codomain_gen = Generator::new_blinded(SECP256K1, codomain_tag, codomain_bf);

        let proof = create_surjection_proof(
            &codomain_tag,
            &codomain_bf,
            &[(domain_gen, domain_tag, domain_bf)],
        )
        .unwrap();

        assert!(verify_surjection_proof(&proof, &codomain_gen, &[domain_gen],).is_ok());
    }

    #[test]
    fn test_surjection_2_inputs() {
        let uid1 = [1u8; 32];
        let uid2 = [2u8; 32];
        let (d1_gen, d1_tag, d1_bf) = random_blinded_tag(&uid1);
        let (d2_gen, d2_tag, d2_bf) = random_blinded_tag(&uid2);

        // Output uses same token as first input
        let codomain_bf = Tweak::new(&mut rand::thread_rng());
        let codomain_gen = Generator::new_blinded(SECP256K1, d1_tag, codomain_bf);

        let proof = create_surjection_proof(
            &d1_tag,
            &codomain_bf,
            &[(d1_gen, d1_tag, d1_bf), (d2_gen, d2_tag, d2_bf)],
        )
        .unwrap();

        assert!(verify_surjection_proof(&proof, &codomain_gen, &[d1_gen, d2_gen],).is_ok());
    }

    #[test]
    fn test_surjection_5_inputs() {
        let mut domain = Vec::new();
        let mut domain_gens = Vec::new();
        for i in 0..5u8 {
            let mut uid = [0u8; 32];
            uid[0] = i;
            let (gen, tag, bf) = random_blinded_tag(&uid);
            domain.push((gen, tag, bf));
            domain_gens.push(gen);
        }

        // Output uses token at index 2
        let codomain_tag = domain[2].1;
        let codomain_bf = Tweak::new(&mut rand::thread_rng());
        let codomain_gen = Generator::new_blinded(SECP256K1, codomain_tag, codomain_bf);

        let proof = create_surjection_proof(&codomain_tag, &codomain_bf, &domain).unwrap();

        assert!(verify_surjection_proof(&proof, &codomain_gen, &domain_gens).is_ok());
    }

    #[test]
    fn test_wrong_output_fails() {
        let uid1 = [1u8; 32];
        let uid2 = [2u8; 32];
        let (d1_gen, d1_tag, d1_bf) = random_blinded_tag(&uid1);

        // Create proof for token 1
        let codomain_bf = Tweak::new(&mut rand::thread_rng());

        let proof =
            create_surjection_proof(&d1_tag, &codomain_bf, &[(d1_gen, d1_tag, d1_bf)]).unwrap();

        // Verify with a different codomain generator (wrong token)
        let wrong_tag = derive_tag(&uid2).unwrap();
        let wrong_gen = Generator::new_blinded(SECP256K1, wrong_tag, codomain_bf);
        assert!(verify_surjection_proof(&proof, &wrong_gen, &[d1_gen]).is_err());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let uid = [1u8; 32];
        let (d_gen, d_tag, d_bf) = random_blinded_tag(&uid);
        let codomain_bf = Tweak::new(&mut rand::thread_rng());
        let codomain_gen = Generator::new_blinded(SECP256K1, d_tag, codomain_bf);

        let proof = create_surjection_proof(&d_tag, &codomain_bf, &[(d_gen, d_tag, d_bf)]).unwrap();

        let bytes = serialize_surjection_proof(&proof);
        let proof2 = deserialize_surjection_proof(&bytes).unwrap();
        assert!(verify_surjection_proof(&proof2, &codomain_gen, &[d_gen]).is_ok());
    }

    #[test]
    fn test_empty_domain_fails() {
        let uid = [1u8; 32];
        let tag = derive_tag(&uid).unwrap();
        let bf = Tweak::new(&mut rand::thread_rng());

        let result = create_surjection_proof(&tag, &bf, &[]);
        assert!(result.is_err());
    }
}
