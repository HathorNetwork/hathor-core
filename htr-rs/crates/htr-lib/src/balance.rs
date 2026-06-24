use secp256k1_zkp::{
    CommitmentSecrets, PedersenCommitment, SECP256K1, Tweak, ZERO_TWEAK,
    compute_adaptive_blinding_factor, verify_commitments_sum_to_equal,
};

use crate::error::{HathorCtError, Result};

/// An entry in the balance equation, either transparent or shielded.
#[derive(Clone, Debug)]
pub enum BalanceEntry {
    /// A transparent input/output with known amount and token.
    Transparent { amount: u64, token_uid: [u8; 32] },
    /// A shielded input/output represented by its Pedersen commitment.
    Shielded {
        value_commitment: PedersenCommitment,
    },
}

/// Verify the homomorphic balance equation:
///
/// `sum(C_in) = sum(C_out) + excess*G`  (when `excess_blinding_factor` is `Some`)
/// `sum(C_in) = sum(C_out)`              (otherwise)
///
/// Transparent entries are converted to trivial (unblinded) commitments.
/// Fees should be included as transparent output entries by the caller.
///
/// `excess_blinding_factor`: used for full-unshield transactions (shielded inputs,
/// no shielded outputs). The sender reveals `excess = sum(r_in) − sum(r_out)` and
/// the verifier adds a synthetic `0*H + excess*G` to the output side so the
/// equation can balance.
///
/// This function performs **only** the cryptographic check; the caller is
/// responsible for enforcing the transaction-structure invariant that a tx must
/// have either shielded outputs or an excess blinding factor, but not both.
/// That invariant requires knowledge of the tx header layout, which lives in
/// the Python layer.
///
/// Privacy note: revealing `excess` leaks a scalar on `G`. With exactly one
/// shielded input this is effectively `r_in` of that input, but the transparent
/// outputs of a full unshield already disclose the spent amount, so nothing
/// previously-private is additionally exposed. With two or more shielded inputs
/// only the sum of their blinding factors is revealed; individual input amounts
/// remain confidential.
pub fn verify_balance(
    inputs: &[BalanceEntry],
    outputs: &[BalanceEntry],
    excess_blinding_factor: Option<Tweak>,
) -> Result<()> {
    let mut positive_commitments = Vec::new();
    let mut negative_commitments = Vec::new();

    // Collect input commitments (positive side)
    for entry in inputs {
        match entry {
            BalanceEntry::Transparent { amount, token_uid } => {
                if *amount == 0 {
                    continue; // Skip zero-value entries (e.g. authority outputs)
                }
                let generator = crate::generators::derive_asset_tag(token_uid)?;
                let c = PedersenCommitment::new_unblinded(SECP256K1, *amount, generator);
                positive_commitments.push(c);
            }
            BalanceEntry::Shielded { value_commitment } => {
                positive_commitments.push(*value_commitment);
            }
        }
    }

    // Collect output commitments (negative side)
    for entry in outputs {
        match entry {
            BalanceEntry::Transparent { amount, token_uid } => {
                if *amount == 0 {
                    continue; // Skip zero-value entries (e.g. authority outputs)
                }
                let generator = crate::generators::derive_asset_tag(token_uid)?;
                let c = PedersenCommitment::new_unblinded(SECP256K1, *amount, generator);
                negative_commitments.push(c);
            }
            BalanceEntry::Shielded { value_commitment } => {
                negative_commitments.push(*value_commitment);
            }
        }
    }

    // Excess blinding factor: synthesise `0*H + bf*G` on the negative side. The
    // generator is irrelevant when value == 0 (0 * genr = identity), so any asset
    // tag works.
    //
    // When bf itself is zero the commitment is the identity point, which
    // libsecp256k1 refuses to serialize (the inner FFI returns 0 and
    // PedersenCommitment::new panics). The contribution is also trivially zero,
    // so skip it. This case arises legitimately whenever sum(r_in) = 0 — for
    // example when a recipient spends together all shielded outputs of a
    // transparent-funded shielding tx, whose vbfs sum to zero by construction.
    if let Some(bf) = excess_blinding_factor
        && bf != ZERO_TWEAK
    {
        let genr = crate::generators::htr_asset_tag();
        let excess_commitment = PedersenCommitment::new(SECP256K1, 0, bf, genr);
        negative_commitments.push(excess_commitment);
    }

    // If both sides are empty (all entries were zero-valued and skipped), the balance
    // is trivially satisfied: 0 == 0. This happens for transactions with no shielded data
    // and only zero-value transparent entries (e.g. authority-only).
    // However, reject asymmetric cases where only one side has commitments.
    if positive_commitments.is_empty() != negative_commitments.is_empty() {
        return Err(HathorCtError::BalanceError(
            "commitment balance verification failed: one side has commitments but the other is empty".into(),
        ));
    }
    if positive_commitments.is_empty() && negative_commitments.is_empty() {
        return Ok(());
    }

    // Verify: sum(positive) == sum(negative)
    if !verify_commitments_sum_to_equal(SECP256K1, &positive_commitments, &negative_commitments) {
        return Err(HathorCtError::BalanceError(
            "commitment balance verification failed: inputs != outputs".into(),
        ));
    }

    Ok(())
}

/// Compute the balancing blinding factor for the last output.
///
/// Given all input blinding factors and all output blinding factors except the last,
/// compute the last output blinding factor so the balance equation holds.
///
/// Uses secp256k1-zkp's `compute_adaptive_blinding_factor`.
pub fn compute_balancing_blinding_factor(
    value: u64,
    generator_blinding_factor: &Tweak,
    inputs: &[(u64, Tweak, Tweak)], // (value, value_bf, generator_bf)
    other_outputs: &[(u64, Tweak, Tweak)], // (value, value_bf, generator_bf) for outputs except last
) -> Result<Tweak> {
    let set_a: Vec<CommitmentSecrets> = inputs
        .iter()
        .map(|(v, vbf, gbf)| CommitmentSecrets::new(*v, *vbf, *gbf))
        .collect();

    let set_b: Vec<CommitmentSecrets> = other_outputs
        .iter()
        .map(|(v, vbf, gbf)| CommitmentSecrets::new(*v, *vbf, *gbf))
        .collect();

    let result = compute_adaptive_blinding_factor(
        SECP256K1,
        value,
        *generator_blinding_factor,
        &set_a,
        &set_b,
    );

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::generators::{derive_asset_tag, htr_asset_tag, htr_tag};
    use crate::pedersen::create_commitment;
    use secp256k1_zkp::ZERO_TWEAK;

    const CUSTOM_TOKEN_UID: [u8; 32] = [7u8; 32];
    const HTR_UID: [u8; 32] = [0u8; 32];

    #[test]
    fn test_transparent_only_balance() {
        let htr = [0u8; 32];
        let inputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: htr,
        }];
        let outputs = vec![
            BalanceEntry::Transparent {
                amount: 900,
                token_uid: htr,
            },
            BalanceEntry::Transparent {
                amount: 100,
                token_uid: htr,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    #[test]
    fn test_transparent_balance_mismatch() {
        let htr = [0u8; 32];
        let inputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: htr,
        }];
        let outputs = vec![
            BalanceEntry::Transparent {
                amount: 800,
                token_uid: htr,
            },
            BalanceEntry::Transparent {
                amount: 100,
                token_uid: htr,
            },
        ];

        // 1000 != 800 + 100
        assert!(verify_balance(&inputs, &outputs, None).is_err());
    }

    #[test]
    fn test_shielded_only_balance() {
        // With same blinding factor and same amount, balance holds
        let genr = htr_asset_tag();
        let bf = Tweak::new(&mut rand::thread_rng());

        let c_in = create_commitment(1000, &bf, &genr).unwrap();
        let c_out = create_commitment(1000, &bf, &genr).unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![BalanceEntry::Shielded {
            value_commitment: c_out,
        }];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    #[test]
    fn test_mixed_transparent_shielded_unblinded() {
        // Transparent input = unblinded commitment
        // If shielded output also unblinded, they should match
        let genr = htr_asset_tag();
        let c_out = PedersenCommitment::new_unblinded(SECP256K1, 1000, genr);

        let inputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: [0u8; 32],
        }];
        let outputs = vec![BalanceEntry::Shielded {
            value_commitment: c_out,
        }];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    #[test]
    fn test_multi_token_transparent() {
        let htr = [0u8; 32];
        let token1 = [1u8; 32];

        let inputs = vec![
            BalanceEntry::Transparent {
                amount: 500,
                token_uid: htr,
            },
            BalanceEntry::Transparent {
                amount: 300,
                token_uid: token1,
            },
        ];
        let outputs = vec![
            BalanceEntry::Transparent {
                amount: 400,
                token_uid: htr,
            },
            BalanceEntry::Transparent {
                amount: 300,
                token_uid: token1,
            },
            BalanceEntry::Transparent {
                amount: 100,
                token_uid: htr,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    #[test]
    fn test_compute_balancing_factor() {
        let _tag = htr_tag();
        let genr = htr_asset_tag();

        // Input: 1000 with some blinding factor
        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        // Output 1: 600 with some blinding factor
        let vbf_out1 = Tweak::new(&mut rand::thread_rng());
        let c_out1 = create_commitment(600, &vbf_out1, &genr).unwrap();

        // Output 2: 400 with balancing blinding factor
        let vbf_out2 = compute_balancing_blinding_factor(
            400,
            &ZERO_TWEAK,
            &[(1000, vbf_in, ZERO_TWEAK)],
            &[(600, vbf_out1, ZERO_TWEAK)],
        )
        .unwrap();

        let c_out2 = create_commitment(400, &vbf_out2, &genr).unwrap();

        // Verify balance
        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![
            BalanceEntry::Shielded {
                value_commitment: c_out1,
            },
            BalanceEntry::Shielded {
                value_commitment: c_out2,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    #[test]
    fn test_compute_balancing_factor_with_fee() {
        let htr = [0u8; 32];
        let genr = htr_asset_tag();

        // Input: 1000 with some blinding factor
        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        // Fee: 100 (as transparent output entry)
        // Output: 900 with balancing blinding factor
        // Balance: C_in = C_out + C_fee
        //   1000*H + vbf_in*G = 900*H + vbf_out*G + 100*H + 0*G
        //   vbf_in = vbf_out
        let vbf_out = compute_balancing_blinding_factor(
            900,
            &ZERO_TWEAK,
            &[(1000, vbf_in, ZERO_TWEAK)],
            &[], // no other outputs
        )
        .unwrap();

        let c_out = create_commitment(900, &vbf_out, &genr).unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![
            BalanceEntry::Shielded {
                value_commitment: c_out,
            },
            BalanceEntry::Transparent {
                amount: 100,
                token_uid: htr,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    // Full unshield without excess blinding factor: shielded input(s) -> transparent
    // output(s), no shielded outputs, no excess. Values match but sum(r_in)*G has no
    // counterpart — rejected. The tx layer must supply the excess on full unshields.
    #[test]
    fn test_full_unshield_to_transparent_without_excess_is_rejected() {
        let htr = [0u8; 32];
        let genr = htr_asset_tag();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: htr,
        }];

        assert!(verify_balance(&inputs, &outputs, None).is_err());
    }

    // Same shape, with a transparent fee: 1000 shielded in -> 900 transparent out + 100 fee.
    // Without excess, also rejected.
    #[test]
    fn test_full_unshield_to_transparent_with_fee_without_excess_is_rejected() {
        let genr = htr_asset_tag();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![
            BalanceEntry::Transparent {
                amount: 900,
                token_uid: HTR_UID,
            },
            BalanceEntry::Transparent {
                amount: 100,
                token_uid: HTR_UID,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, None).is_err());
    }

    // Full unshield variant — only custom tokens (no HTR involved). Rejected without excess.
    #[test]
    fn test_full_unshield_custom_token_only_without_excess_is_rejected() {
        let genr = derive_asset_tag(&CUSTOM_TOKEN_UID).unwrap();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: CUSTOM_TOKEN_UID,
        }];

        assert!(verify_balance(&inputs, &outputs, None).is_err());
    }

    // Full unshield variant — HTR + custom token in the same tx. Rejected without excess.
    #[test]
    fn test_full_unshield_htr_and_custom_token_without_excess_is_rejected() {
        let htr_gen = htr_asset_tag();
        let custom_gen = derive_asset_tag(&CUSTOM_TOKEN_UID).unwrap();

        let vbf_htr = Tweak::new(&mut rand::thread_rng());
        let vbf_custom = Tweak::new(&mut rand::thread_rng());
        let c_in_htr = create_commitment(500, &vbf_htr, &htr_gen).unwrap();
        let c_in_custom = create_commitment(300, &vbf_custom, &custom_gen).unwrap();

        let inputs = vec![
            BalanceEntry::Shielded {
                value_commitment: c_in_htr,
            },
            BalanceEntry::Shielded {
                value_commitment: c_in_custom,
            },
        ];
        let outputs = vec![
            BalanceEntry::Transparent {
                amount: 500,
                token_uid: HTR_UID,
            },
            BalanceEntry::Transparent {
                amount: 300,
                token_uid: CUSTOM_TOKEN_UID,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, None).is_err());
    }

    // Full unshield variant — hybrid inputs (transparent + shielded), no shielded output.
    // Rejected without excess.
    #[test]
    fn test_full_unshield_hybrid_inputs_without_excess_is_rejected() {
        let genr = htr_asset_tag();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_shielded_in = create_commitment(500, &vbf_in, &genr).unwrap();

        let inputs = vec![
            BalanceEntry::Transparent {
                amount: 500,
                token_uid: HTR_UID,
            },
            BalanceEntry::Shielded {
                value_commitment: c_shielded_in,
            },
        ];
        let outputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: HTR_UID,
        }];

        assert!(verify_balance(&inputs, &outputs, None).is_err());
    }

    // --- Full-unshield PASSING cases: same shapes as the rejected tests above,
    // but the sender supplies `excess_blinding_factor = sum(r_in) - sum(r_out)`. ---

    #[test]
    fn test_full_unshield_to_transparent_with_excess() {
        let genr = htr_asset_tag();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        // excess = sum(r_in) - sum(r_out) = vbf_in - 0 = vbf_in.
        let excess = compute_balancing_blinding_factor(
            0,
            &ZERO_TWEAK,
            &[(1000, vbf_in, ZERO_TWEAK)],
            &[(1000, ZERO_TWEAK, ZERO_TWEAK)],
        )
        .unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: HTR_UID,
        }];

        assert!(verify_balance(&inputs, &outputs, Some(excess)).is_ok());
    }

    #[test]
    fn test_full_unshield_to_transparent_with_fee_with_excess() {
        let genr = htr_asset_tag();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        let excess = compute_balancing_blinding_factor(
            0,
            &ZERO_TWEAK,
            &[(1000, vbf_in, ZERO_TWEAK)],
            &[(900, ZERO_TWEAK, ZERO_TWEAK), (100, ZERO_TWEAK, ZERO_TWEAK)],
        )
        .unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![
            BalanceEntry::Transparent {
                amount: 900,
                token_uid: HTR_UID,
            },
            BalanceEntry::Transparent {
                amount: 100,
                token_uid: HTR_UID,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, Some(excess)).is_ok());
    }

    #[test]
    fn test_full_unshield_custom_token_only_with_excess() {
        let genr = derive_asset_tag(&CUSTOM_TOKEN_UID).unwrap();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        let excess = compute_balancing_blinding_factor(
            0,
            &ZERO_TWEAK,
            &[(1000, vbf_in, ZERO_TWEAK)],
            &[(1000, ZERO_TWEAK, ZERO_TWEAK)],
        )
        .unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: CUSTOM_TOKEN_UID,
        }];

        assert!(verify_balance(&inputs, &outputs, Some(excess)).is_ok());
    }

    #[test]
    fn test_full_unshield_htr_and_custom_token_with_excess() {
        let htr_gen = htr_asset_tag();
        let custom_gen = derive_asset_tag(&CUSTOM_TOKEN_UID).unwrap();

        let vbf_htr = Tweak::new(&mut rand::thread_rng());
        let vbf_custom = Tweak::new(&mut rand::thread_rng());
        let c_in_htr = create_commitment(500, &vbf_htr, &htr_gen).unwrap();
        let c_in_custom = create_commitment(300, &vbf_custom, &custom_gen).unwrap();

        // Excess = vbf_htr + vbf_custom (sum of input blinding factors).
        let excess = compute_balancing_blinding_factor(
            0,
            &ZERO_TWEAK,
            &[(500, vbf_htr, ZERO_TWEAK), (300, vbf_custom, ZERO_TWEAK)],
            &[(500, ZERO_TWEAK, ZERO_TWEAK), (300, ZERO_TWEAK, ZERO_TWEAK)],
        )
        .unwrap();

        let inputs = vec![
            BalanceEntry::Shielded {
                value_commitment: c_in_htr,
            },
            BalanceEntry::Shielded {
                value_commitment: c_in_custom,
            },
        ];
        let outputs = vec![
            BalanceEntry::Transparent {
                amount: 500,
                token_uid: HTR_UID,
            },
            BalanceEntry::Transparent {
                amount: 300,
                token_uid: CUSTOM_TOKEN_UID,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, Some(excess)).is_ok());
    }

    #[test]
    fn test_full_unshield_hybrid_inputs_with_excess() {
        let genr = htr_asset_tag();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_shielded_in = create_commitment(500, &vbf_in, &genr).unwrap();

        // Only the shielded input has a non-zero blinding factor; excess = vbf_in.
        let excess = compute_balancing_blinding_factor(
            0,
            &ZERO_TWEAK,
            &[(500, ZERO_TWEAK, ZERO_TWEAK), (500, vbf_in, ZERO_TWEAK)],
            &[(1000, ZERO_TWEAK, ZERO_TWEAK)],
        )
        .unwrap();

        let inputs = vec![
            BalanceEntry::Transparent {
                amount: 500,
                token_uid: HTR_UID,
            },
            BalanceEntry::Shielded {
                value_commitment: c_shielded_in,
            },
        ];
        let outputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: HTR_UID,
        }];

        assert!(verify_balance(&inputs, &outputs, Some(excess)).is_ok());
    }

    // Wrong excess (any non-matching scalar) is rejected.
    #[test]
    fn test_full_unshield_with_wrong_excess_is_rejected() {
        let genr = htr_asset_tag();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        let wrong_excess = Tweak::new(&mut rand::thread_rng());

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: HTR_UID,
        }];

        assert!(verify_balance(&inputs, &outputs, Some(wrong_excess)).is_err());
    }

    // Full unshield where sum(r_in) = 0 by construction. Spending together all
    // shielded outputs of a transparent-funded shielding tx forces the excess
    // to be ZERO_TWEAK. `0*H + 0*G` is the identity point and libsecp256k1
    // refuses to build it; the verifier must accept zero excess by skipping
    // the synthetic commitment rather than panicking.
    #[test]
    fn test_full_unshield_with_zero_excess() {
        let genr = htr_asset_tag();

        // Simulate the prior transparent-funded shielding tx's outputs: two
        // shielded outputs totalling 1000, whose vbfs sum to zero.
        let vbf_a = Tweak::new(&mut rand::thread_rng());
        let vbf_b = compute_balancing_blinding_factor(
            400,
            &ZERO_TWEAK,
            &[(1000, ZERO_TWEAK, ZERO_TWEAK)],
            &[(600, vbf_a, ZERO_TWEAK)],
        )
        .unwrap();

        let c_a = create_commitment(600, &vbf_a, &genr).unwrap();
        let c_b = create_commitment(400, &vbf_b, &genr).unwrap();

        let inputs = vec![
            BalanceEntry::Shielded {
                value_commitment: c_a,
            },
            BalanceEntry::Shielded {
                value_commitment: c_b,
            },
        ];
        let outputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: HTR_UID,
        }];

        assert!(verify_balance(&inputs, &outputs, Some(ZERO_TWEAK)).is_ok());
    }

    // --- Non-bug coverage: these must remain green after the fix lands. ---

    // Shielding: transparent input -> (unblinded) shielded output, custom token.
    // Mirrors the existing HTR variant (`test_mixed_transparent_shielded_unblinded`).
    #[test]
    fn test_shield_custom_token_unblinded() {
        let genr = derive_asset_tag(&CUSTOM_TOKEN_UID).unwrap();
        let c_out = PedersenCommitment::new_unblinded(SECP256K1, 1000, genr);

        let inputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: CUSTOM_TOKEN_UID,
        }];
        let outputs = vec![BalanceEntry::Shielded {
            value_commitment: c_out,
        }];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    // Partial unshield on a custom token: shielded custom -> shielded custom + transparent custom fee.
    // Sender uses compute_balancing_blinding_factor to match vbf on the remaining shielded output.
    #[test]
    fn test_partial_unshield_custom_token() {
        let genr = derive_asset_tag(&CUSTOM_TOKEN_UID).unwrap();

        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &genr).unwrap();

        let vbf_out =
            compute_balancing_blinding_factor(900, &ZERO_TWEAK, &[(1000, vbf_in, ZERO_TWEAK)], &[])
                .unwrap();
        let c_out = create_commitment(900, &vbf_out, &genr).unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![
            BalanceEntry::Shielded {
                value_commitment: c_out,
            },
            BalanceEntry::Transparent {
                amount: 100,
                token_uid: CUSTOM_TOKEN_UID,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    // Hybrid inputs -> single shielded output. The shielded output absorbs the
    // shielded input's blinding factor via compute_balancing_blinding_factor.
    #[test]
    fn test_hybrid_inputs_to_shielded_output() {
        let genr = htr_asset_tag();

        let vbf_shielded_in = Tweak::new(&mut rand::thread_rng());
        let c_shielded_in = create_commitment(500, &vbf_shielded_in, &genr).unwrap();

        let vbf_out = compute_balancing_blinding_factor(
            1000,
            &ZERO_TWEAK,
            &[
                (500, ZERO_TWEAK, ZERO_TWEAK),
                (500, vbf_shielded_in, ZERO_TWEAK),
            ],
            &[],
        )
        .unwrap();
        let c_out = create_commitment(1000, &vbf_out, &genr).unwrap();

        let inputs = vec![
            BalanceEntry::Transparent {
                amount: 500,
                token_uid: HTR_UID,
            },
            BalanceEntry::Shielded {
                value_commitment: c_shielded_in,
            },
        ];
        let outputs = vec![BalanceEntry::Shielded {
            value_commitment: c_out,
        }];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    // Hybrid inputs -> hybrid outputs. Most general passing shape:
    // transparent + shielded in, transparent + shielded out. The single shielded
    // output carries the balancing blinding factor.
    #[test]
    fn test_hybrid_inputs_to_hybrid_outputs() {
        let genr = htr_asset_tag();

        let vbf_shielded_in = Tweak::new(&mut rand::thread_rng());
        let c_shielded_in = create_commitment(500, &vbf_shielded_in, &genr).unwrap();

        let vbf_out = compute_balancing_blinding_factor(
            700,
            &ZERO_TWEAK,
            &[
                (500, ZERO_TWEAK, ZERO_TWEAK),
                (500, vbf_shielded_in, ZERO_TWEAK),
            ],
            &[],
        )
        .unwrap();
        let c_shielded_out = create_commitment(700, &vbf_out, &genr).unwrap();

        let inputs = vec![
            BalanceEntry::Transparent {
                amount: 500,
                token_uid: HTR_UID,
            },
            BalanceEntry::Shielded {
                value_commitment: c_shielded_in,
            },
        ];
        let outputs = vec![
            BalanceEntry::Shielded {
                value_commitment: c_shielded_out,
            },
            BalanceEntry::Transparent {
                amount: 300,
                token_uid: HTR_UID,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }

    // Multi-token partial unshield with hybrid outputs: HTR is fully unshielded
    // (no HTR-side shielded output) while the custom token keeps a shielded output
    // that absorbs the total blinding factor across both tokens (vbfs sum on a
    // single G, independent of per-token generators).
    #[test]
    fn test_multi_token_hybrid_outputs() {
        let htr_gen = htr_asset_tag();
        let custom_gen = derive_asset_tag(&CUSTOM_TOKEN_UID).unwrap();

        let vbf_htr_in = Tweak::new(&mut rand::thread_rng());
        let vbf_custom_in = Tweak::new(&mut rand::thread_rng());
        let c_htr_in = create_commitment(500, &vbf_htr_in, &htr_gen).unwrap();
        let c_custom_in = create_commitment(300, &vbf_custom_in, &custom_gen).unwrap();

        // Sole shielded output is a custom-token 300 commitment whose vbf_out
        // absorbs both vbf_htr_in + vbf_custom_in.
        let vbf_custom_out = compute_balancing_blinding_factor(
            300,
            &ZERO_TWEAK,
            &[
                (500, vbf_htr_in, ZERO_TWEAK),
                (300, vbf_custom_in, ZERO_TWEAK),
            ],
            &[],
        )
        .unwrap();
        let c_custom_out = create_commitment(300, &vbf_custom_out, &custom_gen).unwrap();

        let inputs = vec![
            BalanceEntry::Shielded {
                value_commitment: c_htr_in,
            },
            BalanceEntry::Shielded {
                value_commitment: c_custom_in,
            },
        ];
        let outputs = vec![
            BalanceEntry::Transparent {
                amount: 500,
                token_uid: HTR_UID,
            },
            BalanceEntry::Shielded {
                value_commitment: c_custom_out,
            },
        ];

        assert!(verify_balance(&inputs, &outputs, None).is_ok());
    }
}
