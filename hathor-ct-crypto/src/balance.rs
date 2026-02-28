use secp256k1_zkp::{
    compute_adaptive_blinding_factor, verify_commitments_sum_to_equal, CommitmentSecrets,
    PedersenCommitment, Tweak, SECP256K1,
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
/// `sum(C_in) = sum(C_out)`
///
/// Transparent entries are converted to trivial (unblinded) commitments.
/// Fees should be included as transparent output entries by the caller.
/// For the equation to balance, the builder must ensure blinding factors sum correctly.
pub fn verify_balance(inputs: &[BalanceEntry], outputs: &[BalanceEntry]) -> Result<()> {
    let mut positive_commitments = Vec::new();
    let mut negative_commitments = Vec::new();

    // Collect input commitments (positive side)
    for entry in inputs {
        match entry {
            BalanceEntry::Transparent { amount, token_uid } => {
                if *amount == 0 {
                    continue; // Skip zero-value entries (e.g. authority outputs) — VULN-010
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
                    continue; // Skip zero-value entries (e.g. authority outputs) — VULN-010
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
    use crate::generators::{htr_asset_tag, htr_tag};
    use crate::pedersen::create_commitment;
    use secp256k1_zkp::ZERO_TWEAK;

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

        assert!(verify_balance(&inputs, &outputs).is_ok());
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
        assert!(verify_balance(&inputs, &outputs).is_err());
    }

    #[test]
    fn test_shielded_only_balance() {
        // With same blinding factor and same amount, balance holds
        let gen = htr_asset_tag();
        let bf = Tweak::new(&mut rand::thread_rng());

        let c_in = create_commitment(1000, &bf, &gen).unwrap();
        let c_out = create_commitment(1000, &bf, &gen).unwrap();

        let inputs = vec![BalanceEntry::Shielded {
            value_commitment: c_in,
        }];
        let outputs = vec![BalanceEntry::Shielded {
            value_commitment: c_out,
        }];

        assert!(verify_balance(&inputs, &outputs).is_ok());
    }

    #[test]
    fn test_mixed_transparent_shielded_unblinded() {
        // Transparent input = unblinded commitment
        // If shielded output also unblinded, they should match
        let gen = htr_asset_tag();
        let c_out = PedersenCommitment::new_unblinded(SECP256K1, 1000, gen);

        let inputs = vec![BalanceEntry::Transparent {
            amount: 1000,
            token_uid: [0u8; 32],
        }];
        let outputs = vec![BalanceEntry::Shielded {
            value_commitment: c_out,
        }];

        assert!(verify_balance(&inputs, &outputs).is_ok());
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

        assert!(verify_balance(&inputs, &outputs).is_ok());
    }

    #[test]
    fn test_compute_balancing_factor() {
        let _tag = htr_tag();
        let gen = htr_asset_tag();

        // Input: 1000 with some blinding factor
        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &gen).unwrap();

        // Output 1: 600 with some blinding factor
        let vbf_out1 = Tweak::new(&mut rand::thread_rng());
        let c_out1 = create_commitment(600, &vbf_out1, &gen).unwrap();

        // Output 2: 400 with balancing blinding factor
        let vbf_out2 = compute_balancing_blinding_factor(
            400,
            &ZERO_TWEAK,
            &[(1000, vbf_in, ZERO_TWEAK)],
            &[(600, vbf_out1, ZERO_TWEAK)],
        )
        .unwrap();

        let c_out2 = create_commitment(400, &vbf_out2, &gen).unwrap();

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

        assert!(verify_balance(&inputs, &outputs).is_ok());
    }

    #[test]
    fn test_compute_balancing_factor_with_fee() {
        let htr = [0u8; 32];
        let gen = htr_asset_tag();

        // Input: 1000 with some blinding factor
        let vbf_in = Tweak::new(&mut rand::thread_rng());
        let c_in = create_commitment(1000, &vbf_in, &gen).unwrap();

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

        let c_out = create_commitment(900, &vbf_out, &gen).unwrap();

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

        assert!(verify_balance(&inputs, &outputs).is_ok());
    }
}
