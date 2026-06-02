"""Range proof + value commitment via grin_secp256k1zkp (original Bulletproofs).

This module is the grin-BP replacement for `hathor.crypto.shielded.range_proof`
+ `hathor.crypto.shielded.commitment`. The native binding crate `hathor_grin_bp`
is built from `poc-grin-bp-benchmark/hathor-grin-bp/` via maturin.

Unlike bppp (`poc-bppp-benchmark/`), grin_secp256k1zkp's `commit` uses the
fixed libsecp value generator `H` — the asset-blinded generator coming out of
`hathor.crypto.shielded.asset_tag` is therefore not part of the value
commitment here. The function signatures keep the extra arguments (`generator`,
`message`, `nonce`) for parity with the Borromean range-proof API, but
`generator` and `message` are ignored. `nonce`, if supplied, is reused as both
rewind and private nonce — that's benchmark-only behavior.
"""

import hathor_grin_bp


def create_commitment(amount: int, blinding: bytes, generator: bytes | None = None) -> bytes:
    """Grin Pedersen value commitment: `amount*H + blinding*G` on secp256k1's H.

    `generator` is accepted for signature parity with the Pedersen commitment
    helper in hathor.crypto.shielded.commitment, but it is not used — grin's
    `commit` pins libsecp's `H`.
    """
    return hathor_grin_bp.create_commitment(amount, blinding, generator)


def create_range_proof(
    amount: int,
    blinding: bytes,
    commitment: bytes | None = None,
    generator: bytes | None = None,
    message: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Single-output original Bulletproof range proof for `amount`.

    The extra positional arguments (commitment / generator / message) are
    accepted for compatibility with the secp256k1-zkp `create_range_proof`
    signature so the existing benchmark scripts can call this with minimal
    edits. They are ignored by this wrapper.
    """
    return hathor_grin_bp.create_range_proof(
        amount, blinding, commitment, generator, message, nonce,
    )


def verify_range_proof(
    proof: bytes,
    commitment: bytes,
    generator: bytes | None = None,
) -> bool:
    """Verify a single Bulletproof against `commitment`."""
    return hathor_grin_bp.verify_range_proof(proof, commitment, generator)


def batch_verify_range_proofs(proofs: list[bytes], commitments: list[bytes]) -> bool:
    """Real batched verify: one `verify_bullet_proof_multi` call across all
    (commitment, proof) pairs. This is the function the in-tree
    `hathor-ct-crypto/src/rangeproof.rs:batch_verify_range_proofs` only
    pretends to be — there it is a sequential loop with no aggregation.
    """
    return hathor_grin_bp.batch_verify_range_proofs(proofs, commitments)


def multi_create_proofs(amounts: list[int], blindings: list[bytes]) -> list[bytes]:
    """Serial create of K single-output proofs.

    NOT an aggregated multi-output proof — see hathor-grin-bp/src/lib.rs for
    the rationale. This is the baseline against which `batch_verify_range_proofs`
    measures its speedup.
    """
    return hathor_grin_bp.multi_create_proofs(amounts, blindings)


def proof_size_bytes() -> int:
    """Diagnostic: byte length of one proof for amount=2^60."""
    return hathor_grin_bp.proof_size_bytes()
