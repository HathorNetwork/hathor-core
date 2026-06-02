"""Range proof + value commitment via distributed-lab/bp-pp (Bulletproofs++).

This module is the bppp replacement for `hathor.crypto.shielded.range_proof` +
`hathor.crypto.shielded.commitment`. The native binding crate `hathor_bppp` is
built from `poc-bppp-benchmark/hathor-bppp/` via maturin.

bppp uses its own base points (g, g_vec[16], h_vec[32]) so the externally-supplied
asset generator from the secp256k1-zkp pipeline is *not* part of the value
commitment here. The function signatures keep the extra arguments (`generator`,
`message`, `nonce`) for parity with the Borromean range proof API, but those
arguments are ignored — see the Rust source for the actual call shape.
"""

import hathor_bppp


def create_commitment(amount: int, blinding: bytes, generator: bytes | None = None) -> bytes:
    """bppp value commitment: `amount * g + blinding * h_vec[0]`.

    `generator` is accepted for signature parity with the Pedersen commitment
    helper in hathor.crypto.shielded.commitment, but it is not used: bppp pins
    its own base points.
    """
    return hathor_bppp.create_commitment(amount, blinding, generator)


def create_range_proof(
    amount: int,
    blinding: bytes,
    commitment: bytes | None = None,
    generator: bytes | None = None,
    message: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """bppp u64 range proof for `amount` with blinding `blinding`.

    The extra positional arguments (commitment / generator / message / nonce)
    are accepted for compatibility with the secp256k1-zkp `create_range_proof`
    signature so the existing benchmark scripts can call this with minimal edits.
    They are not consumed by bppp.
    """
    return hathor_bppp.create_range_proof(
        amount, blinding, commitment, generator, message, nonce,
    )


def verify_range_proof(
    proof: bytes,
    commitment: bytes,
    generator: bytes | None = None,
) -> bool:
    """Verify a bppp u64 range proof against the bppp `commitment`."""
    return hathor_bppp.verify_range_proof(proof, commitment, generator)


def commit_and_prove(amount: int, blinding: bytes) -> tuple[bytes, bytes]:
    """One-shot: returns `(commitment_bytes, proof_bytes)`. Convenience for the
    memory/bandwidth benchmarks where the commitment isn't built separately."""
    return hathor_bppp.commit_and_prove(amount, blinding)
