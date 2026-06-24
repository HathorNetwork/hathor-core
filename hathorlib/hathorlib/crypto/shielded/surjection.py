"""Surjection proof helpers wrapping the native Rust library."""

from htr_lib import shielded as _lib


def create_surjection_proof(
    codomain_tag: bytes,
    codomain_blinding_factor: bytes,
    domain: list[tuple[bytes, bytes, bytes]],
) -> bytes:
    """Create a surjection proof.

    Args:
        codomain_tag: 32 bytes raw Tag for the output.
        codomain_blinding_factor: 32 bytes blinding factor for the output generator.
        domain: List of (blinded_generator_33B, raw_tag_32B, blinding_factor_32B) for each input.
    """
    return _lib.create_surjection_proof(codomain_tag, codomain_blinding_factor, domain)


def verify_surjection_proof(proof: bytes, codomain: bytes, domain: list[bytes]) -> bool:
    """Verify a surjection proof.

    Args:
        proof: The serialized surjection proof.
        codomain: 33 bytes blinded Generator for the output.
        domain: List of 33 bytes blinded Generators for each input.
    """
    return _lib.verify_surjection_proof(proof, codomain, domain)
