"""Type stubs for hathor_ct_crypto native module."""

from typing import Any

_lib: Any
AVAILABLE: bool

COMMITMENT_SIZE: int
GENERATOR_SIZE: int
ZERO_TWEAK: bytes

def derive_asset_tag(token_uid: bytes) -> bytes: ...
def htr_asset_tag() -> bytes: ...
def derive_tag(token_uid: bytes) -> bytes: ...
def create_asset_commitment(tag_bytes: bytes, r_asset: bytes) -> bytes: ...
def create_commitment(amount: int, blinding: bytes, generator: bytes) -> bytes: ...
def create_trivial_commitment(amount: int, generator: bytes) -> bytes: ...
def verify_commitments_sum(positive: list[bytes], negative: list[bytes]) -> bool: ...
def create_range_proof(
    amount: int,
    blinding: bytes,
    commitment: bytes,
    generator: bytes,
    message: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes: ...
def verify_range_proof(proof: bytes, commitment: bytes, generator: bytes) -> bool: ...
def rewind_range_proof(
    proof: bytes,
    commitment: bytes,
    nonce: bytes,
    generator: bytes,
) -> tuple[int, bytes, bytes]: ...
def create_surjection_proof(
    codomain_tag: bytes,
    codomain_blinding_factor: bytes,
    domain: list[tuple[bytes, bytes, bytes]],
) -> bytes: ...
def verify_surjection_proof(proof: bytes, codomain: bytes, domain: list[bytes]) -> bool: ...
def verify_balance(
    transparent_inputs: list[tuple[int, bytes]],
    shielded_inputs: list[bytes],
    transparent_outputs: list[tuple[int, bytes]],
    shielded_outputs: list[bytes],
) -> bool: ...
def compute_balancing_blinding_factor(
    value: int,
    generator_blinding_factor: bytes,
    inputs: list[tuple[int, bytes, bytes]],
    other_outputs: list[tuple[int, bytes, bytes]],
) -> bytes: ...
