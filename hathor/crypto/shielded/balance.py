"""Balance verification helpers wrapping the native Rust library."""

from hathor.crypto.shielded._bindings import _lib


def verify_balance(
    transparent_inputs: list[tuple[int, bytes]],
    shielded_inputs: list[bytes],
    transparent_outputs: list[tuple[int, bytes]],
    shielded_outputs: list[bytes],
) -> bool:
    """Verify the homomorphic balance equation.

    Args:
        transparent_inputs: List of (amount, token_uid_32B) for each transparent input.
        shielded_inputs: List of 33B commitment bytes for each shielded input.
        transparent_outputs: List of (amount, token_uid_32B) for each transparent output.
            Fee entries should be included here as transparent outputs.
        shielded_outputs: List of 33B commitment bytes for each shielded output.
    """
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.verify_balance(transparent_inputs, shielded_inputs, transparent_outputs, shielded_outputs)


def compute_balancing_blinding_factor(
    value: int,
    generator_blinding_factor: bytes,
    inputs: list[tuple[int, bytes, bytes]],
    other_outputs: list[tuple[int, bytes, bytes]],
) -> bytes:
    """Compute the balancing blinding factor for the last output.

    Args:
        value: The value for the last output.
        generator_blinding_factor: 32B blinding factor for the last output's generator.
        inputs: List of (value, vbf_32B, gbf_32B) for each input.
        other_outputs: List of (value, vbf_32B, gbf_32B) for each other output (not the last).
    """
    if _lib is None:
        raise RuntimeError('hathor_ct_crypto native library is not available')
    return _lib.compute_balancing_blinding_factor(value, generator_blinding_factor, inputs, other_outputs)
