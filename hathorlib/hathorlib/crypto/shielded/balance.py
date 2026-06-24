"""Balance verification helpers wrapping the native Rust library."""

from htr_lib import shielded as _lib


def verify_balance(
    transparent_inputs: list[tuple[int, bytes]],
    shielded_inputs: list[bytes],
    transparent_outputs: list[tuple[int, bytes]],
    shielded_outputs: list[bytes],
    excess_blinding_factor: bytes | None = None,
) -> bool:
    """Verify the homomorphic balance equation.

    Args:
        transparent_inputs: List of (amount, token_uid_32B) for each transparent input.
        shielded_inputs: List of 33B commitment bytes for each shielded input.
        transparent_outputs: List of (amount, token_uid_32B) for each transparent output.
            Fee entries should be included here as transparent outputs.
        shielded_outputs: List of 33B commitment bytes for each shielded output.
        excess_blinding_factor: Optional 32B scalar used on full-unshield txs to
            carry `sum(r_in) - sum(r_out)` to the output side. Mutually exclusive
            with `shielded_outputs`: must be None whenever there is at least one
            shielded output, and must be set whenever there are shielded inputs
            but no shielded outputs.
    """
    if excess_blinding_factor is not None:
        if shielded_outputs:
            raise ValueError('excess_blinding_factor must be None when shielded_outputs is non-empty')
        if not shielded_inputs:
            raise ValueError('excess_blinding_factor requires at least one shielded input')
        if len(excess_blinding_factor) != 32:
            raise ValueError('excess_blinding_factor must be 32 bytes')
    return _lib.verify_balance(
        transparent_inputs,
        shielded_inputs,
        transparent_outputs,
        shielded_outputs,
        excess_blinding_factor,
    )


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
    return _lib.compute_balancing_blinding_factor(value, generator_blinding_factor, inputs, other_outputs)
