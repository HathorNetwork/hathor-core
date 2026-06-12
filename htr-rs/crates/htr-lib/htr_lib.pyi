from typing import Sequence


def sum_as_string(a: int, b: int) -> str:
    ...


def count_sigops_outputs(
    scripts: Sequence[bytes],
    max_multisig_pubkeys: int,
    enable_checkdatasig_count: bool,
) -> tuple[tuple[str, str] | None, int]:
    """Count signature operations over output scripts.

    Returns `(None, total)` on success, or `((kind, message), 0)` for the first malformed
    script, where `kind` is the Python exception class name the reference would raise.
    """
    ...


def verify_outputs(
    outputs: Sequence[tuple[int, int, int]],
    max_num_outputs: int,
    max_output_script_size: int,
) -> tuple[str, str] | None:
    """VertexVerifier.verify_outputs (incl. the number-of-outputs check) over marshalled
    `(value, script_len, token_data)` tuples. Returns `None` or `(kind, message)`."""
    ...


def verify_output_token_indexes(
    token_data_list: Sequence[int],
    tokens_count: int,
) -> tuple[str, str] | None:
    """TransactionVerifier.verify_output_token_indexes over the outputs' token_data bytes."""
    ...


def verify_pow(hash: bytes, target_be: bytes) -> tuple[str, str] | None:
    """VertexVerifier.verify_pow's comparison: hash (big-endian) must be strictly below the
    Python-computed target (minimal big-endian bytes)."""
    ...


def verify_vertex_stateless(
    checks: Sequence[int],
    data: object,
    num_workers: int,
) -> list[tuple[str, str] | None]:
    """Run the requested stateless checks for one vertex in a single GIL-released call (parallel
    on the shared rayon pool). One entry per requested check, in request order.

    `data` must expose the `StatelessVertexCheckData` fields as attributes (extracted by name).
    """
    ...


def verify_scripts_batch(
    jobs: Sequence[object],
    max_multisig_pubkeys: int,
    max_multisig_signatures: int,
    p2pkh_version_byte: bytes,
    num_workers: int,
) -> list[tuple[str, str] | None]:
    """Verify a batch of script jobs in parallel (GIL released), one result per job in order.

    Each job must expose the `ScriptVerificationJob` fields as attributes. A result of `None`
    means the script is valid; otherwise it is `(kind, message)` where `kind` is the Python
    exception class name the reference implementation would raise and `message` is debug-only.
    """
    ...
