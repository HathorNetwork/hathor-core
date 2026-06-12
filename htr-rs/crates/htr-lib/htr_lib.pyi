from typing import Sequence


def sum_as_string(a: int, b: int) -> str:
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


def count_sigops_inputs(
    pairs: Sequence[tuple[bytes, bytes]],
    max_multisig_pubkeys: int,
    enable_checkdatasig_count: bool,
    num_workers: int,
) -> list[tuple[tuple[str, str] | None, int]]:
    """Count sigops per (input_data, spent_output_script) pair (multisig redeem scripts are
    unwrapped). One (error, count) entry per pair, in order."""
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
