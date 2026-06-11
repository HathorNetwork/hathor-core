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
