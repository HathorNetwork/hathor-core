from typing import Sequence


def sum_as_string(a: int, b: int) -> str:
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
