def sum_as_string(a: int, b: int) -> str:
    ...


def bls_keygen(ikm: bytes) -> bytes:
    ...


def bls_sk_to_pk(secret_key: bytes) -> bytes:
    ...


def bls_pop_prove(secret_key: bytes) -> bytes:
    ...


def bls_pop_verify(public_key: bytes, pop: bytes) -> bool:
    ...


def bls_sign(secret_key: bytes, message: bytes) -> bytes:
    ...


def bls_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    ...


def bls_aggregate(signatures: list[bytes]) -> bytes:
    ...


def bls_fast_aggregate_verify(public_keys: list[bytes], message: bytes, aggregate_signature: bytes) -> bool:
    ...
