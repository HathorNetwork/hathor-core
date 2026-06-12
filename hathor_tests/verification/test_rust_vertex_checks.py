#  Copyright 2026 Hathor Labs
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

"""Check-level differential fuzz for the Rust stateless checks (htr_lib.verify_outputs,
verify_output_token_indexes, verify_pow) against the authoritative Python verifier implementations.
Service-level end-to-end coverage lives in test_rust_verification_service.py."""

import math
from types import SimpleNamespace
from typing import Callable

import htr_lib
from hypothesis import HealthCheck, given, settings as hypothesis_settings, strategies as st

from hathor.conf.get_settings import get_global_settings
from hathor.reactor import get_global_reactor
from hathor.transaction import Transaction, TxOutput
from hathor.verification.transaction_verifier import TransactionVerifier
from hathor.verification.vertex_verifier import VertexVerifier

FUZZ = hypothesis_settings(max_examples=400, deadline=None, derandomize=True,
                           suppress_health_check=[HealthCheck.too_slow])

OutputFields = tuple[int, int, int]  # (value, script_len, token_data)


def _make_output(value: int, script_len: int, token_data: int) -> TxOutput:
    # Bypass any constructor validation: the differential must cover values the constructor
    # would reject but a hand-crafted vertex could still carry.
    output = TxOutput(1, b'')
    output.value = value
    output.script = b'\x00' * script_len
    output.token_data = token_data
    return output


def _outcome(fn: Callable[[], None]) -> str:
    try:
        fn()
        return 'valid'
    except BaseException as e:
        return type(e).__name__


def _python_vertex_verifier() -> VertexVerifier:
    return VertexVerifier(
        reactor=get_global_reactor(), settings=get_global_settings(),
        feature_service=None,  # type: ignore[arg-type]  # unused by these checks
    )


def _rust_kind(error: tuple[str, str] | None) -> str:
    return 'valid' if error is None else error[0]


def assert_equivalent_outputs(outputs_fields: list[OutputFields]) -> None:
    settings = get_global_settings()
    vertex = SimpleNamespace(outputs=[_make_output(*fields) for fields in outputs_fields])
    python = _outcome(lambda: _python_vertex_verifier().verify_outputs(vertex))  # type: ignore[arg-type]
    rust = _rust_kind(htr_lib.verify_outputs(
        [(value, script_len, token_data) for value, script_len, token_data in outputs_fields],
        settings.MAX_NUM_OUTPUTS,
        settings.MAX_OUTPUT_SCRIPT_SIZE,
    ))
    assert python == rust, f'{outputs_fields[:5]}...: python={python} rust={rust}'


def assert_equivalent_token_indexes(token_data_list: list[int], tokens_count: int) -> None:
    tx = SimpleNamespace(
        outputs=[_make_output(1, 0, token_data) for token_data in token_data_list],
        tokens=[bytes(32)] * tokens_count,
    )
    verifier = TransactionVerifier(
        settings=get_global_settings(), daa_factory=None, feature_service=None,  # type: ignore[arg-type]
    )
    python = _outcome(lambda: verifier.verify_output_token_indexes(tx))  # type: ignore[arg-type]
    rust = _rust_kind(htr_lib.verify_output_token_indexes(token_data_list, tokens_count))
    assert python == rust, f'{token_data_list}/{tokens_count}: python={python} rust={rust}'


def test_outputs_corpus() -> None:
    settings = get_global_settings()
    max_script = settings.MAX_OUTPUT_SCRIPT_SIZE
    cases: list[list[OutputFields]] = [
        [],
        [(100, 25, 0)],
        [(1, max_script, 0)],                      # script exactly at the limit
        [(1, max_script + 1, 0)],                  # one over
        [(0, 0, 0)],                               # zero value
        [(-5, 0, 0)],                              # negative value
        [(1, 0, 0x80)],                            # hathor authority
        [(1, 0, 0x81)],                            # custom-token authority (allowed here)
        [(1, 0, 0x7F)],                            # max token index, no authority
        [(1, 0, 0xFF)],                            # authority + max index
        [(0, 0, 0x80)],                            # authority check ordered before value check
        [(1, 0, 0), (0, 0, 0), (1, max_script + 1, 0)],   # first failure wins
        [(1, 0, 0)] * 255,                         # at the count limit
        [(1, 0, 0)] * 256,                         # over the count limit
        [(0, 0, 0)] * 256,                         # count check ordered before per-output checks
    ]
    for case in cases:
        assert_equivalent_outputs(case)


@FUZZ
@given(
    outputs=st.lists(
        st.tuples(
            st.integers(min_value=-2**62, max_value=2**62),
            st.integers(min_value=0, max_value=1100),
            st.integers(min_value=0, max_value=255),
        ),
        max_size=20,
    ),
)
def test_fuzz_outputs(outputs: list[OutputFields]) -> None:
    assert_equivalent_outputs(outputs)


def test_token_indexes_corpus() -> None:
    cases: list[tuple[list[int], int]] = [
        ([], 0),
        ([0], 0),
        ([1], 0),                  # index beyond empty tokens list
        ([0, 1, 2], 2),
        ([3], 2),
        ([0x80 | 2], 2),           # authority bit ignored for the index
        ([0x80 | 3], 2),
        ([0x7F], 2),               # max index
        ([0x7F], 127),             # max index, exactly enough tokens
    ]
    for token_data_list, tokens_count in cases:
        assert_equivalent_token_indexes(token_data_list, tokens_count)


@FUZZ
@given(
    token_data_list=st.lists(st.integers(min_value=0, max_value=255), max_size=20),
    tokens_count=st.integers(min_value=0, max_value=16),
)
def test_fuzz_token_indexes(token_data_list: list[int], tokens_count: int) -> None:
    assert_equivalent_token_indexes(token_data_list, tokens_count)


def _rust_pow_outcome(vertex_hash: bytes, target: int) -> str:
    """Mirror the marshalling: negative targets (float underflow at absurd weights) clamp to zero."""
    target = max(target, 0)
    target_bytes = target.to_bytes(max(1, (target.bit_length() + 7) // 8), 'big')
    return _rust_kind(htr_lib.verify_pow(vertex_hash, target_bytes))


def test_pow_weight_space() -> None:
    """Differential over the weight space, target computed by Python's get_target in both paths."""
    tx = Transaction(outputs=[TxOutput(1, b'\x51')])
    tx.update_hash()
    verifier = _python_vertex_verifier()
    # weight 0 -> target 2**256 (always passes); 256+ -> target 0 (always fails); 1500 -> float
    # underflow makes get_target return -1 (clamped to 0 in the rust marshalling); inf/nan ->
    # WeightError raised by get_target itself, identically on both paths.
    for weight in [0.0, 1.0, 60.0, 255.9, 256.0, 300.0, 1500.0, math.inf, math.nan]:
        tx.weight = weight
        python = _outcome(lambda: verifier.verify_pow(tx))
        try:
            target = tx.get_target()
        except BaseException as e:
            rust = type(e).__name__
        else:
            rust = _rust_pow_outcome(tx.hash, target)
        assert python == rust, f'weight={weight}: python={python} rust={rust}'


def test_pow_boundary() -> None:
    """Exact boundary semantics: hash must be strictly below the target."""
    hash_bytes = b'\xab' * 32
    hash_int = int.from_bytes(hash_bytes, 'big')
    for target, expect_error in [
        (hash_int + 1, False),    # hash < target: ok
        (hash_int, True),         # equal: rejected
        (hash_int - 1, True),     # above: rejected
        (2**256, False),          # max target accepts any hash
        (0, True),                # zero target rejects everything
        (-1, True),               # negative target (weight underflow) rejects everything
    ]:
        outcome = _rust_pow_outcome(hash_bytes, target)
        assert (outcome == 'PowError') == expect_error, f'target={target}: {outcome}'


@FUZZ
@given(hash_bytes=st.binary(min_size=32, max_size=32), weight=st.floats(min_value=0.0, max_value=300.0))
def test_fuzz_pow(hash_bytes: bytes, weight: float) -> None:
    """Random hash/weight pairs: the Rust comparison must equal Python's int comparison."""
    target = int(2 ** (256 - weight) - 1)
    rust = _rust_pow_outcome(hash_bytes, target)
    python = 'PowError' if int.from_bytes(hash_bytes, 'big') >= target else 'valid'
    assert rust == python
