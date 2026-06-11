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

"""Differential tests for the Rust sigops counter (htr_lib.count_sigops_outputs) against the authoritative
Python `SigopCounter`, plus end-to-end checks of `VertexVerifier.verify_sigops_output` under the rust and
shadow-rust executors."""

import htr_lib
from hypothesis import HealthCheck, given, settings as hypothesis_settings, strategies as st

from hathor.conf.get_settings import get_global_settings
from hathor.reactor import get_global_reactor
from hathor.transaction import Transaction, TxOutput
from hathor.transaction.exceptions import TooManySigOps
from hathor.transaction.scripts import SigopCounter
from hathor.verification.script_verification_pool import ScriptVerificationMode, ScriptVerificationPool
from hathor.verification.vertex_verifier import VertexVerifier

FUZZ = hypothesis_settings(max_examples=400, deadline=None, derandomize=True,
                           suppress_health_check=[HealthCheck.too_slow])

P2PKH_OUT = bytes.fromhex('76a914a390bb4d6d4ab570767ef21f66c3edc1a4d6902688ac')
MULTISIG_OUT = bytes.fromhex('a914435d1cb21e38a88634dfe325e1ec0fd5c98adc4387')


def python_outcome(script: bytes, *, enable_checkdatasig_count: bool = True) -> tuple[str, int]:
    """('valid', count) or (exception class name, 0) from the authoritative Python counter."""
    settings = get_global_settings()
    counter = SigopCounter(
        max_multisig_pubkeys=settings.MAX_MULTISIG_PUBKEYS,
        enable_checkdatasig_count=enable_checkdatasig_count,
    )
    try:
        return 'valid', counter.get_sigops_count(script)
    except BaseException as e:
        return type(e).__name__, 0


def rust_outcome(script: bytes, *, enable_checkdatasig_count: bool = True) -> tuple[str, int]:
    settings = get_global_settings()
    error, total = htr_lib.count_sigops_outputs(
        [script], settings.MAX_MULTISIG_PUBKEYS, enable_checkdatasig_count,
    )
    if error is not None:
        return error[0], 0
    return 'valid', total


def assert_scripts_equivalent(scripts: list[bytes]) -> None:
    mismatches = []
    for script in scripts:
        for enable_checkdatasig_count in (True, False):
            python = python_outcome(script, enable_checkdatasig_count=enable_checkdatasig_count)
            rust = rust_outcome(script, enable_checkdatasig_count=enable_checkdatasig_count)
            if python != rust:
                mismatches.append(
                    f'script={script.hex()} checkdatasig={enable_checkdatasig_count} '
                    f'python={python} rust={rust}'
                )
    assert not mismatches, 'Python/Rust sigops mismatches:\n' + '\n'.join(mismatches)


def test_corpus() -> None:
    scripts: list[bytes] = [
        b'',
        P2PKH_OUT,
        MULTISIG_OUT,
        b'\xac' * 5,                      # repeated OP_CHECKSIG
        b'\x53\xae',                      # OP_3 OP_CHECKMULTISIG -> 3
        b'\x50\xae',                      # OP_0 OP_CHECKMULTISIG -> 0
        b'\x60\xae',                      # OP_16 OP_CHECKMULTISIG -> 16
        b'\xae',                          # bare OP_CHECKMULTISIG -> max pubkeys
        b'\x01\xab\xae',                  # pushdata then multisig -> max pubkeys
        b'\x01\x53\xae',                  # OP_3 inside a push does not count
        b'\xba',                          # OP_CHECKDATASIG (counts only when enabled)
        b'\xba\xac\x53\xae',              # mixed
        b'\x04\x00\x00\x03\xe8\x6f' + P2PKH_OUT,   # timelocked p2pkh
        b'\x00',                          # invalid opcode
        b'\x4d',                          # invalid opcode
        b'\x61',                          # invalid opcode
        b'\x05\x01',                      # truncated push
        b'\x4c',                          # pushdata1 missing length
        b'\x4c\x00',                      # pushdata1 zero length
        P2PKH_OUT[:-1],                   # truncated p2pkh
        b'\x4c\xff' + b'\xab' * 254,      # pushdata1 truncated by one byte
    ]
    assert_scripts_equivalent(scripts)


@FUZZ
@given(script=st.binary(max_size=300))
def test_fuzz_random_scripts(script: bytes) -> None:
    assert_scripts_equivalent([script])


@FUZZ
@given(
    opcodes=st.lists(
        st.sampled_from([0xAC, 0xAE, 0xBA, 0x50, 0x53, 0x60, 0x76, 0xA9, 0x87, 0x6F]),
        max_size=30,
    ),
    suffix=st.binary(max_size=10),
)
def test_fuzz_opcode_sequences(opcodes: list[int], suffix: bytes) -> None:
    """Structure-aware fuzz: sequences of sigop-relevant opcodes (exercising the last-opcode OP_N rule)."""
    assert_scripts_equivalent([bytes(opcodes) + suffix])


def _make_vertex(scripts: list[bytes]) -> Transaction:
    tx = Transaction(outputs=[TxOutput(1, script) for script in scripts])
    tx.update_hash()
    return tx


def _make_verifier(mode: ScriptVerificationMode | None) -> tuple[VertexVerifier, ScriptVerificationPool | None]:
    settings = get_global_settings()
    pool = None
    if mode is not None:
        pool = ScriptVerificationPool(mode=mode, num_workers=2, min_inputs=1)
        pool.start()
    verifier = VertexVerifier(
        reactor=get_global_reactor(),
        settings=settings,
        feature_service=None,  # type: ignore[arg-type]  # not used by verify_sigops_output
        script_verification_pool=pool,
    )
    return verifier, pool


def test_verify_sigops_output_equivalence() -> None:
    """End-to-end: verify_sigops_output must surface the same exception type under python/rust/shadow."""
    settings = get_global_settings()
    over_limit_count = settings.MAX_TX_SIGOPS_OUTPUT // 16 + 1
    cases = [
        ('valid p2pkh', [P2PKH_OUT]),
        ('empty', []),
        ('over limit', [b'\x60\xae'] * over_limit_count),     # 16 sigops per output
        ('malformed', [P2PKH_OUT, b'\x00']),
        ('truncated', [b'\x05\x01']),
    ]
    verifiers = {mode: _make_verifier(mode) for mode in (None, ScriptVerificationMode.RUST,
                                                         ScriptVerificationMode.SHADOW_RUST)}
    try:
        for label, scripts in cases:
            vertex = _make_vertex(scripts)
            outcomes = {}
            for mode, (verifier, _) in verifiers.items():
                try:
                    verifier.verify_sigops_output(vertex)
                    outcomes[mode] = 'valid'
                except BaseException as e:
                    outcomes[mode] = type(e).__name__
            baseline = outcomes[None]
            assert all(outcome == baseline for outcome in outcomes.values()), f'{label}: {outcomes}'

        _, shadow_pool = verifiers[ScriptVerificationMode.SHADOW_RUST]
        assert shadow_pool is not None
        assert shadow_pool.shadow_mismatches == 0
    finally:
        for _, pool in verifiers.values():
            if pool is not None:
                pool.stop()


def test_over_limit_raises_too_many_sigops() -> None:
    settings = get_global_settings()
    over_limit_count = settings.MAX_TX_SIGOPS_OUTPUT // 16 + 1
    vertex = _make_vertex([b'\x60\xae'] * over_limit_count)
    verifier, pool = _make_verifier(ScriptVerificationMode.RUST)
    try:
        try:
            verifier.verify_sigops_output(vertex)
        except TooManySigOps:
            pass
        else:
            raise AssertionError('expected TooManySigOps')
    finally:
        assert pool is not None
        pool.stop()
