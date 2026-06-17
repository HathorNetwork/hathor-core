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

"""Differential tests for the Rust script verifier (htr_lib.verify_scripts_batch).

Python (`execute_script_verification_job`) is the authoritative consensus reference; the Rust port must agree on
the *category* of every outcome: valid, which ScriptError subclass would be returned, or which exception type
would escape unwrapped. Human-readable messages are debug-only and intentionally not compared.

The suite has four layers:
  1. a hand-built corpus covering every opcode, both opcode versions and the known quirks;
  2. an exhaustive mutation pass (truncations + byte flips) over valid P2PKH/MultiSig scripts;
  3. hypothesis fuzz over random and structure-mutated scripts;
  4. a dedicated signature-acceptance corpus + fuzz (the empirical arbiter of the Rust DER policy
     vs OpenSSL: strict DER parse + low-S normalization).
"""

import struct
from functools import cache

import htr_lib
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.hashes import SHA256
from hypothesis import HealthCheck, given, settings as hypothesis_settings, strategies as st

from hathor.conf.get_settings import get_global_settings
from hathor.crypto.util import decode_address, get_address_from_public_key_hash, get_public_key_bytes_compressed
from hathor.transaction.scripts import P2PKH, MultiSig, create_output_script
from hathor.transaction.scripts.opcode import OpcodesVersion
from hathor.verification.script_verification_pool import (
    _RUST_SCRIPT_ERRORS,
    ScriptVerificationJob,
    ScriptVerificationMode,
    ScriptVerificationPool,
    execute_script_verification_job,
)
from hathor.wallet.util import generate_multisig_address, generate_multisig_redeem_script
from hathorlib.utils.address import get_hash160

SIGHASH = b'sighash-all-data-differential-vector'
TX_TIMESTAMP = 2000
SPENT_VALUE = 100
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# Fuzz settings: derandomized so CI and xdist workers are deterministic; failing inputs are printed as hex and
# can be replayed directly (and frozen as Rust unit vectors).
FUZZ = hypothesis_settings(max_examples=400, deadline=None, derandomize=True,
                           suppress_health_check=[HealthCheck.too_slow])


@cache
def _key(seed: int) -> ec.EllipticCurvePrivateKey:
    return ec.derive_private_key(seed, ec.SECP256K1())


def _sign(private_key: ec.EllipticCurvePrivateKey, data: bytes = SIGHASH) -> bytes:
    return private_key.sign(data, ec.ECDSA(SHA256()))


def _push(data: bytes) -> bytes:
    """Minimal pushdata framing for up to 255 bytes (mirrors HathorScript.pushData)."""
    assert 1 <= len(data) <= 255
    if len(data) <= 75:
        return bytes([len(data)]) + data
    return bytes([0x4C, len(data)]) + data


def make_job(
    input_data: bytes,
    output_script: bytes,
    *,
    version: OpcodesVersion = OpcodesVersion.V2,
    timestamp: int = TX_TIMESTAMP,
    value: int = SPENT_VALUE,
    outputs: tuple[tuple[int, bytes], ...] = (),
) -> ScriptVerificationJob:
    return ScriptVerificationJob(
        input_index=0,
        input_data=input_data,
        output_script=output_script,
        sighash_all_data=SIGHASH,
        tx_timestamp=timestamp,
        spent_output_value=value,
        tx_outputs=outputs,
        opcodes_version=version,
    )


def python_category(job: ScriptVerificationJob) -> str:
    """Run the authoritative Python evaluator and classify the outcome."""
    try:
        error = execute_script_verification_job(job)
    except BaseException as e:
        name = 'StructError' if isinstance(e, struct.error) else type(e).__name__
        return f'raise:{name}'
    return 'valid' if error is None else f'script:{type(error).__name__}'


def rust_categories(jobs: list[ScriptVerificationJob]) -> list[str]:
    """Run the Rust batch verifier and classify each outcome with the same labels."""
    settings = get_global_settings()
    raw = htr_lib.verify_scripts_batch(
        jobs, settings.MAX_MULTISIG_PUBKEYS, settings.MAX_MULTISIG_SIGNATURES, settings.P2PKH_VERSION_BYTE, 2,
    )
    categories = []
    for item in raw:
        if item is None:
            categories.append('valid')
        elif item[0] in _RUST_SCRIPT_ERRORS:
            categories.append(f'script:{item[0]}')
        else:
            categories.append(f'raise:{item[0]}')
    return categories


def assert_jobs_equivalent(labeled_jobs: list[tuple[str, ScriptVerificationJob]]) -> None:
    """Assert Python and Rust agree on every job's category; report all mismatches with replayable hex."""
    jobs = [job for _, job in labeled_jobs]
    rust = rust_categories(jobs)
    mismatches = []
    for (label, job), rust_category in zip(labeled_jobs, rust):
        python = python_category(job)
        if python != rust_category:
            mismatches.append(
                f'{label}: python={python} rust={rust_category} '
                f'input_data={job.input_data.hex()} output_script={job.output_script.hex()} '
                f'version={int(job.opcodes_version)} timestamp={job.tx_timestamp} value={job.spent_output_value}'
            )
    assert not mismatches, 'Python/Rust mismatches:\n' + '\n'.join(mismatches)


@cache
def p2pkh_pair(timelock: bytes | None = None) -> tuple[bytes, bytes]:
    """A valid (input_data, output_script) P2PKH pair signed over SIGHASH.

    Cached: ECDSA signing draws a random nonce, so the DER length varies between calls; hypothesis requires
    stable data generation within a run.
    """
    private_key = _key(0x1234567890ABCDEF)
    pubkey = get_public_key_bytes_compressed(private_key.public_key())
    address = get_address_from_public_key_hash(get_hash160(pubkey))
    output_script = P2PKH.create_output_script(address, timelock)
    input_data = P2PKH.create_input_data(pubkey, _sign(private_key))
    return input_data, output_script


@cache
def multisig_pair() -> tuple[bytes, bytes, bytes, list[bytes]]:
    """A valid 2-of-3 multisig: (input_data, output_script, redeem_script, signatures). Cached like p2pkh_pair."""
    private_keys = [_key(1000 + i) for i in range(3)]
    pubkeys = [get_public_key_bytes_compressed(k.public_key()) for k in private_keys]
    redeem_script = generate_multisig_redeem_script(2, pubkeys)
    output_script = create_output_script(decode_address(generate_multisig_address(redeem_script)))
    signatures = [_sign(private_keys[0]), _sign(private_keys[1])]
    input_data = MultiSig.create_input_data(redeem_script, signatures)
    return input_data, output_script, redeem_script, signatures


def _corpus() -> list[tuple[str, ScriptVerificationJob]]:
    jobs: list[tuple[str, ScriptVerificationJob]] = []
    p2pkh_in, p2pkh_out = p2pkh_pair()
    _, p2pkh_out_timelocked = p2pkh_pair(timelock=(1000).to_bytes(4, 'big'))
    private_key = _key(0x1234567890ABCDEF)
    pubkey = get_public_key_bytes_compressed(private_key.public_key())
    signature = _sign(private_key)
    v1 = OpcodesVersion.V1

    # --- P2PKH ---
    jobs.append(('p2pkh valid', make_job(p2pkh_in, p2pkh_out)))
    jobs.append(('p2pkh valid V1', make_job(p2pkh_in, p2pkh_out, version=v1)))
    corrupted = bytearray(p2pkh_in)
    corrupted[10] ^= 0xFF
    jobs.append(('p2pkh corrupted sig', make_job(bytes(corrupted), p2pkh_out)))
    wrong_key = _key(0xDEAD)
    wrong_input = P2PKH.create_input_data(get_public_key_bytes_compressed(wrong_key.public_key()), signature)
    jobs.append(('p2pkh wrong pubkey', make_job(wrong_input, p2pkh_out)))
    jobs.append(('p2pkh swapped pushes', make_job(_push(pubkey) + _push(signature), p2pkh_out)))
    jobs.append(('p2pkh missing pubkey', make_job(_push(signature), p2pkh_out)))
    jobs.append(('p2pkh empty input', make_job(b'', p2pkh_out)))
    jobs.append(('p2pkh extra stack item', make_job(b'\x51' + p2pkh_in, p2pkh_out)))
    jobs.append(('p2pkh uncompressed pubkey', make_job(
        _push(signature) + _push(b'\x04' + pubkey[1:] + pubkey[1:]), p2pkh_out)))
    jobs.append(('p2pkh short pubkey', make_job(_push(signature) + _push(b'\x02\xAB'), p2pkh_out)))
    jobs.append(('p2pkh off-curve pubkey', make_job(
        _push(signature) + _push(b'\x02' + b'\xFF' * 32), p2pkh_out)))
    jobs.append(('p2pkh timelocked ok', make_job(p2pkh_in, p2pkh_out_timelocked, timestamp=2000)))
    jobs.append(('p2pkh timelocked locked', make_job(p2pkh_in, p2pkh_out_timelocked, timestamp=900)))
    jobs.append(('p2pkh timelocked boundary', make_job(p2pkh_in, p2pkh_out_timelocked, timestamp=1000)))
    # struct.error from a non-4-byte timelock buffer
    jobs.append(('timelock 3-byte buffer', make_job(b'\x03\x00\x00\x01\x6F\x51', b'')))
    jobs.append(('timelock int on stack', make_job(b'\x51\x6F\x51', b'')))
    # output script with a trailing newline still matches the P2PKH regex but evaluates differently
    jobs.append(('p2pkh trailing newline output', make_job(p2pkh_in, p2pkh_out + b'\n')))

    # --- MultiSig ---
    ms_in, ms_out, redeem_script, signatures = multisig_pair()
    jobs.append(('multisig valid', make_job(ms_in, ms_out)))
    jobs.append(('multisig swapped sigs', make_job(
        MultiSig.create_input_data(redeem_script, [signatures[1], signatures[0]]), ms_out)))
    jobs.append(('multisig one sig', make_job(
        MultiSig.create_input_data(redeem_script, [signatures[0]]), ms_out)))
    jobs.append(('multisig no pushes input', make_job(b'\x6F', ms_out)))
    jobs.append(('multisig empty input', make_job(b'', ms_out)))
    jobs.append(('multisig invalid opcode in input', make_job(ms_in + b'\x00', ms_out)))
    jobs.append(('multisig trailing newline output', make_job(ms_in, ms_out + b'\n')))
    jobs.append(('multisig 0-of-0', make_job(b'\x50\x50', b'\xAE')))
    jobs.append(('multisig sig count 16', make_job(b'\x60\x50', b'\xAE')))
    jobs.append(('multisig bytes pubkey count', make_job(b'\x01\xAB', b'\xAE')))
    jobs.append(('multisig int pubkey on stack', make_job(
        _push(signature) + b'\x51' + b'\x51\x51', b'\xAE')))

    # --- V1-only opcodes ---
    data_payload = b'\x03abc\x02de'  # two length-prefixed values: "abc", "de"
    data_push = _push(data_payload)
    jobs.append(('checkdatasig valid', make_job(
        _push(b'data') + _push(_sign(private_key, b'data')) + _push(pubkey), b'\xBA', version=v1)))
    jobs.append(('checkdatasig invalid sig', make_job(
        _push(b'data') + _push(b'\x30\x01\x02') + _push(pubkey), b'\xBA', version=v1)))
    jobs.append(('checkdatasig under V2', make_job(
        _push(b'data') + _push(b'\x30\x01\x02') + _push(pubkey), b'\xBA')))
    jobs.append(('data_strequal match', make_job(
        data_push + b'\x50' + _push(b'abc'), b'\xC0', version=v1)))
    jobs.append(('data_strequal mismatch utf8', make_job(
        data_push + b'\x50' + _push(b'xyz'), b'\xC0', version=v1)))
    jobs.append(('data_strequal mismatch non-utf8', make_job(
        _push(b'\x03\xFF\xFE\xFD') + b'\x50' + _push(b'xyz'), b'\xC0', version=v1)))
    jobs.append(('data_strequal bytes k', make_job(
        data_push + _push(b'\x00') + _push(b'abc'), b'\xC0', version=v1)))
    jobs.append(('data_strequal k out of range', make_job(
        data_push + b'\x55' + _push(b'abc'), b'\xC0', version=v1)))
    jobs.append(('data_strequal data overrun', make_job(
        _push(b'\x05ab') + b'\x50' + _push(b'abc'), b'\xC0', version=v1)))
    jobs.append(('data_greaterthan greater', make_job(
        _push(b'\x01\x05') + b'\x50' + _push(b'\x03'), b'\xC1', version=v1)))
    jobs.append(('data_greaterthan less', make_job(
        _push(b'\x01\x05') + b'\x50' + _push(b'\x07'), b'\xC1', version=v1)))
    jobs.append(('data_greaterthan bad value len', make_job(
        _push(b'\x01\x05') + b'\x50' + _push(b'\x00\x00\x07'), b'\xC1', version=v1)))
    jobs.append(('data_match_value match', make_job(
        _push(b'\x01\x05') + b'\x50' + _push(b'LP') + _push(b'\x05') + _push(b'P0') + _push(b'\x01'),
        b'\xD1', version=v1)))
    jobs.append(('data_match_value no match int last pubkey', make_job(
        _push(b'\x01\x09') + b'\x50' + b'\x51' + _push(b'\x05') + _push(b'P0') + _push(b'\x01'),
        b'\xD1', version=v1)))
    jobs.append(('data_match_value uncaught struct error', make_job(
        _push(b'\x03\x00\x00\x05') + b'\x50' + _push(b'LP') + _push(b'\x05') + _push(b'P0') + _push(b'\x01'),
        b'\xD1', version=v1)))
    jobs.append(('data_match_value caught struct error', make_job(
        _push(b'\x01\x05') + b'\x50' + _push(b'LP') + _push(b'\x00\x00\x05') + _push(b'P0') + _push(b'\x01'),
        b'\xD1', version=v1)))
    parsed_p2pkh = P2PKH.parse_script(p2pkh_out)
    assert parsed_p2pkh is not None
    address = decode_address(parsed_p2pkh.address)
    find_p2pkh_in = _push(address)
    outputs = ((SPENT_VALUE, p2pkh_out),)
    jobs.append(('find_p2pkh match', make_job(find_p2pkh_in, b'\xD0', version=v1, outputs=outputs)))
    jobs.append(('find_p2pkh wrong value', make_job(
        find_p2pkh_in, b'\xD0', version=v1, value=SPENT_VALUE + 1, outputs=outputs)))
    jobs.append(('find_p2pkh no outputs', make_job(find_p2pkh_in, b'\xD0', version=v1)))
    jobs.append(('find_p2pkh non-p2pkh outputs', make_job(
        find_p2pkh_in, b'\xD0', version=v1, outputs=((SPENT_VALUE, ms_out),))))
    jobs.append(('find_p2pkh timelocked output', make_job(
        find_p2pkh_in, b'\xD0', version=v1, outputs=((SPENT_VALUE, p2pkh_out_timelocked),))))
    jobs.append(('find_p2pkh newline output', make_job(
        find_p2pkh_in, b'\xD0', version=v1, outputs=((SPENT_VALUE, p2pkh_out + b'\n'),))))
    jobs.append(('find_p2pkh int address', make_job(b'\x51', b'\xD0', version=v1)))
    jobs.append(('find_p2pkh under V2', make_job(find_p2pkh_in, b'\xD0', outputs=outputs)))

    # --- interpreter edges ---
    jobs.append(('int equal assertion', make_job(b'\x51\x51', b'\x87')))
    jobs.append(('hash160 on int', make_job(b'\x51', b'\xA9')))
    jobs.append(('dup empty stack', make_job(b'', b'\x76')))
    jobs.append(('invalid opcode 0x00', make_job(b'\x00', b'')))
    jobs.append(('invalid opcode 0x4D', make_job(b'\x4D', b'')))
    jobs.append(('invalid opcode 0x61', make_job(b'\x61', b'')))
    jobs.append(('empty scripts', make_job(b'', b'')))
    jobs.append(('two items left', make_job(b'\x51\x51', b'')))
    jobs.append(('single int 1', make_job(b'\x51', b'')))
    jobs.append(('single int 0', make_job(b'\x50', b'')))
    jobs.append(('single byte 0x01', make_job(b'\x01\x01', b'')))
    jobs.append(('pushdata1 missing len', make_job(b'\x4C', b'')))
    jobs.append(('pushdata1 zero len', make_job(b'\x4C\x00', b'')))
    jobs.append(('pushdata1 truncated', make_job(b'\x4C\x05\xAB', b'')))
    jobs.append(('truncated push', make_job(b'\x05\x01', b'')))
    jobs.append(('equalverify ok', make_job(b'\x51\x01\xAB\x01\xAB', b'\x88')))
    jobs.append(('equalverify fail', make_job(b'\x51\x01\xAB\x01\xAC', b'\x88')))
    return jobs


def test_corpus() -> None:
    assert_jobs_equivalent(_corpus())


def test_mutations_truncations_and_flips() -> None:
    """Truncate the valid scripts at every byte boundary and flip every byte: categories must match."""
    p2pkh_in, p2pkh_out = p2pkh_pair()
    ms_in, ms_out, _, _ = multisig_pair()
    labeled = []
    for name, (input_data, output_script) in (('p2pkh', (p2pkh_in, p2pkh_out)),
                                              ('multisig', (ms_in, ms_out))):
        for cut in range(len(input_data)):
            labeled.append((f'{name} input cut {cut}', make_job(input_data[:cut], output_script)))
        for cut in range(len(output_script)):
            labeled.append((f'{name} output cut {cut}', make_job(input_data, output_script[:cut])))
        for position in range(len(input_data)):
            flipped = bytearray(input_data)
            flipped[position] ^= 0xFF
            labeled.append((f'{name} input flip {position}', make_job(bytes(flipped), output_script)))
        for position in range(len(output_script)):
            flipped = bytearray(output_script)
            flipped[position] ^= 0xFF
            labeled.append((f'{name} output flip {position}', make_job(input_data, bytes(flipped))))
    assert_jobs_equivalent(labeled)


@FUZZ
@given(
    input_data=st.binary(max_size=300),
    output_script=st.binary(max_size=80),
    version=st.sampled_from([OpcodesVersion.V1, OpcodesVersion.V2]),
)
def test_fuzz_random_scripts(input_data: bytes, output_script: bytes, version: OpcodesVersion) -> None:
    job = make_job(input_data, output_script, version=version)
    assert_jobs_equivalent([('fuzz', job)])


@FUZZ
@given(
    data=st.data(),
    version=st.sampled_from([OpcodesVersion.V1, OpcodesVersion.V2]),
    use_multisig=st.booleans(),
)
def test_fuzz_structured_mutations(data: st.DataObject, version: OpcodesVersion, use_multisig: bool) -> None:
    """Structure-aware fuzz: mutate a *valid* script pair (splice, flip, append) and compare categories."""
    if use_multisig:
        input_data, output_script, _, _ = multisig_pair()
    else:
        input_data, output_script = p2pkh_pair()
    target_input = bytearray(input_data)
    for _ in range(data.draw(st.integers(0, 3), label='num_input_mutations')):
        position = data.draw(st.integers(0, len(target_input) - 1), label='input_position')
        target_input[position] = data.draw(st.integers(0, 255), label='input_byte')
    input_cut = data.draw(st.integers(0, len(target_input)), label='input_cut')
    target_output = bytearray(output_script)
    if data.draw(st.booleans(), label='mutate_output'):
        position = data.draw(st.integers(0, len(target_output) - 1), label='output_position')
        target_output[position] = data.draw(st.integers(0, 255), label='output_byte')
    suffix = data.draw(st.binary(max_size=3), label='output_suffix')
    job = make_job(bytes(target_input[:input_cut]), bytes(target_output) + suffix, version=version)
    assert_jobs_equivalent([('structured fuzz', job)])


def _int_to_der_bytes(value: int) -> bytes:
    """Minimal DER INTEGER content bytes (with sign byte when the high bit is set)."""
    if value == 0:
        return b'\x00'
    encoded = value.to_bytes((value.bit_length() + 7) // 8, 'big')
    if encoded[0] & 0x80:
        encoded = b'\x00' + encoded
    return encoded


def _raw_der(r_bytes: bytes, s_bytes: bytes, *, long_form: bool = False) -> bytes:
    """Hand-rolled DER SEQUENCE of two INTEGERs, optionally with a long-form sequence length."""
    body = b'\x02' + bytes([len(r_bytes)]) + r_bytes + b'\x02' + bytes([len(s_bytes)]) + s_bytes
    if long_form:
        return b'\x30\x81' + bytes([len(body)]) + body
    return b'\x30' + bytes([len(body)]) + body


def _signature_job(signature: bytes) -> ScriptVerificationJob:
    """A minimal OP_CHECKSIG job for the given signature bytes and the fixed test pubkey."""
    pubkey = get_public_key_bytes_compressed(_key(0x1234567890ABCDEF).public_key())
    if len(signature) == 0:
        # The interpreter cannot push empty bytes; frame it as OP_PUSHDATA1 with length 0,
        # which both sides must reject identically.
        input_data = b'\x4C\x00' + _push(pubkey)
    else:
        input_data = _push(signature) + _push(pubkey)
    return make_job(input_data, b'\xAC')


def test_signature_acceptance_corpus() -> None:
    """Frozen DER-policy vectors: every known way OpenSSL and libsecp256k1 could disagree."""
    private_key = _key(0x1234567890ABCDEF)
    signature = _sign(private_key)
    r, s = decode_dss_signature(signature)
    n = SECP256K1_ORDER
    r_bytes, s_bytes = _int_to_der_bytes(r), _int_to_der_bytes(s)

    variants: list[tuple[str, bytes]] = [
        ('valid', signature),
        ('re-encoded', _raw_der(r_bytes, s_bytes)),
        ('high_s', encode_dss_signature(r, n - s)),
        ('swapped_r_s', encode_dss_signature(s, r)),
        ('trailing_zero', signature + b'\x00'),
        ('trailing_ff', signature + b'\xFF'),
        ('truncated_1', signature[:-1]),
        ('truncated_half', signature[:len(signature) // 2]),
        ('empty', b''),
        ('r_zero', _raw_der(b'\x00', s_bytes)),
        ('s_zero', _raw_der(r_bytes, b'\x00')),
        ('r_order', _raw_der(_int_to_der_bytes(n), s_bytes)),
        ('s_order', _raw_der(r_bytes, _int_to_der_bytes(n))),
        ('s_order_plus_s', _raw_der(r_bytes, _int_to_der_bytes(n + s))),
        ('r_extra_pad', _raw_der(b'\x00' + r_bytes, s_bytes)),
        ('s_extra_pad', _raw_der(r_bytes, b'\x00' + s_bytes)),
        ('missing_required_pad', _raw_der(r_bytes.lstrip(b'\x00'), s_bytes.lstrip(b'\x00'))),
        ('long_form_length', _raw_der(r_bytes, s_bytes, long_form=True)),
        ('wrong_sequence_tag', b'\x31' + _raw_der(r_bytes, s_bytes)[1:]),
        ('wrong_integer_tag', _raw_der(r_bytes, s_bytes).replace(b'\x02', b'\x03', 1)),
        ('declared_length_short', b'\x30' + bytes([len(_raw_der(r_bytes, s_bytes)) - 3]) +
         _raw_der(r_bytes, s_bytes)[2:]),
        ('tiny_valid_der', _raw_der(b'\x01', b'\x01')),
        ('garbage', b'\xDE\xAD\xBE\xEF'),
    ]
    assert_jobs_equivalent([(label, _signature_job(sig)) for label, sig in variants])


@FUZZ
@given(signature=st.binary(max_size=120))
def test_fuzz_signature_random_bytes(signature: bytes) -> None:
    assert_jobs_equivalent([('random sig bytes', _signature_job(signature))])


@FUZZ
@given(
    r=st.integers(0, SECP256K1_ORDER * 2),
    s=st.integers(0, SECP256K1_ORDER * 2),
    r_pad=st.integers(0, 2),
    s_pad=st.integers(0, 2),
    long_form=st.booleans(),
    trailing=st.binary(max_size=4),
)
def test_fuzz_signature_der_structure(
    r: int, s: int, r_pad: int, s_pad: int, long_form: bool, trailing: bytes,
) -> None:
    """Fuzz the DER structure space: arbitrary r/s (including >= group order), extra integer padding,
    long-form lengths and trailing garbage. Both sides must agree on accept/reject for every shape."""
    r_bytes = b'\x00' * r_pad + _int_to_der_bytes(r)
    s_bytes = b'\x00' * s_pad + _int_to_der_bytes(s)
    if len(r_bytes) + len(s_bytes) + 4 > 127:
        # keep the sequence body in short-form range so the encoding stays well-defined
        return
    signature = _raw_der(r_bytes, s_bytes, long_form=long_form) + trailing
    if len(signature) > 255:
        return
    assert_jobs_equivalent([('der structure fuzz', _signature_job(signature))])


def test_tx_level_rust_pool_equivalence() -> None:
    """Whole-tx check through TransactionVerifier._verify_inputs: the RUST pool must surface the same exception
    *type* as the serial Python path (messages legitimately differ)."""
    from hathor.verification.transaction_verifier import TransactionVerifier
    from hathor_tests.tx.test_parallel_script_verification import (
        OPCODES_VERSION,
        build_multisig_tx,
        build_p2pkh_tx,
        corrupt_signature,
    )

    settings = get_global_settings()
    pool = ScriptVerificationPool(mode=ScriptVerificationMode.RUST, num_workers=2, min_inputs=1)
    pool.start()
    try:
        def verify(tx, script_pool):
            try:
                TransactionVerifier._verify_inputs(
                    settings, tx, OPCODES_VERSION, skip_script=False, script_pool=script_pool,
                )
            except BaseException as e:
                return type(e)
            return None

        scenarios = []
        scenarios.append(('p2pkh 3 inputs', build_p2pkh_tx([0, 1, 2])))
        scenarios.append(('multisig 2 inputs', build_multisig_tx(2)))
        bad_tx = build_p2pkh_tx([0, 1, 2])
        corrupt_signature(bad_tx, 1)
        scenarios.append(('p2pkh corrupted input 1', bad_tx))
        for label, tx in scenarios:
            assert verify(tx, pool) == verify(tx, None), label
    finally:
        pool.stop()


def test_shadow_pool_has_no_mismatches() -> None:
    """Run the corpus through the SHADOW_RUST pool: Python outcomes are returned and no mismatch is logged."""
    pool = ScriptVerificationPool(mode=ScriptVerificationMode.SHADOW_RUST, num_workers=2, min_inputs=1)
    pool.start()
    try:
        for label, job in _corpus():
            try:
                pool.run_jobs([job])
            except BaseException:
                pass  # raise-kind outcomes propagate by design; only the mismatch counter matters here
        assert pool.shadow_mismatches == 0
    finally:
        pool.stop()
