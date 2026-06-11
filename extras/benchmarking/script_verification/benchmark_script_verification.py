#  Copyright 2024 Hathor Labs
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

"""Micro-benchmark for parallel input script (signature) verification.

Compares, for transactions with varying numbers of inputs, the wall time of verifying all input scripts:
  - serial:    today's in-process ``script_eval`` (baseline, the production serial path)
  - detached:  the serial loop over the detached ``execute_script_verification_job`` (to show the detached
               payload adds no measurable overhead vs. ``script_eval``)
  - threads:   ``ScriptVerificationPool`` backed by a ThreadPoolExecutor
  - processes: ``ScriptVerificationPool`` backed by a ProcessPoolExecutor (spawn)

Run with (from the repo root):

    uv run python extras/benchmarking/script_verification/benchmark_script_verification.py

Useful flags:
    --input-counts 1,2,8,32,255   transaction input counts to test
    --kinds p2pkh,multisig        which script kinds to build
    --workers 2,4,8               worker-pool sizes (capped at cpu_count)
    --repeat 50                   measured iterations per cell (excludes warm-up)
"""

from __future__ import annotations

import argparse
import hashlib
import os
import statistics
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.hashes import SHA256

from hathor.crypto.util import get_address_from_public_key, get_public_key_bytes_compressed
from hathor.transaction import Transaction, TxInput, TxOutput
from hathor.transaction.scripts import P2PKH, MultiSig, create_output_script, script_eval
from hathor.transaction.scripts.opcode import OpcodesVersion
from hathor.verification.script_verification_pool import (
    ScriptVerificationJob,
    ScriptVerificationMode,
    ScriptVerificationPool,
    build_script_verification_job,
    execute_script_verification_job,
)
from hathor.wallet.util import generate_multisig_address, generate_multisig_redeem_script

OPCODES_VERSION = OpcodesVersion.V2
INPUT_VALUE = 100


@dataclass(slots=True, frozen=True, kw_only=True)
class BuiltTx:
    """A signed transaction plus the per-input objects needed to drive every benchmark arm."""
    tx: Transaction
    spent_tx: Transaction
    jobs: list[ScriptVerificationJob]


def _sign(tx: Transaction, private_key: ec.EllipticCurvePrivateKey) -> bytes:
    """Sign a transaction's sighash the same way hathor.wallet.util.generate_signature does."""
    hashed = hashlib.sha256(tx.get_sighash_all()).digest()
    return private_key.sign(hashed, ec.ECDSA(SHA256()))


def _build_jobs(tx: Transaction, spent_tx: Transaction) -> list[ScriptVerificationJob]:
    shared_outputs = tuple((o.value, o.script) for o in tx.outputs) if OPCODES_VERSION == OpcodesVersion.V1 else ()
    return [
        build_script_verification_job(
            input_index=i,
            tx=tx,
            txin=txin,
            spent_tx=spent_tx,
            opcodes_version=OPCODES_VERSION,
            shared_outputs=shared_outputs,
        )
        for i, txin in enumerate(tx.inputs)
    ]


def build_p2pkh_tx(num_inputs: int) -> BuiltTx:
    """Build a transaction with ``num_inputs`` P2PKH inputs, each validly signed."""
    private_key = ec.generate_private_key(ec.SECP256K1())
    pubkey_bytes = get_public_key_bytes_compressed(private_key.public_key())
    output_script = P2PKH.create_output_script(get_address_from_public_key(private_key.public_key()))

    spent_tx = Transaction(timestamp=1000, outputs=[TxOutput(INPUT_VALUE, output_script) for _ in range(num_inputs)])
    spent_tx.update_hash()

    tx = Transaction(
        timestamp=2000,
        inputs=[TxInput(spent_tx.hash, i, b'') for i in range(num_inputs)],
        outputs=[TxOutput(INPUT_VALUE * num_inputs, output_script)],
    )
    signature = _sign(tx, private_key)  # sighash excludes input data, so one signature is valid for all inputs
    input_data = P2PKH.create_input_data(pubkey_bytes, signature)
    for txin in tx.inputs:
        txin.data = input_data
    tx.clear_sighash_cache()
    return BuiltTx(tx=tx, spent_tx=spent_tx, jobs=_build_jobs(tx, spent_tx))


def build_multisig_tx(num_inputs: int) -> BuiltTx:
    """Build a transaction with ``num_inputs`` 2-of-3 multisig inputs, each validly signed."""
    private_keys = [ec.generate_private_key(ec.SECP256K1()) for _ in range(3)]
    pubkeys = [get_public_key_bytes_compressed(k.public_key()) for k in private_keys]
    redeem_script = generate_multisig_redeem_script(2, pubkeys)
    multisig_address = generate_multisig_address(redeem_script)

    from hathor.crypto.util import decode_address
    output_script = create_output_script(decode_address(multisig_address))

    spent_tx = Transaction(timestamp=1000, outputs=[TxOutput(INPUT_VALUE, output_script) for _ in range(num_inputs)])
    spent_tx.update_hash()

    tx = Transaction(
        timestamp=2000,
        inputs=[TxInput(spent_tx.hash, i, b'') for i in range(num_inputs)],
        outputs=[TxOutput(INPUT_VALUE * num_inputs, output_script)],
    )
    signatures = [_sign(tx, private_keys[0]), _sign(tx, private_keys[1])]
    input_data = MultiSig.create_input_data(redeem_script, signatures)
    for txin in tx.inputs:
        txin.data = input_data
    tx.clear_sighash_cache()
    return BuiltTx(tx=tx, spent_tx=spent_tx, jobs=_build_jobs(tx, spent_tx))


def _verify_serial_script_eval(built: BuiltTx) -> None:
    for txin in built.tx.inputs:
        script_eval(built.tx, txin, built.spent_tx, OPCODES_VERSION)


def _verify_serial_detached(built: BuiltTx) -> None:
    for job in built.jobs:
        assert execute_script_verification_job(job) is None


def _verify_with_pool(built: BuiltTx, pool: ScriptVerificationPool) -> None:
    results = pool.run_jobs(built.jobs)
    assert all(r is None for r in results)


def _measure(fn, *, repeat: int, warmup: int = 3) -> tuple[float, float]:
    """Return (median_ms, p90_ms) wall time of calling fn() over `repeat` measured iterations."""
    for _ in range(warmup):
        fn()
    samples = []
    for _ in range(repeat):
        start = time.perf_counter()
        fn()
        samples.append((time.perf_counter() - start) * 1000.0)
    samples.sort()
    p90 = samples[min(len(samples) - 1, int(round(0.9 * (len(samples) - 1))))]
    return statistics.median(samples), p90


def run(*, input_counts: list[int], kinds: list[str], worker_counts: list[int], repeat: int) -> None:
    builders = {'p2pkh': build_p2pkh_tx, 'multisig': build_multisig_tx}
    cpu_count = os.cpu_count() or 1
    print(f'cpu_count={cpu_count}  repeat={repeat}  opcodes_version={OPCODES_VERSION.name}')
    print(f'{"kind":9} {"inputs":>7} {"arm":>20} {"workers":>8} {"median_ms":>11} {"p90_ms":>9} '
          f'{"us/input":>9} {"speedup":>8}')
    print('-' * 96)

    for kind in kinds:
        builder = builders[kind]
        for n in input_counts:
            built = builder(n)
            # Sanity: every arm must agree the tx is valid before we time it.
            _verify_serial_script_eval(built)

            baseline_median, baseline_p90 = _measure(lambda: _verify_serial_script_eval(built), repeat=repeat)
            _row(kind, n, 'serial (script_eval)', '-', baseline_median, baseline_p90, baseline_median)

            det_median, det_p90 = _measure(lambda: _verify_serial_detached(built), repeat=repeat)
            _row(kind, n, 'serial (detached)', '-', det_median, det_p90, baseline_median)

            for mode in (ScriptVerificationMode.THREADS, ScriptVerificationMode.PROCESSES):
                for workers in worker_counts:
                    workers = min(workers, cpu_count)
                    pool = ScriptVerificationPool(mode=mode, num_workers=workers, min_inputs=1)
                    pool.start()
                    try:
                        median, p90 = _measure(lambda: _verify_with_pool(built, pool), repeat=repeat)
                    finally:
                        pool.stop()
                    _row(kind, n, mode.value, str(workers), median, p90, baseline_median)
            print('-' * 96)


def _row(kind: str, n: int, arm: str, workers: str, median: float, p90: float, baseline: float) -> None:
    us_per_input = (median * 1000.0) / n
    speedup = baseline / median if median > 0 else float('inf')
    print(f'{kind:9} {n:>7} {arm:>20} {workers:>8} {median:>11.3f} {p90:>9.3f} '
          f'{us_per_input:>9.1f} {speedup:>7.2f}x')


def _parse_int_list(value: str) -> list[int]:
    return [int(x) for x in value.split(',') if x.strip()]


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--input-counts', type=_parse_int_list, default=[1, 2, 8, 32, 255])
    parser.add_argument('--kinds', type=lambda v: v.split(','), default=['p2pkh', 'multisig'])
    parser.add_argument('--workers', type=_parse_int_list, default=[2, 4, 8])
    parser.add_argument('--repeat', type=int, default=50)
    args = parser.parse_args()
    run(input_counts=args.input_counts, kinds=args.kinds, worker_counts=args.workers, repeat=args.repeat)


if __name__ == '__main__':
    main()
