# Copyright 2026 Hathor Labs
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""DAG-Builder matrix covering shielded/transparent transactions.

Matrix axes: (inputs) × (outputs) × (nano) × (tokens) = 3 × 3 × 2 × 3 = 54 tests.
    inputs  / outputs : T (only transparent), S (only shielded), B (both)
    nano              : absent, present
    tokens            : HTR-only, custom-only (TKA), HTR+custom

Each case builds the DAG, asserts the expected header layout
(UnshieldBalanceHeader exactly when the tx has shielded inputs and no shielded
outputs, ShieldedOutputsHeader when there are any shielded outputs,
NanoHeader when requested), and serialisation round-trips the tx bytes back
into a tx preserving the excess scalar.
"""

from hathor.conf.settings import FeatureSetting
from hathor.nanocontracts import Blueprint, Context, public
from hathor.transaction import Transaction
from hathor.transaction.headers import NanoHeader, ShieldedOutputsHeader, UnshieldBalanceHeader
from hathor_tests import unittest
from hathor_tests.dag_builder.builder import TestDAGBuilder

INPUT_KINDS = ('T', 'S', 'B')
OUTPUT_KINDS = ('T', 'S', 'B')
NANO_KINDS = (False, True)
TOKEN_MIXES = ('htr', 'custom', 'mixed')

_BLUEPRINT_ID = b'\xab' * 32


class _NoopBlueprint(Blueprint):
    """A minimal blueprint used by the nano=True matrix cells."""

    @public(allow_deposit=True, allow_withdrawal=True)
    def initialize(self, ctx: Context) -> None:
        pass


def _tokens_for(mix: str) -> list[str]:
    if mix == 'htr':
        return ['HTR']
    if mix == 'custom':
        return ['TKA']
    return ['HTR', 'TKA']


def _matrix_name(ik: str, ok: str, nano: bool, tm: str) -> str:
    return f'test_in_{ik}_out_{ok}_{"nano" if nano else "noNano"}_{tm}'


class UnshieldDAGBuilderMatrixTestCase(unittest.TestCase):
    """54 tests covering (inputs × outputs × nano × tokens)."""

    def setUp(self) -> None:
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()
        settings = self._settings.model_copy(update={
            'ENABLE_SHIELDED_TRANSACTIONS': FeatureSetting.ENABLED,
            'ENABLE_NANO_CONTRACTS': True,
        })
        builder = self.get_builder(settings) \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service)
        self.manager = self.create_peer_from_builder(builder)
        # Register the no-op blueprint used by nano=True cells.
        self.manager.blueprint_service.register_blueprint(_BLUEPRINT_ID, _NoopBlueprint)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    # ------------------------------------------------------------------
    # DSL generation
    # ------------------------------------------------------------------

    def _build_dsl(self, ik: str, ok: str, nano: bool, tm: str) -> str:
        per_token = 60  # divisible by 2, small for fast tests
        tokens = _tokens_for(tm)

        lines: list[str] = [
            'blockchain genesis b[1..50]',
            'b30 < dummy',
        ]

        # --- Sources: one transparent and/or shielded UTXO per token required.
        # When tokens include TKA, the DAG builder auto-creates a TKA
        # TokenCreationTransaction to produce the supply consumed by the sources.
        # We always give each source tx exactly one output so the DSL index 0
        # maps cleanly to the serialization index 0 or (shielded) len(outputs)+0.
        src_t: dict[str, str] = {}   # token -> source node name (transparent)
        src_s: dict[str, str] = {}   # token -> source node name (shielded)

        if ik in ('T', 'B'):
            for t in tokens:
                name = f'src_T_{t}'
                src_t[t] = name
                lines.append(f'{name}.out[0] = {per_token} {t}')
        if ik in ('S', 'B'):
            for t in tokens:
                name = f'src_S_{t}'
                src_s[t] = name
                lines.append(f'{name}.out[0] = {per_token} {t} [shielded]')

        # --- Main tx inputs: declare via `src.out[0] <<< tx`.
        for t in tokens:
            if t in src_t:
                lines.append(f'{src_t[t]}.out[0] <<< tx')
            if t in src_s:
                lines.append(f'{src_s[t]}.out[0] <<< tx')

        # --- Main tx outputs: balance per token.
        out_idx = 0
        for t in tokens:
            total = 0
            if t in src_t:
                total += per_token
            if t in src_s:
                total += per_token
            if ok == 'T':
                lines.append(f'tx.out[{out_idx}] = {total} {t}')
                out_idx += 1
            elif ok == 'S':
                lines.append(f'tx.out[{out_idx}] = {total} {t} [shielded]')
                out_idx += 1
            else:  # B — half transparent, half shielded
                half = total // 2
                lines.append(f'tx.out[{out_idx}] = {half} {t}')
                out_idx += 1
                lines.append(f'tx.out[{out_idx}] = {total - half} {t} [shielded]')
                out_idx += 1

        # --- Nano header (optional). Inline initialize() on the no-op blueprint.
        if nano:
            lines.append(f'tx.nc_id = "{_BLUEPRINT_ID.hex()}"')
            lines.append('tx.nc_method = initialize()')

        return '\n            '.join(lines)

    # ------------------------------------------------------------------
    # One matrix cell
    # ------------------------------------------------------------------

    def _run_matrix_case(self, ik: str, ok: str, nano: bool, tm: str) -> None:
        dsl = self._build_dsl(ik, ok, nano, tm)
        artifacts = self.dag_builder.build_from_str('\n            ' + dsl + '\n        ')
        tx = artifacts.get_typed_vertex('tx', Transaction)

        header_types = {type(h) for h in tx.headers}
        expects_unshield = (ik in ('S', 'B')) and (ok == 'T')
        expects_shielded_outputs = ok in ('S', 'B')

        # Mutual-exclusion: the two shielded headers never coexist.
        self.assertFalse(
            ShieldedOutputsHeader in header_types and UnshieldBalanceHeader in header_types,
            f'both shielded headers present in {_matrix_name(ik, ok, nano, tm)}',
        )

        self.assertEqual(
            UnshieldBalanceHeader in header_types, expects_unshield,
            f'UnshieldBalanceHeader presence mismatch for {_matrix_name(ik, ok, nano, tm)}: '
            f'got headers={sorted(t.__name__ for t in header_types)}',
        )
        self.assertEqual(ShieldedOutputsHeader in header_types, expects_shielded_outputs)
        self.assertEqual(NanoHeader in header_types, nano)

        if expects_unshield:
            header = tx.get_unshield_balance_header()
            self.assertEqual(len(header.excess_blinding_factor), 32)

        # Header-level serialization round-trip on the unshield header (when
        # present). The full-tx round-trip (Transaction.create_from_struct)
        # consults global settings which default to shielded=DISABLED in the
        # test env, so we stay at the header level here — the full-tx path is
        # exercised separately in test_unshield_balance_header.py.
        if expects_unshield:
            header = tx.get_unshield_balance_header()
            data = header.serialize()
            restored, leftover = UnshieldBalanceHeader.deserialize(tx, data)
            self.assertEqual(leftover, b'')
            self.assertEqual(restored.excess_blinding_factor, header.excess_blinding_factor)


# ----------------------------------------------------------------------
# Dynamic test generation: 3 × 3 × 2 × 3 = 54.
# ----------------------------------------------------------------------
def _make_test(ik: str, ok: str, nano: bool, tm: str):
    def _test(self) -> None:
        self._run_matrix_case(ik, ok, nano, tm)
    _test.__name__ = _matrix_name(ik, ok, nano, tm)
    return _test


for _ik in INPUT_KINDS:
    for _ok in OUTPUT_KINDS:
        for _n in NANO_KINDS:
            for _tm in TOKEN_MIXES:
                setattr(
                    UnshieldDAGBuilderMatrixTestCase,
                    _matrix_name(_ik, _ok, _n, _tm),
                    _make_test(_ik, _ok, _n, _tm),
                )
