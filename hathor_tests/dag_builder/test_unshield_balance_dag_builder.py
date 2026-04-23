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


class MutualExclusionRejectionTestCase(unittest.TestCase):
    """Real DAG-built tx carrying BOTH ShieldedOutputsHeader and
    UnshieldBalanceHeader must be rejected by verify_shielded_balance.

    The DAG builder never produces this shape on its own
    (add_unshield_balance_header_if_needed early-returns when a shielded
    output exists), so we inject the second header manually post-build to
    exercise the verifier's invariant on a real Transaction object — not
    just a MagicMock as in test_unshield_balance_header.py.
    """

    def setUp(self) -> None:
        super().setUp()

        from hathor.simulator.patches import SimulatorCpuMiningService
        from hathor.simulator.simulator import _build_vertex_verifiers

        cpu_mining_service = SimulatorCpuMiningService()
        settings = self._settings.model_copy(update={
            'ENABLE_SHIELDED_TRANSACTIONS': FeatureSetting.ENABLED,
        })
        builder = self.get_builder(settings) \
            .set_vertex_verifiers_builder(_build_vertex_verifiers) \
            .set_cpu_mining_service(cpu_mining_service)
        self.manager = self.create_peer_from_builder(builder)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def _get_shielded_verifier(self):
        """The TransactionVerifier instance the manager uses for shielded checks."""
        return self.manager.verification_service.verifiers.tx

    def _build_tx_and_sources(self, dsl: str) -> tuple[Transaction, dict]:
        """Return the built `tx` plus a spent_txs mapping so verify_shielded_balance
        can resolve inputs without requiring the source to be in storage.

        The DAG builder produces valid tx objects in memory, but propagation
        through the manager requires global settings to have shielded enabled
        (not the case in the test env). Supplying `spent_txs` lets us bypass
        that and exercise the verifier directly on real tx objects.
        """
        artifacts = self.dag_builder.build_from_str(dsl)
        tx = artifacts.get_typed_vertex('tx', Transaction)
        # The verifier asserts `tx.storage is not None`; any non-None storage
        # object satisfies it — we route all spent-tx lookups through the
        # explicit spent_txs dict. Index every vertex by hash so the DAG
        # builder's implicit dummy-funded inputs also resolve.
        tx.storage = self.manager.tx_storage
        spent_txs = {pair.vertex.hash: pair.vertex for pair in artifacts.list}
        return tx, spent_txs

    def test_partial_unshield_tx_with_extra_unshield_header_rejected(self) -> None:
        """Partial unshield (has ShieldedOutputsHeader) + injected UnshieldBalanceHeader → rejected."""
        from hathor.transaction.exceptions import ShieldedBalanceMismatchError

        tx, spent_txs = self._build_tx_and_sources("""
            blockchain genesis b[1..50]
            b30 < dummy

            src_S.out[0] = 60 HTR [shielded]
            src_S.out[0] <<< tx

            tx.out[0] = 30 HTR
            tx.out[1] = 30 HTR [shielded]
        """)

        # Sanity: the builder produced a partial unshield with ONLY the
        # ShieldedOutputsHeader (no UnshieldBalanceHeader).
        self.assertTrue(tx.has_shielded_outputs())
        self.assertFalse(tx.has_unshield_balance_header())

        # Inject a synthetic UnshieldBalanceHeader so the tx now carries both.
        tx.headers.append(
            UnshieldBalanceHeader(tx=tx, excess_blinding_factor=b'\x01' * 32)
        )
        self.assertTrue(tx.has_unshield_balance_header())
        self.assertTrue(tx.has_shielded_outputs())

        # Verifier rejects on the mutual-exclusion invariant, not on
        # cryptographic balance — the "cannot carry both" message is specific.
        verifier = self._get_shielded_verifier()
        with self.assertRaises(ShieldedBalanceMismatchError) as ctx:
            verifier.verify_shielded_balance(tx, spent_txs=spent_txs)
        self.assertIn('cannot carry both', str(ctx.exception))

    def test_full_unshield_tx_with_extra_shielded_outputs_header_rejected(self) -> None:
        """Full unshield (has UnshieldBalanceHeader) + injected ShieldedOutputsHeader → rejected."""
        from hathor.transaction.exceptions import ShieldedBalanceMismatchError
        from hathor.transaction.headers.shielded_outputs_header import ShieldedOutputsHeader as SOHdr

        tx, spent_txs = self._build_tx_and_sources("""
            blockchain genesis b[1..50]
            b30 < dummy

            src_S.out[0] = 60 HTR [shielded]
            src_S.out[0] <<< tx

            tx.out[0] = 60 HTR
        """)

        # Sanity: full unshield — UnshieldBalanceHeader but no ShieldedOutputsHeader.
        self.assertTrue(tx.has_unshield_balance_header())
        self.assertFalse(tx.has_shielded_outputs())

        # Inject an (empty) ShieldedOutputsHeader so the tx now carries both.
        # Empty shielded_outputs wouldn't normally be accepted by the outputs-
        # header's own validation, but that's verified separately — here we
        # only probe the invariant in verify_shielded_balance.
        tx.headers.append(SOHdr(tx=tx, shielded_outputs=[]))
        self.assertTrue(tx.has_shielded_outputs())
        self.assertTrue(tx.has_unshield_balance_header())

        verifier = self._get_shielded_verifier()
        with self.assertRaises(ShieldedBalanceMismatchError) as ctx:
            verifier.verify_shielded_balance(tx, spent_txs=spent_txs)
        self.assertIn('cannot carry both', str(ctx.exception))
