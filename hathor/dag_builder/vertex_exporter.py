# Copyright 2024 Hathor Labs
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

import ast
import os
import re
from collections import defaultdict
from types import ModuleType
from typing import Iterator, cast

from structlog import get_logger
from typing_extensions import assert_never

from hathor.conf.settings import HathorSettings
from hathor.crypto.util import decode_address, get_address_from_public_key_bytes
from hathor.daa import DAAFactory
from hathor.dag_builder.builder import FEE_KEY, NC_DEPOSIT_KEY, NC_WITHDRAWAL_KEY, DAGBuilder, DAGNode
from hathor.dag_builder.types import DAGNodeType, VertexResolverType, WalletFactoryType
from hathor.dag_builder.utils import get_literal, is_literal
from hathor.nanocontracts import Blueprint, OnChainBlueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.on_chain_blueprint import Code
from hathor.nanocontracts.types import (
    BlueprintId,
    ContractId,
    NCActionType,
    TokenUid,
    VertexId,
    blueprint_id_from_bytes,
)
from hathor.nanocontracts.utils import derive_child_contract_id, load_builtin_blueprint_for_ocb, sign_pycoin
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.base_transaction import TxInput, TxOutput
from hathor.transaction.headers.fee_header import FeeHeader, FeeHeaderEntry
from hathor.transaction.headers.nano_header import ADDRESS_LEN_BYTES
from hathor.transaction.scripts.p2pkh import P2PKH
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.wallet import BaseWallet, HDWallet, KeyPair

_TEMPLATE_PATTERN = re.compile(r'`(\w+)`')

logger = get_logger()


class VertexExporter:
    """Transform a complete DAG into vertices.
    """
    def __init__(
        self,
        *,
        builder: DAGBuilder,
        settings: HathorSettings,
        daa_factory: DAAFactory,
        genesis_wallet: BaseWallet,
        wallet_factory: WalletFactoryType,
        vertex_resolver: VertexResolverType,
        nc_catalog: NCBlueprintCatalog,
        blueprints_module: ModuleType | None,
    ) -> None:
        self._builder = builder
        self._vertices: dict[str, BaseTransaction] = {}
        self._wallets: dict[str, BaseWallet] = {}
        self._vertice_per_id: dict[bytes, BaseTransaction] = {}
        self._block_height: dict[bytes, int] = {}

        self.log = logger.new()
        self._settings = settings
        self._daa_factory = daa_factory
        self._wallet_factory = wallet_factory
        self._vertex_resolver = vertex_resolver
        self._nc_catalog = nc_catalog
        self._blueprints_module = blueprints_module

        self._wallets['genesis'] = genesis_wallet
        self._wallets['main'] = self._wallet_factory()

        self._next_nc_seqnum: defaultdict[bytes, int] = defaultdict(int)

        # Track blinding factors of shielded outputs so later txs spending them
        # can compute the excess scalar required by UnshieldBalanceHeader on
        # full-unshield txs. Keyed by (node_name, dsl_output_index) → 32-byte vbf.
        self._shielded_blinding_factors: dict[tuple[str, int], bytes] = {}
        # Generator (asset) blinding per shielded output — ZERO for amount-shielded (unblinded
        # HTR asset tag), the asset_blinding for full-shielded. Needed so a tx that SPENDS a
        # full-shielded output (whose commitment is on a BLINDED generator) balances correctly.
        self._shielded_asset_blinding_factors: dict[tuple[str, int], bytes] = {}
        # BENCHMARK-ONLY build optimization (gated by HATHOR_BENCH_CACHE_RANGE_PROOFS=1): range-proof
        # generation dominates the build wall-clock when minting many shielded UTXOs. When enabled,
        # the build uses FIXED blindings/nonce (below) so outputs of the same value yield byte-
        # identical commitments+proofs, and the proof is generated once per (value, …) then COPIED.
        # This deliberately breaks confidentiality (fixed blindings) — fine for timing — and touches
        # ONLY generation; verification is unchanged and re-verifies every proof (audited: no dedup).
        self._cache_rp: bool = os.environ.get('HATHOR_BENCH_CACHE_RANGE_PROOFS') == '1'
        self._rp_cache: dict = {}

    def _get_node(self, name: str) -> DAGNode:
        """Get node."""
        return self._builder._get_node(name)

    def get_wallet(self, name: str) -> BaseWallet:
        if name not in self._wallets:
            self._wallets[name] = self._wallet_factory()
        return self._wallets[name]

    def get_vertex_id(self, name: str) -> bytes:
        """Get the vertex id given its node name."""
        return self._vertices[name].hash

    def get_parent_block(self, block: Block) -> Block:
        """Get the parent block of a block."""
        if block.parents[0] == self._settings.GENESIS_BLOCK_HASH:
            genesis_block = Block(
                timestamp=self._settings.GENESIS_BLOCK_TIMESTAMP,
                weight=self._settings.MIN_BLOCK_WEIGHT,
            )
            genesis_block.get_height = lambda: 0  # type: ignore[method-assign]
            return genesis_block
        parent = self._vertice_per_id[block.parents[0]]
        assert isinstance(parent, Block)
        return parent

    def _create_vertex_parents(self, node: DAGNode) -> tuple[list[bytes], list[bytes]]:
        """Convert node parents to vertex parents, splitted into blocks and transactions."""
        block_parents = []
        txs_parents = []
        for pi in node.parents:
            pi_node = self._get_node(pi)
            if pi_node.type == DAGNodeType.Block or pi_node.name == 'genesis_block':
                block_parents.append(self.get_vertex_id(pi))
            else:
                txs_parents.append(self.get_vertex_id(pi))
        return block_parents, txs_parents

    def _create_vertex_txin(self, node: DAGNode) -> list[TxInput]:
        """Create TxInput objects for a node."""
        inputs = []
        for tx_name, index in node.inputs:
            txin = TxInput(tx_id=self.get_vertex_id(tx_name), index=index, data=b'')
            inputs.append(txin)
        return inputs

    def _get_token_id(self, token_name: str) -> TokenUid:
        """Return token uid for a token name."""
        node = self._get_node(token_name)
        if 'token_id' in node.attrs:
            return TokenUid(bytes.fromhex(get_literal(node.attrs['token_id'])))
        else:
            return TokenUid(self.get_vertex_id(token_name))

    def _create_vertex_txout(
        self,
        node: DAGNode,
        *,
        token_creation: bool = False
    ) -> tuple[list[bytes], list[TxOutput]]:
        """Create TxOutput objects for a node. Shielded outputs are skipped here."""
        tokens: list[bytes] = []
        outputs: list[TxOutput] = []

        for txout in node.outputs:
            assert txout is not None
            amount, token_name, attrs = txout

            # Skip shielded outputs — they are handled by add_shielded_outputs_header_if_needed
            if attrs.get('shielded') or attrs.get('full-shielded'):
                continue

            if token_name == 'HTR':
                index = 0
            elif token_creation:
                index = 1
            else:
                token_id = self._get_token_id(token_name)
                try:
                    index = tokens.index(token_id) + 1
                except ValueError:
                    tokens.append(token_id)
                    index = len(tokens)

            script = self.get_next_p2pkh_script()
            outputs.append(TxOutput(value=amount, token_data=index, script=script))

        if token_creation:
            # Create mint and melt authorities to be used by future transactions
            outputs.extend([
                TxOutput(
                    value=TxOutput.TOKEN_MINT_MASK,
                    token_data=TxOutput.TOKEN_AUTHORITY_MASK | 1,
                    script=self.get_next_p2pkh_script(),
                ),
                TxOutput(
                    value=TxOutput.TOKEN_MELT_MASK,
                    token_data=TxOutput.TOKEN_AUTHORITY_MASK | 1,
                    script=self.get_next_p2pkh_script(),
                ),
            ])

        return tokens, outputs

    def get_next_p2pkh_script(self) -> bytes:
        """Return next p2pkh script to be used in outputs."""
        address_b58 = self._wallets['main'].get_unused_address()
        return P2PKH.create_output_script(decode_address(address_b58))

    def get_min_timestamp(self, node: DAGNode) -> int:
        """Return the minimum timestamp where a node is valid."""
        # update timestamp
        deps = list(node.get_all_dependencies())
        assert deps
        timestamp = 1 + max(self._vertices[name].timestamp for name in deps if name in self._vertices)
        return timestamp

    def update_vertex_hash(self, vertex: BaseTransaction, *, fix_conflict: bool = True) -> None:
        """Resolve vertex and update its hash."""
        self._vertex_resolver(vertex)
        vertex.update_hash()

        if fix_conflict:
            max_attempts = 100
            while vertex.hash in self._vertice_per_id:
                max_attempts -= 1
                if max_attempts <= 0:
                    raise ValueError('could not resolve a conflict')
                vertex.nonce += 1
                self._vertex_resolver(vertex)
                vertex.update_hash()

    def sign_all_inputs(self, vertex: Transaction, *, node: DAGNode | None = None) -> None:
        """Sign all inputs of a vertex."""
        data_to_sign = vertex.get_sighash_all()
        for txin in vertex.inputs:
            pi = self._vertice_per_id[txin.tx_id]
            txout = pi.resolve_spent_output(txin.index)
            p2pkh = P2PKH.parse_script(txout.script)
            assert p2pkh is not None

            for wallet_name, wallet in self._wallets.items():
                try:
                    private_key = wallet.get_private_key(p2pkh.address)
                    break
                except KeyError:
                    pass
            else:
                raise ValueError('private key not found')

            public_key_bytes, signature = wallet.get_input_aux_data(data_to_sign, private_key)
            txin.data = P2PKH.create_input_data(public_key_bytes, signature)

    def create_vertex_token(self, node: DAGNode) -> TokenCreationTransaction | None:
        """Create a token given a node."""
        if 'token_id' in node.attrs:
            # Skip token creation when `token_id` is provided.
            if list(node.attrs.keys()) != ['token_id']:
                raise ValueError('no other attribute is allowed when `token_id` is provided')
            return None

        block_parents, txs_parents = self._create_vertex_parents(node)
        inputs = self._create_vertex_txin(node)
        tokens, outputs = self._create_vertex_txout(node, token_creation=True)

        assert len(block_parents) == 0
        assert len(tokens) == 0
        assert node.name != 'HTR'

        vertex = TokenCreationTransaction(parents=txs_parents, inputs=inputs, outputs=outputs)
        vertex.token_name = node.name
        vertex.token_symbol = node.name
        vertex.token_version = node.get_attr_token_version()
        vertex.timestamp = self.get_min_timestamp(node)
        self.add_headers_if_needed(node, vertex)
        self.sign_all_inputs(vertex, node=node)
        if 'weight' in node.attrs:
            vertex.weight = float(node.attrs['weight'])
        else:
            vertex.weight = self._daa_factory.minimum_tx_weight(vertex)
        self.update_vertex_hash(vertex)
        return vertex

    def create_vertex_block(self, node: DAGNode) -> Block:
        """Create a Block given a node."""
        block_parents, txs_parents = self._create_vertex_parents(node)
        inputs = self._create_vertex_txin(node)
        tokens, outputs = self._create_vertex_txout(node)

        assert len(inputs) == 0
        assert len(block_parents) == 1
        assert len(txs_parents) == 2

        height = 1 + self._block_height[block_parents[0]]

        parents = block_parents + txs_parents

        blk = Block(parents=parents, outputs=outputs)
        self.add_headers_if_needed(node, blk)
        blk.timestamp = self.get_min_timestamp(node) + self._settings.AVG_TIME_BETWEEN_BLOCKS
        blk.get_height = lambda: height  # type: ignore[method-assign]
        blk.update_hash()  # the next call fails if blk.hash is None
        if 'weight' in node.attrs:
            blk.weight = float(node.attrs['weight'])
        else:
            # synthetic blocks have no storage, so use get_parent_block (which returns a
            # fake genesis when the parent is genesis); the factory falls back to V1 when
            # the parent has no static metadata, which matches the dag_builder's V1-only
            # mode.
            daa = self._daa_factory.create_from_parent(self.get_parent_block(blk))
            blk.weight = daa.calculate_block_difficulty(blk, self.get_parent_block)
        if 'signal_bits' in node.attrs:
            blk.signal_bits = int(node.attrs['signal_bits'])
        self.update_vertex_hash(blk)
        self._block_height[blk.hash] = height
        return blk

    def _get_ast_value_bytes(self, ast_node: ast.AST) -> bytes:
        if isinstance(ast_node, ast.Constant):
            assert isinstance(ast_node.value, str)
            return bytes.fromhex(ast_node.value)
        elif isinstance(ast_node, ast.Name):
            return self.get_vertex_id(ast_node.id)
        elif isinstance(ast_node, ast.Attribute):
            assert isinstance(ast_node.value, ast.Name)
            vertex = self._vertices[ast_node.value.id]
            assert isinstance(vertex, Transaction)
            if ast_node.attr == 'nc_id':
                return vertex.get_nano_header().nc_id
            else:
                raise ValueError
        else:
            raise ValueError('unsupported ast node')

    def _parse_nc_id(self, ast_node: ast.AST) -> tuple[bytes, BlueprintId | None]:
        if not isinstance(ast_node, ast.Call):
            return self._get_ast_value_bytes(ast_node), None

        assert isinstance(ast_node.func, ast.Name)
        if ast_node.func.id != 'child_contract':
            raise ValueError(f'unknown function: {ast_node.func.id}')
        args = [self._get_ast_value_bytes(x) for x in ast_node.args]
        if len(args) != 3:
            raise ValueError('wrong number of args')
        parent_id_bytes, salt, blueprint_id_bytes = args
        parent_id = ContractId(VertexId(parent_id_bytes))
        blueprint_id = BlueprintId(VertexId(blueprint_id_bytes))
        child_contract_id = derive_child_contract_id(parent_id, salt, blueprint_id)
        return child_contract_id, blueprint_id

    def _get_next_nc_seqnum(self, nc_pubkey: bytes) -> int:
        address = get_address_from_public_key_bytes(nc_pubkey)
        cur = self._next_nc_seqnum[address]
        self._next_nc_seqnum[address] = cur + 1
        return cur

    def add_headers_if_needed(self, node: DAGNode, vertex: BaseTransaction) -> None:
        """Add the configured headers."""
        self.add_nano_header_if_needed(node, vertex)
        self.add_fee_header_if_needed(node, vertex)
        self.add_shielded_outputs_header_if_needed(node, vertex)
        self._add_or_augment_shielded_fee(node, vertex)
        self.add_unshield_balance_header_if_needed(node, vertex)
        # Ensure headers are in canonical (ascending VertexHeaderId) order.
        vertex.headers.sort(key=lambda h: h.get_header_id())

    def add_nano_header_if_needed(self, node: DAGNode, vertex: BaseTransaction) -> None:
        if 'nc_id' not in node.attrs:
            return

        nc_id, blueprint_id = self._parse_nc_id(node.get_attr_ast('nc_id'))
        nc_method_raw = node.get_attr_str('nc_method')

        if blueprint_id is None:
            if nc_method_raw.startswith('initialize('):
                blueprint_id = blueprint_id_from_bytes(nc_id)
            else:
                contract_creation_vertex = self._vertice_per_id[nc_id]
                assert contract_creation_vertex.is_nano_contract()
                assert isinstance(contract_creation_vertex, Transaction)
                contract_creation_vertex_nano_header = contract_creation_vertex.get_nano_header()
                blueprint_id = blueprint_id_from_bytes(contract_creation_vertex_nano_header.nc_id)

        blueprint_class = self._get_blueprint_class(blueprint_id)

        # allows method calls such as
        # nc2.nc_method = call_another_nc(`nc1`)
        def _replace_escaped_vertex_id(match: re.Match) -> str:
            vertex_name = match.group(1)
            if vertex_ := self._vertices.get(vertex_name):
                return f'"{vertex_.hash_hex}"'
            raise SyntaxError(f'unknown vertex: {vertex_name}')

        if raw_args_bytes := node.get_attr_str('nc_args_bytes', default=''):
            nc_method = nc_method_raw
            nc_args_bytes = bytes.fromhex(get_literal(raw_args_bytes))
        else:
            from hathor.nanocontracts.api_arguments_parser import parse_nc_method_call
            from hathor.nanocontracts.method import Method
            nc_method_raw = _TEMPLATE_PATTERN.sub(_replace_escaped_vertex_id, nc_method_raw)
            nc_method, nc_args, _ = parse_nc_method_call(blueprint_class, nc_method_raw)
            method = Method.from_callable(getattr(blueprint_class, nc_method))
            nc_args_bytes = method.serialize_args_bytes(nc_args)

        wallet_name = node.attrs.get('nc_address', f'node_{node.name}')
        wallet = self.get_wallet(wallet_name)
        assert isinstance(wallet, HDWallet)
        privkey = wallet.get_key_at_index(0)

        from hathor.transaction.headers.nano_header import NanoHeaderAction
        nc_actions = []

        def append_actions(action: NCActionType, key: str) -> None:
            actions = node.get_attr_list(key, default=[])
            for token_name, value in actions:
                assert isinstance(token_name, str)
                assert isinstance(value, int)
                token_index = 0
                if token_name != 'HTR':
                    assert isinstance(vertex, Transaction)
                    token_id = self._get_token_id(token_name)
                    if token_id not in vertex.tokens:
                        # when depositing, the token uid must be added to the tokens list
                        # because it's possible that there are no outputs with this token.
                        assert action == NCActionType.DEPOSIT
                        vertex.tokens.append(token_id)
                    token_index = 1 + vertex.tokens.index(token_id)

                nc_actions.append(NanoHeaderAction(
                    type=action,
                    token_index=token_index,
                    amount=value,
                ))

        append_actions(NCActionType.DEPOSIT, NC_DEPOSIT_KEY)
        append_actions(NCActionType.WITHDRAWAL, NC_WITHDRAWAL_KEY)

        from hathor.transaction.headers import NanoHeader
        nano_header = NanoHeader(
            # Even though we know the NanoHeader only supports Transactions, we force the typing here so we can test
            # that other types of vertices such as blocks would fail verification by using an unsupported header.
            tx=cast(Transaction, vertex),
            nc_seqnum=0,
            nc_id=nc_id,
            nc_method=nc_method,
            nc_args_bytes=nc_args_bytes,
            nc_actions=nc_actions,
            nc_address=b'\x00' * ADDRESS_LEN_BYTES,
            nc_script=b'',
        )
        vertex.headers.append(nano_header)

        if isinstance(vertex, Transaction):
            sign_pycoin(nano_header, privkey)

        if 'nc_seqnum' in node.attrs:
            nano_header.nc_seqnum = int(node.attrs['nc_seqnum'])
        else:
            nano_header.nc_seqnum = self._get_next_nc_seqnum(nano_header.nc_address)

    def add_fee_header_if_needed(self, node: DAGNode, vertex: BaseTransaction) -> None:
        """Add a FeeHeader if one is configured."""
        if FEE_KEY not in node.attrs:
            return
        assert isinstance(vertex, Transaction)

        fees = node.get_attr_list(FEE_KEY)

        entries = []
        for token_name, fee_amount in fees:
            assert isinstance(token_name, str)
            assert isinstance(fee_amount, int)
            token_index = 0
            if token_name != 'HTR':
                token_id = self._get_token_id(token_name)
                if token_id not in vertex.tokens:
                    # when paying fees, the token uid must be added to the tokens list
                    # because it's possible that there are no outputs with this token.
                    vertex.tokens.append(token_id)
                token_index = 1 + vertex.tokens.index(token_id)

            entry = FeeHeaderEntry(token_index=token_index, amount=fee_amount)
            entries.append(entry)

        fee_header = FeeHeader(
            settings=vertex._settings,
            tx=vertex,
            fees=entries,
        )
        vertex.headers.append(fee_header)

    def _add_or_augment_shielded_fee(self, node: DAGNode, vertex: BaseTransaction) -> None:
        """Add or augment a FeeHeader with the shielded output fee."""
        if not isinstance(vertex, Transaction):
            return

        from hathor.verification.transaction_verifier import TransactionVerifier
        shielded_fee = TransactionVerifier.calculate_shielded_fee(self._settings, vertex)
        if shielded_fee == 0:
            return

        # Look for an existing FeeHeader
        existing_fee_header: FeeHeader | None = None
        for header in vertex.headers:
            if isinstance(header, FeeHeader):
                existing_fee_header = header
                break

        if existing_fee_header is not None:
            # Augment the existing FeeHeader: find HTR entry and add shielded fee
            new_fees: list[FeeHeaderEntry] = []
            found_htr = False
            for entry in existing_fee_header.fees:
                if entry.token_index == 0 and not found_htr:
                    # Augment the HTR fee entry
                    new_fees.append(FeeHeaderEntry(token_index=0, amount=entry.amount + shielded_fee))
                    found_htr = True
                else:
                    new_fees.append(entry)
            if not found_htr:
                new_fees.append(FeeHeaderEntry(token_index=0, amount=shielded_fee))
            existing_fee_header.fees = new_fees
        else:
            # Create a new FeeHeader with just the shielded fee
            fee_header = FeeHeader(
                settings=vertex._settings,
                tx=vertex,
                fees=[FeeHeaderEntry(token_index=0, amount=shielded_fee)],
            )
            vertex.headers.append(fee_header)

    def _range_proof(self, key: tuple, gen_fn) -> bytes:
        """BENCHMARK-ONLY: return the cached range proof for `key`, generating+caching it on a miss.
        When caching is off, always generate fresh (key unused). Generation only — never verification."""
        if not self._cache_rp:
            return gen_fn()
        rp = self._rp_cache.get(key)
        if rp is None:
            rp = gen_fn()
            self._rp_cache[key] = rp
        return rp

    def add_shielded_outputs_header_if_needed(self, node: DAGNode, vertex: BaseTransaction) -> None:
        """Collect outputs with [shielded] or [full-shielded] attrs into a ShieldedOutputsHeader.

        BALANCE RECONCILIATION (benchmark patch — see below).
        The Pedersen balance the verifier checks is ``sum(C_in) == sum(C_out) + fee*H``
        (``verify_shielded_balance``). A shielded output's commitment is
        ``C = v*H + r*G``; transparent inputs/outputs/fees contribute ``v*H`` with ``r = 0``.
        For the equation to hold the *value* sides must match (guaranteed by the filler)
        AND the value-blinding factors must cancel: ``sum(r_in) == sum(r_out)``. The
        upstream builder assigned every shielded output an independent ``os.urandom(32)``
        blinding and never reconciled them, so ``sum(r_out) != 0`` and the equation could
        not hold — every shielded-*output* tx failed verification. (No upstream test
        caught this: none drives a shielded-output tx through ``verify_shielded_balance``.)

        Fix: assign random blindings to all but the LAST shielded output, then set the
        last output's blinding to the residual via ``compute_balancing_blinding_factor``,
        so ``sum(r_out)`` reconciles against the inputs (== 0 for all-transparent inputs).
        Mirrors ``hathor_tests/tx/test_shielded_audit_equation.py::_shield_in_tx`` and the
        sibling ``add_unshield_balance_header_if_needed`` (which reads input amounts the
        same way). Done in two passes: (1) collect specs + finalize blindings,
        (2) build commitments/proofs with the finalized blindings.
        """
        import os

        from hathor.crypto.shielded import (
            compute_balancing_blinding_factor,
            create_asset_commitment,
            create_commitment,
            create_range_proof,
            create_surjection_proof,
            derive_asset_tag,
            derive_tag,
        )
        from hathor.crypto.shielded.ecdh import (
            derive_ecdh_shared_secret,
            derive_rewind_nonce,
            generate_ephemeral_keypair,
        )
        from hathor.transaction.headers.shielded_outputs_header import ShieldedOutputsHeader
        from hathor.transaction.shielded_tx_output import AmountShieldedOutput, FullShieldedOutput, ShieldedOutput

        ZERO = bytes(32)  # zero scalar (transparent entries carry blinding == 0)

        # A FULL-shielded output whose tx also SPENDS a full-shielded input cannot use the fixed
        # asset-blinding: it would share its inputs' (equally-fixed) asset generator, making the
        # surjection re-blind difference ZERO — which secp256k1-zkp refuses to prove. Such txs
        # (the few MEASURED txs) fall back to random blindings; the bulk SOURCE minting (transparent-
        # funded, so no full-shielded input) keeps the fixed blindings and stays cacheable.
        # A non-ZERO recorded asset-blinding == a full-shielded input; amount-shielded/transparent
        # inputs record ZERO (unblinded generator) and never collide, so they don't force a fallback.
        spends_full_shielded = self._cache_rp and any(
            self._shielded_asset_blinding_factors.get((tx_name, out_idx), ZERO) != ZERO
            for (tx_name, out_idx) in node.inputs
        )

        # ---- PASS 1: collect one spec per shielded output + assign blindings -------------
        specs: list[dict] = []
        for dsl_index, txout in enumerate(node.outputs):
            if txout is None:
                continue
            amount, token_name, attrs = txout
            if not attrs.get('shielded') and not attrs.get('full-shielded'):
                continue

            assert isinstance(vertex, Transaction)
            token_uid = self._settings.HATHOR_TOKEN_UID if token_name == 'HTR' else self._get_token_id(token_name)
            if len(token_uid) < 32:
                token_uid = token_uid.ljust(32, b'\x00')

            script = self.get_next_p2pkh_script()
            ephemeral_privkey, ephemeral_pubkey = generate_ephemeral_keypair()
            recipient_pubkey = self._get_recipient_pubkey_from_script(script)
            if recipient_pubkey is not None:
                nonce = derive_rewind_nonce(derive_ecdh_shared_secret(ephemeral_privkey, recipient_pubkey))
            else:
                nonce = None
                ephemeral_pubkey = b''  # No ECDH possible without recipient pubkey

            is_full = bool(attrs.get('full-shielded'))
            if self._cache_rp and not (is_full and spends_full_shielded):
                # BENCHMARK build cache (see __init__): FIXED value-blinding, asset-blinding and
                # rewind-nonce so outputs of the same value yield identical commitments → cacheable
                # proofs. The last output is still reconciled to the balance residual below.
                out_blinding = b'\x11' * 32
                out_asset_blinding = (b'\x22' * 32) if is_full else ZERO
                out_nonce = b'\x33' * 32
            else:
                out_blinding = os.urandom(32)                    # value blinding (last is reconciled below)
                out_asset_blinding = os.urandom(32) if is_full else ZERO  # generator blinding (full only)
                out_nonce = nonce
            specs.append({
                'dsl_index': dsl_index,
                'amount': amount,
                'token_name': token_name,
                'token_uid': token_uid,
                'script': script,
                'ephemeral_pubkey': ephemeral_pubkey,
                'nonce': out_nonce,
                'is_full': is_full,
                'blinding': out_blinding,
                'asset_blinding': out_asset_blinding,
            })

        if not specs:
            return

        # ---- reconcile the LAST output's value blinding so sum(C_in)==sum(C_out)+fee*H ----
        # Inputs as the verifier folds them: spent transparent outputs -> (value, 0, 0);
        # spent shielded outputs -> (value, recorded_vbf, 0). (Benchmark shield txs spend
        # transparent UTXOs, so blindings are 0; shielded inputs are handled for generality.)
        input_entries: list[tuple[int, bytes, bytes]] = []
        for tx_name, out_idx in node.inputs:
            spent_output = self._get_node(tx_name).outputs[out_idx]
            assert spent_output is not None
            in_bf = self._shielded_blinding_factors.get((tx_name, out_idx), ZERO)
            in_gbf = self._shielded_asset_blinding_factors.get((tx_name, out_idx), ZERO)
            input_entries.append((spent_output.amount, in_bf, in_gbf))

        # Other outputs (everything except the last shielded output): transparent outputs
        # already on the vertex, all fees, and the first n-1 shielded outputs.
        other_entries: list[tuple[int, bytes, bytes]] = [(o.value, ZERO, ZERO) for o in vertex.outputs]
        total_fee = 0
        for header in vertex.headers:                              # explicit FeeHeader(s) already added
            for fee_entry in getattr(header, 'fees', []):
                if fee_entry.token_index == 0:                     # HTR
                    total_fee += fee_entry.amount
        for s in specs:                                            # the shielded fee added later by
            total_fee += (self._settings.FEE_PER_FULL_SHIELDED_OUTPUT if s['is_full']    # _add_or_augment_shielded_fee
                          else self._settings.FEE_PER_AMOUNT_SHIELDED_OUTPUT)
        if total_fee:
            other_entries.append((total_fee, ZERO, ZERO))
        for s in specs[:-1]:
            other_entries.append((s['amount'], s['blinding'], s['asset_blinding']))

        last = specs[-1]
        last['blinding'] = compute_balancing_blinding_factor(
            last['amount'], last['asset_blinding'], input_entries, other_entries,
        )
        for s in specs:   # record final value + asset blindings so later txs spending these reconcile
            self._shielded_blinding_factors[(node.name, s['dsl_index'])] = s['blinding']
            self._shielded_asset_blinding_factors[(node.name, s['dsl_index'])] = s['asset_blinding']

        # ---- surjection domain (bug #3 fix): one (generator, raw_tag, asset_blinding) entry per
        # input, MIRRORING verify_surjection_proofs so a FullShieldedOutput verifies for ANY input
        # set — not just a single transparent input. Verifier domain generator per input:
        # transparent / amount-shielded -> derive_asset_tag(uid) (unblinded); full-shielded -> the
        # spent output's asset_commitment (blinded). Same order as tx.inputs (built from node.inputs);
        # computed once (shared by all full-shielded outputs of this tx).
        surj_domain: list[tuple[bytes, bytes, bytes]] = []
        if any(s['is_full'] for s in specs):
            for tx_name, out_idx in node.inputs:
                spent = self._get_node(tx_name).outputs[out_idx]
                in_uid = self._settings.HATHOR_TOKEN_UID if spent.token == 'HTR' else self._get_token_id(spent.token)
                if len(in_uid) < 32:
                    in_uid = in_uid.ljust(32, b'\x00')
                in_raw = derive_tag(in_uid)
                if spent.attrs.get('full-shielded'):
                    in_abf = self._shielded_asset_blinding_factors.get((tx_name, out_idx), ZERO)
                    in_gen = create_asset_commitment(in_raw, in_abf)
                else:  # transparent or amount-shielded input -> unblinded asset tag
                    in_gen = derive_asset_tag(in_uid)
                    in_abf = ZERO
                surj_domain.append((in_gen, in_raw, in_abf))

        # ---- PASS 2: build commitments/proofs with the finalized blindings ----------------
        shielded_outputs: list[ShieldedOutput] = []
        for s in specs:
            amount, blinding, token_uid = s['amount'], s['blinding'], s['token_uid']
            script, nonce, ephemeral_pubkey = s['script'], s['nonce'], s['ephemeral_pubkey']

            if s['is_full']:
                # FullShieldedOutput: both amount and token hidden
                raw_tag = derive_tag(token_uid)
                asset_blinding = s['asset_blinding']
                asset_comm = create_asset_commitment(raw_tag, asset_blinding)
                commitment = create_commitment(amount, blinding, asset_comm)

                # Embed token_uid(32B) + asset_blinding(32B) in range proof message
                message = token_uid + asset_blinding
                range_proof = self._range_proof(
                    (True, amount, blinding, asset_blinding, nonce, token_uid),
                    lambda: create_range_proof(amount, blinding, commitment, asset_comm,
                                               message=message, nonce=nonce),
                )

                # Surjection over the REAL input domain (bug #3 fix; built above as surj_domain).
                surjection_proof = create_surjection_proof(raw_tag, asset_blinding, surj_domain)

                output: ShieldedOutput = FullShieldedOutput(
                    commitment=commitment,
                    range_proof=range_proof,
                    script=script,
                    asset_commitment=asset_comm,
                    surjection_proof=surjection_proof,
                    ephemeral_pubkey=ephemeral_pubkey,
                )
            else:
                # AmountShieldedOutput: amount hidden, token visible
                asset_tag = derive_asset_tag(token_uid)
                commitment = create_commitment(amount, blinding, asset_tag)
                range_proof = self._range_proof(
                    (False, amount, blinding, ZERO, nonce, token_uid),
                    lambda: create_range_proof(amount, blinding, commitment, asset_tag, nonce=nonce),
                )

                # Resolve token_data index
                if s['token_name'] == 'HTR':
                    token_data = 0
                else:
                    token_id = self._get_token_id(s['token_name'])
                    if token_id in vertex.tokens:
                        token_data = 1 + vertex.tokens.index(token_id)
                    else:
                        vertex.tokens.append(token_id)
                        token_data = len(vertex.tokens)

                output = AmountShieldedOutput(
                    commitment=commitment,
                    range_proof=range_proof,
                    script=script,
                    token_data=token_data,
                    ephemeral_pubkey=ephemeral_pubkey,
                )

            shielded_outputs.append(output)

        assert isinstance(vertex, Transaction)
        header = ShieldedOutputsHeader(tx=vertex, shielded_outputs=shielded_outputs)
        vertex.headers.append(header)

    def add_unshield_balance_header_if_needed(self, node: DAGNode, vertex: BaseTransaction) -> None:
        """Attach an UnshieldBalanceHeader when this is a full unshield.

        A full unshield is a tx with at least one shielded input and no
        shielded outputs. The scalar we compute is
        `excess = sum(r_in) − sum(r_out) = sum(r_in)` (transparent outputs
        have blinding factor 0), so the verifier can synthesise the
        missing `excess*G` on the output side of the balance equation.
        """
        from hathor.crypto.shielded import compute_balancing_blinding_factor
        from hathor.transaction.headers.unshield_balance_header import UnshieldBalanceHeader

        if not isinstance(vertex, Transaction):
            return

        # Gather shielded input blinding factors.
        input_entries: list[tuple[int, bytes, bytes]] = []
        for tx_name, out_idx in node.inputs:
            bf = self._shielded_blinding_factors.get((tx_name, out_idx))
            if bf is None:
                continue  # transparent input (vbf = 0, no contribution)
            spent_node = self._get_node(tx_name)
            spent_output = spent_node.outputs[out_idx]
            assert spent_output is not None
            input_entries.append((spent_output.amount, bf, bytes(32)))

        if not input_entries:
            # No shielded inputs — no excess needed. Verifier invariant (3)
            # would reject a stray excess here, so we simply don't attach one.
            return

        # If there are shielded outputs, the ShieldedOutputsHeader path
        # balances blinding factors through compute_balancing_blinding_factor
        # on the last shielded output — no excess is needed (and attaching
        # both headers would violate the mutual-exclusion invariant).
        has_shielded_output = any(
            txout is not None and (txout.attrs.get('shielded') or txout.attrs.get('full-shielded'))
            for txout in node.outputs
        )
        if has_shielded_output:
            return

        # Build the "other outputs" set for the balancing computation. All
        # outputs (and any transparent fees) are unblinded, so only the
        # structure matters; exact values drop out when gbf = 0.
        other_outputs: list[tuple[int, bytes, bytes]] = []
        for txout in node.outputs:
            if txout is None:
                continue
            other_outputs.append((txout.amount, bytes(32), bytes(32)))
        fees = node.get_attr_list(FEE_KEY, default=[])
        for _token_name, fee_amount in fees:
            assert isinstance(fee_amount, int)
            other_outputs.append((fee_amount, bytes(32), bytes(32)))

        excess = compute_balancing_blinding_factor(
            0,
            bytes(32),
            input_entries,
            other_outputs,
        )

        header = UnshieldBalanceHeader(tx=vertex, excess_blinding_factor=excess)
        vertex.headers.append(header)

    def _get_recipient_pubkey_from_script(self, script: bytes) -> bytes | None:
        """Extract the recipient's compressed public key from a P2PKH script.

        Looks up the address in all wallets to find the corresponding public key.
        Returns None if the public key cannot be determined.
        """
        from hathor.transaction.scripts.p2pkh import P2PKH as P2PKHScript

        p2pkh = P2PKHScript.parse_script(script)
        if p2pkh is None:
            return None

        for wallet_name, wallet in self._wallets.items():
            if p2pkh.address in wallet.keys:
                try:
                    from hathor.crypto.shielded.ecdh import extract_key_bytes
                    private_key = wallet.get_private_key(p2pkh.address)
                    _, pubkey_bytes = extract_key_bytes(private_key)
                    return pubkey_bytes
                except TypeError:
                    self.log.warning(
                        'failed to extract pubkey from wallet key',
                        wallet=wallet_name,
                        address=p2pkh.address,
                    )
                    continue
        return None

    def create_vertex_on_chain_blueprint(self, node: DAGNode) -> OnChainBlueprint:
        """Create an OnChainBlueprint given a node."""
        block_parents, txs_parents = self._create_vertex_parents(node)
        inputs = self._create_vertex_txin(node)
        tokens, outputs = self._create_vertex_txout(node)

        assert len(block_parents) == 0
        ocb = OnChainBlueprint(parents=txs_parents, inputs=inputs, outputs=outputs, tokens=tokens)
        self.add_headers_if_needed(node, ocb)
        code_attr = node.get_attr_str('ocb_code')

        if is_literal(code_attr):
            code_literal = get_literal(code_attr)
            try:
                code_bytes = bytes.fromhex(code_literal)
            except ValueError:
                code_str = code_literal
            else:
                code_str = code_bytes.decode()
        else:
            assert self._blueprints_module is not None
            filename, _, class_name = code_attr.partition(',')
            filename, class_name = filename.strip(), class_name.strip()
            if not filename or not class_name:
                raise SyntaxError(f'missing blueprint filename or class name: {code_attr}')
            code_str = load_builtin_blueprint_for_ocb(filename, class_name, self._blueprints_module)

        ocb.code = Code.from_python_code(code_str, self._settings)
        ocb.timestamp = self.get_min_timestamp(node)
        self.sign_all_inputs(ocb, node=node)

        private_key_literal = node.get_required_literal('ocb_private_key')
        private_key_bytes = bytes.fromhex(private_key_literal)
        password_literal = node.get_required_literal('ocb_password')
        password_bytes = bytes.fromhex(password_literal)
        key = KeyPair(private_key_bytes)
        private_key = key.get_private_key(password_bytes)
        ocb.sign(private_key)

        if 'weight' in node.attrs:
            ocb.weight = float(node.attrs['weight'])
        else:
            ocb.weight = self._daa_factory.minimum_tx_weight(ocb)

        self.update_vertex_hash(ocb)
        return ocb

    def create_vertex_transaction(self, node: DAGNode, *, cls: type[Transaction] = Transaction) -> Transaction:
        """Create a Transaction given a node."""
        block_parents, txs_parents = self._create_vertex_parents(node)
        inputs = self._create_vertex_txin(node)
        tokens, outputs = self._create_vertex_txout(node)

        assert len(block_parents) == 0
        tx = cls(parents=txs_parents, inputs=inputs, outputs=outputs, tokens=tokens)
        tx.timestamp = self.get_min_timestamp(node)
        self.add_headers_if_needed(node, tx)
        self.sign_all_inputs(tx, node=node)
        if 'weight' in node.attrs:
            tx.weight = float(node.attrs['weight'])
        else:
            tx.weight = self._daa_factory.minimum_tx_weight(tx)
        self.update_vertex_hash(tx)
        return tx

    def create_genesis_vertex(self, node: DAGNode) -> BaseTransaction:
        """Create a genesis vertex given a node."""
        vertex: BaseTransaction

        if node.name == 'genesis_block':
            vertex = Block()
            vertex.hash = self._settings.GENESIS_BLOCK_HASH
            vertex.timestamp = self._settings.GENESIS_BLOCK_TIMESTAMP
            txout = TxOutput(
                value=self._settings.GENESIS_TOKENS,
                token_data=0,
                script=self._settings.GENESIS_OUTPUT_SCRIPT
            )
            vertex.outputs.append(txout)

        elif node.name == 'genesis_1':
            vertex = Transaction()
            vertex.hash = self._settings.GENESIS_TX1_HASH
            vertex.timestamp = self._settings.GENESIS_TX1_TIMESTAMP

        elif node.name == 'genesis_2':
            vertex = Transaction()
            vertex.hash = self._settings.GENESIS_TX2_HASH
            vertex.timestamp = self._settings.GENESIS_TX2_TIMESTAMP

        else:
            raise NotImplementedError(node.name)

        return vertex

    def create_vertex(self, node: DAGNode) -> BaseTransaction | None:
        """Create a vertex."""
        vertex: BaseTransaction | None

        match node.type:
            case DAGNodeType.Block:
                vertex = self.create_vertex_block(node)

            case DAGNodeType.Token:
                vertex = self.create_vertex_token(node)

            case DAGNodeType.Transaction:
                vertex = self.create_vertex_transaction(node)

            case DAGNodeType.Genesis:
                vertex = self.create_genesis_vertex(node)

            case DAGNodeType.OnChainBlueprint:
                vertex = self.create_vertex_on_chain_blueprint(node)

            case DAGNodeType.Unknown:
                raise AssertionError('dag type should be known at this point')

            case _:
                assert_never(node.type)

        if vertex is None:
            # skip it
            return None

        assert vertex is not None
        assert vertex.hash not in self._vertice_per_id
        assert node.name not in self._vertices
        self._vertice_per_id[vertex.hash] = vertex
        self._vertices[node.name] = vertex
        vertex.name = node.name
        return vertex

    def export(self) -> Iterator[tuple[DAGNode, BaseTransaction]]:
        """Yield all pairs (node, vertex)."""
        self._block_height[self._settings.GENESIS_BLOCK_HASH] = 0

        vertex: BaseTransaction | None

        for node in self._builder.topological_sorting():
            vertex = self.create_vertex(node)
            if vertex is None:
                continue
            if node.type is not DAGNodeType.Genesis:
                yield node, vertex

    def _get_blueprint_class(self, blueprint_id: BlueprintId) -> type[Blueprint]:
        """Get a blueprint class from the catalog or from our own on-chain blueprints."""
        if blueprint_class := self._nc_catalog.get_blueprint_class(blueprint_id):
            return blueprint_class
        ocb = self._vertice_per_id.get(blueprint_id)
        if ocb is None or not isinstance(ocb, OnChainBlueprint):
            raise SyntaxError(f'{blueprint_id.hex()} is not a valid blueprint id')
        return ocb.get_blueprint_class()
