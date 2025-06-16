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
import re
from collections import defaultdict
from types import ModuleType
from typing import Iterator

from typing_extensions import assert_never

from hathor.conf.settings import HathorSettings
from hathor.crypto.util import decode_address, get_address_from_public_key_bytes
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.dag_builder.builder import DAGBuilder, DAGNode
from hathor.dag_builder.types import DAGNodeType, VertexResolverType, WalletFactoryType
from hathor.dag_builder.utils import get_literal, is_literal
from hathor.nanocontracts import Blueprint, OnChainBlueprint
from hathor.nanocontracts.catalog import NCBlueprintCatalog
from hathor.nanocontracts.on_chain_blueprint import Code
from hathor.nanocontracts.types import BlueprintId, ContractId, VertexId
from hathor.nanocontracts.utils import derive_child_contract_id, load_builtin_blueprint_for_ocb
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.base_transaction import TxInput, TxOutput
from hathor.transaction.scripts.p2pkh import P2PKH
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.wallet import BaseWallet, KeyPair

_TEMPLATE_PATTERN = re.compile(r'`(\w+)`')


class VertexExporter:
    """Transform a complete DAG into vertices.
    """
    def __init__(
        self,
        *,
        builder: DAGBuilder,
        settings: HathorSettings,
        daa: DifficultyAdjustmentAlgorithm,
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

        self._settings = settings
        self._daa = daa
        self._wallet_factory = wallet_factory
        self._vertex_resolver = vertex_resolver
        self._nc_catalog = nc_catalog
        self._blueprints_module = blueprints_module

        self._wallets['genesis'] = genesis_wallet
        self._wallets['main'] = self._wallet_factory()

        self._next_nc_seqnum: defaultdict[bytes, int] = defaultdict(int)

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
            if pi_node.type is DAGNodeType.Block or pi_node.name == 'genesis_block':
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

    def _create_vertex_txout(
        self,
        node: DAGNode,
        *,
        token_creation: bool = False
    ) -> tuple[list[bytes], list[TxOutput]]:
        """Create TxOutput objects for a node."""
        tokens: list[bytes] = []
        outputs: list[TxOutput] = []

        for txout in node.outputs:
            assert txout is not None
            amount, token_name, attrs = txout
            if token_name == 'HTR':
                index = 0
            elif token_creation:
                index = 1
            else:
                token_uid = self.get_vertex_id(token_name)
                try:
                    index = tokens.index(token_uid) + 1
                except ValueError:
                    tokens.append(token_uid)
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
        timestamp = 1 + max(self._vertices[name].timestamp for name in deps)
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
            txout = pi.outputs[txin.index]
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

    def create_vertex_token(self, node: DAGNode) -> TokenCreationTransaction:
        """Create a token given a node."""
        block_parents, txs_parents = self._create_vertex_parents(node)
        inputs = self._create_vertex_txin(node)
        tokens, outputs = self._create_vertex_txout(node, token_creation=True)

        assert len(block_parents) == 0
        assert len(tokens) == 0
        assert node.name != 'HTR'

        vertex = TokenCreationTransaction(parents=txs_parents, inputs=inputs, outputs=outputs)
        vertex.token_name = node.name
        vertex.token_symbol = node.name
        vertex.timestamp = self.get_min_timestamp(node)
        self.sign_all_inputs(vertex, node=node)
        if 'weight' in node.attrs:
            vertex.weight = float(node.attrs['weight'])
        else:
            vertex.weight = self._daa.minimum_tx_weight(vertex)
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
        blk.timestamp = self.get_min_timestamp(node) + self._settings.AVG_TIME_BETWEEN_BLOCKS
        blk.get_height = lambda: height  # type: ignore[method-assign]
        blk.update_hash()  # the next call fails is blk.hash is None
        if 'weight' in node.attrs:
            blk.weight = float(node.attrs['weight'])
        else:
            blk.weight = self._daa.calculate_block_difficulty(blk, self.get_parent_block)
        self.update_vertex_hash(blk)
        self._block_height[blk.hash] = height
        return blk

    def _get_ast_value_bytes(self, ast_node: ast.AST) -> bytes:
        if isinstance(ast_node, ast.Constant):
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

    def create_vertex_on_chain_blueprint(self, node: DAGNode) -> OnChainBlueprint:
        """Create an OnChainBlueprint given a node."""
        block_parents, txs_parents = self._create_vertex_parents(node)
        inputs = self._create_vertex_txin(node)
        tokens, outputs = self._create_vertex_txout(node)

        assert len(block_parents) == 0
        ocb = OnChainBlueprint(parents=txs_parents, inputs=inputs, outputs=outputs, tokens=tokens)
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
            ocb.weight = self._daa.minimum_tx_weight(ocb)

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
        self.sign_all_inputs(tx, node=node)
        if 'weight' in node.attrs:
            tx.weight = float(node.attrs['weight'])
        else:
            tx.weight = self._daa.minimum_tx_weight(tx)
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

    def create_vertex(self, node: DAGNode) -> BaseTransaction:
        """Create a vertex."""
        vertex: BaseTransaction

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
