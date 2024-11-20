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

from typing import Iterator

from hathor.conf.settings import HathorSettings
from hathor.crypto.util import decode_address
from hathor.daa import DifficultyAdjustmentAlgorithm
from hathor.dag_builder.builder import DAGBuilder, DAGNode
from hathor.dag_builder.types import DAGNodeType, VertexResolverType, WalletFactoryType
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.base_transaction import TxInput, TxOutput
from hathor.transaction.scripts.p2pkh import P2PKH
from hathor.transaction.token_creation_tx import TokenCreationTransaction
from hathor.wallet import BaseWallet


class VertexExporter:
    """Transform a complete DAG into vertices.
    """
    def __init__(
        self,
        *,
        node_iter: Iterator[DAGNode],
        builder: DAGBuilder,
        settings: HathorSettings,
        daa: DifficultyAdjustmentAlgorithm,
        genesis_wallet: BaseWallet,
        wallet_factory: WalletFactoryType,
        vertex_resolver: VertexResolverType,
    ) -> None:
        self._node_iter = node_iter
        self._builder = builder
        self._vertices: dict[str, BaseTransaction] = {}
        self._wallets: dict[str, BaseWallet] = {}
        self._vertice_per_id: dict[bytes, BaseTransaction] = {}
        self._block_height: dict[bytes, int] = {}

        self._settings = settings
        self._daa = daa
        self._wallet_factory = wallet_factory
        self._vertex_resolver = vertex_resolver

        self._wallets['genesis'] = genesis_wallet
        self._wallets['main'] = self._wallet_factory()

    def _get_node(self, name: str) -> DAGNode:
        """Get node."""
        return self._builder._get_node(name)

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

    def update_vertex_hash(self, vertex: BaseTransaction) -> None:
        """Resolve vertex and update its hash."""
        self._vertex_resolver(vertex)
        vertex.update_hash()

    def sign_all_inputs(self, node: DAGNode, vertex: Transaction) -> None:
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
        self.sign_all_inputs(node, vertex)
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

    def create_vertex_transaction(self, node: DAGNode) -> Transaction:
        """Create a Transaction given a node."""
        block_parents, txs_parents = self._create_vertex_parents(node)
        inputs = self._create_vertex_txin(node)
        tokens, outputs = self._create_vertex_txout(node)

        assert len(block_parents) == 0
        tx = Transaction(parents=txs_parents, inputs=inputs, outputs=outputs, tokens=tokens)
        tx.timestamp = self.get_min_timestamp(node)
        self.sign_all_inputs(node, tx)
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

            case _:
                raise NotImplementedError(node.type)

        assert vertex is not None
        self._vertice_per_id[vertex.hash] = vertex
        self._vertices[node.name] = vertex
        return vertex

    def export(self) -> Iterator[tuple[DAGNode, BaseTransaction]]:
        """Yield all pairs (node, vertex)."""
        self._block_height[self._settings.GENESIS_BLOCK_HASH] = 0

        vertex: BaseTransaction | None

        for node in self._node_iter:
            vertex = self.create_vertex(node)
            if node.type is not DAGNodeType.Genesis:
                yield node, vertex
