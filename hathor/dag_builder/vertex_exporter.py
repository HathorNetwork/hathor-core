from typing import Iterator

from hathor.crypto.util import decode_address
from hathor.dag_builder.builder import DAGBuilder, DAGNode
from hathor.transaction import BaseTransaction, Block, Transaction
from hathor.transaction.base_transaction import TxInput, TxOutput
from hathor.transaction.scripts.p2pkh import P2PKH
from hathor.transaction.token_creation_tx import TokenCreationTransaction


class VertexExporter:
    def __init__(self, builder: DAGBuilder) -> None:
        self._builder = builder
        self._vertices = {}
        self._wallets = {}
        self._vertice_per_id: dict[bytes, BaseTransaction] = {}
        self._block_height: dict[bytes, int] = {}

    def _get_node(self, name, *, default_type='unknown'):
        return self._builder._get_node(name, default_type=default_type)

    def set_settings(self, settings) -> None:
        self._settings = settings

    def set_daa(self, daa) -> None:
        self._daa = daa

    def set_genesis_wallet(self, wallet) -> None:
        self._wallets['genesis'] = wallet

    def set_wallet_factory(self, wallet_factory) -> None:
        self._wallet_factory = wallet_factory
        self._wallets['main'] = self._wallet_factory()

    def get_vertex_id(self, name: str) -> bytes:
        return self._vertices[name].hash

    def get_parent_block(self, block: Block) -> Block:
        if block.parents[0] == self._settings.GENESIS_BLOCK_HASH:
            genesis_block = Block(
                timestamp=self._settings.GENESIS_BLOCK_TIMESTAMP,
                weight=self._settings.MIN_BLOCK_WEIGHT,
            )
            genesis_block.get_height = lambda: 0
            return genesis_block
        return self._vertice_per_id[block.parents[0]]

    def _create_vertex_parents(self, node: DAGNode) -> tuple[list[bytes], list[bytes]]:
        block_parents = []
        txs_parents = []
        for pi in node.parents:
            pi_node = self._get_node(pi)
            if pi_node.type == 'block' or pi_node.name == 'genesis_block':
                block_parents.append(self.get_vertex_id(pi))
            else:
                txs_parents.append(self.get_vertex_id(pi))
        return block_parents, txs_parents

    def _create_vertex_txin(self, node: DAGNode) -> list[TxInput]:
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
        tokens = []
        outputs = []

        for amount, token_name, attrs in node.outputs:
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
        address_b58 = self._wallets['main'].get_unused_address()
        return P2PKH.create_output_script(decode_address(address_b58))

    def get_min_timestamp(self, node: DAGNode) -> int:
        # update timestamp
        deps = list(node.get_all_dependencies())
        assert deps
        timestamp = 1 + max(self._vertices[name].timestamp for name in deps)
        return timestamp

    def sign_all_inputs(self, node: DAGNode, vertex: BaseTransaction) -> None:
        data_to_sign = vertex.get_sighash_all()
        for txin in vertex.inputs:
            pi = self._vertice_per_id[txin.tx_id]
            txout = pi.outputs[txin.index]
            p2pkh = P2PKH.parse_script(txout.script)

            for wallet_name, wallet in self._wallets.items():
                try:
                    private_key = wallet.get_private_key(p2pkh.address)
                    break
                except KeyError:
                    pass

            public_key_bytes, signature = wallet.get_input_aux_data(data_to_sign, private_key)
            txin.data = P2PKH.create_input_data(public_key_bytes, signature)

    def create_vertex_token(self, node: DAGNode) -> TokenCreationTransaction | None:
        block_parents, txs_parents = self._create_vertex_parents(node)
        inputs = self._create_vertex_txin(node)
        tokens, outputs = self._create_vertex_txout(node, token_creation=True)

        assert len(block_parents) == 0
        assert len(tokens) == 0

        if node.name == 'HTR':
            # do nothing
            return None
        vertex = TokenCreationTransaction(parents=txs_parents, inputs=inputs, outputs=outputs)
        vertex.token_name = node.name
        vertex.token_symbol = node.name
        vertex.timestamp = self.get_min_timestamp(node)
        vertex.weight = self._daa.minimum_tx_weight(vertex)
        self.sign_all_inputs(node, vertex)
        vertex.update_hash()
        return vertex

    def create_vertex_block(self, node: DAGNode) -> Block:
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
        blk.get_height = lambda: height
        blk.weight = self._daa.calculate_block_difficulty(blk, self.get_parent_block)
        blk.update_hash()
        self._block_height[blk.hash] = height
        return blk

    def create_vertex_transaction(self, node: DAGNode) -> Transaction:
        block_parents, txs_parents = self._create_vertex_parents(node)
        inputs = self._create_vertex_txin(node)
        tokens, outputs = self._create_vertex_txout(node)

        assert len(block_parents) == 0
        tx = Transaction(parents=txs_parents, inputs=inputs, outputs=outputs, tokens=tokens)
        tx.timestamp = self.get_min_timestamp(node)
        tx.weight = self._daa.minimum_tx_weight(tx)
        self.sign_all_inputs(node, tx)
        tx.update_hash()
        return tx

    def create_genesis_vertex(self, node: DAGNode) -> BaseTransaction:
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
        """Create a vertex.

        - timestamp will be valid but must be adjusted according
        """
        if node.type == 'block':
            vertex = self.create_vertex_block(node)

        elif node.type == 'token':
            vertex = self.create_vertex_token(node)
            if vertex is None:
                return

        elif node.type == 'transaction':
            vertex = self.create_vertex_transaction(node)

        elif node.type == 'genesis':
            vertex = self.create_genesis_vertex(node)

        else:
            raise NotImplementedError(node.type)

        self._vertice_per_id[vertex.hash] = vertex
        self._vertices[node.name] = vertex
        return vertex

    def export(self) -> Iterator[BaseTransaction]:
        self._block_height[self._settings.GENESIS_BLOCK_HASH] = 0

        for node in self._builder.topological_sorting():
            vertex = self.create_vertex(node)
            if node.type != 'genesis':
                yield node, vertex
