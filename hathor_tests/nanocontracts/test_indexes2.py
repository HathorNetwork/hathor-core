#  Copyright 2025 Hathor Labs
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

from hathor.nanocontracts import HATHOR_TOKEN_UID, Blueprint, Context, public
from hathor.nanocontracts.types import ContractId, VertexId
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.transaction import Transaction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.transaction.util import get_deposit_token_deposit_amount
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase


class MyBlueprint(Blueprint):
    @public(allow_deposit=True)
    def initialize(self, ctx: Context, amount: int) -> None:
        self.syscall.create_deposit_token(token_name='token a', token_symbol='TKA', amount=amount)


class TestIndexes2(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        assert self.manager.tx_storage.indexes is not None
        assert self.manager.tx_storage.indexes.tokens is not None
        self.tokens_index = self.manager.tx_storage.indexes.tokens

        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)

    def test_indexes_tx_affected_twice(self) -> None:
        amount = 10000
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..11]
            b10 < dummy

            tx1.nc_id = "{self.blueprint_id.hex()}"
            tx1.nc_method = initialize({amount})
            tx1.nc_deposit = 1000 HTR
            tx1 <-- b11  # Confirming tx1 means it's affected in the consensus

            tx1.out[0] <<< tx2  # Spending tx1 means it's affected in the consensus for a second time
            b11 < tx2
        ''')
        artifacts.propagate_with(self.manager)

        tx1, = artifacts.get_typed_vertices(['tx1'], Transaction)
        tka = derive_child_token_id(ContractId(VertexId(tx1.hash)), 'TKA')

        tka_token_info = self.tokens_index.get_token_info(tka)
        htr_token_info = self.tokens_index.get_token_info(HATHOR_TOKEN_UID)

        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert tka_token_info.get_total() == amount
        assert htr_token_info.get_total() == (
            self._settings.GENESIS_TOKENS
            + 11 * self._settings.INITIAL_TOKENS_PER_BLOCK
            - get_deposit_token_deposit_amount(self._settings, amount)
        )
