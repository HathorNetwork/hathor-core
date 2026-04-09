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

import pytest

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.exception import NanoContractDoesNotExist
from hathor.nanocontracts.storage.contract_storage import Balance
from hathor.nanocontracts.types import ContractId, NCAcquireAuthorityAction, NCActionType, TokenUid, VertexId
from hathor.nanocontracts.utils import derive_child_token_id
from hathor.transaction import Block, Transaction, TxOutput
from hathor.transaction.headers.nano_header import NanoHeaderAction
from hathor.transaction.nc_execution_state import NCExecutionState
from hathor.wallet import HDWallet
from hathor_tests.dag_builder.builder import TestDAGBuilder
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase
from hathor_tests.nanocontracts.utils import set_nano_header


class MyBlueprint(Blueprint):
    token_uid: TokenUid | None

    @public(allow_grant_authority=True)
    def initialize(self, ctx: Context) -> None:
        self.token_uid = None

    @public
    def revoke_all(self, ctx: Context, token_uid: TokenUid | None) -> None:
        if token_uid is None:
            assert self.token_uid is not None
            token_uid = self.token_uid
        self.syscall.revoke_authorities(token_uid, revoke_mint=True, revoke_melt=True)

    @public(allow_deposit=True)
    def create_token(self, ctx: Context) -> None:
        self.token_uid = self.syscall.create_deposit_token(token_name='token a', token_symbol='TKA', amount=1000)

    @public(allow_acquire_authority=True)
    def allow_acquire_authority(self, ctx: Context) -> None:
        pass

    @public
    def acquire_authority(self, ctx: Context, other_id: ContractId) -> None:
        self.token_uid = derive_child_token_id(other_id, 'TKA')
        action = NCAcquireAuthorityAction(token_uid=self.token_uid, mint=True, melt=True)
        self.syscall.get_contract(other_id, blueprint_id=None).public(action).allow_acquire_authority()


class TestAuthoritiesIndex(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()

        self.tokens_index = self.manager.tx_storage.indexes.tokens
        self.dag_builder = TestDAGBuilder.from_manager(self.manager)
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)

        wallet = self.dag_builder.get_main_wallet()
        assert isinstance(wallet, HDWallet)
        self.wallet = wallet

    def test_grant_action_then_revoke(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..12]
            b10 < dummy < TKA

            tx1.out[0] = 1000 TKA # To force TKA to be a token creation tx

            TKA <-- b11
            tx1 <-- b12
        ''')
        artifacts.propagate_with(self.manager, up_to='dummy')
        tka, tx1 = artifacts.get_typed_vertices(['TKA', 'tx1'], Transaction)

        # Remove authority outputs so no UTXOs have them
        assert tka.outputs[-1].is_token_authority()
        assert tka.outputs[-2].is_token_authority()
        tka.outputs = tka.outputs[:-2]
        # HACK: We don't clear the sighash cache on purpose so we don't need to re-sign the tx
        # tka.clear_sighash_cache()

        # Add GRANT action to TKA
        set_nano_header(
            tx=tka,
            wallet=self.wallet,
            nc_id=self.blueprint_id,
            nc_actions=[
                NanoHeaderAction(type=NCActionType.GRANT_AUTHORITY, token_index=1, amount=TxOutput.ALL_AUTHORITIES)
            ],
            nc_method='initialize',
            blueprint=MyBlueprint,
            seqnum=0,
        )

        # Before executing TKA, nobody can mint or melt
        artifacts.propagate_with(self.manager, up_to='TKA')
        token_info = self.tokens_index.get_token_info(tka.hash)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert not token_info.can_mint()
        assert not token_info.can_melt()

        # After b11, TKA is executed and holds authorities
        artifacts.propagate_with(self.manager, up_to='b11')
        assert tka.get_metadata().nc_execution == NCExecutionState.SUCCESS

        storage = self.manager.get_best_block_nc_storage(tka.hash)
        assert storage.get_balance(tka.hash) == Balance(value=0, can_mint=True, can_melt=True)

        token_info = self.tokens_index.get_token_info(tka.hash)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert token_info.can_mint()
        assert token_info.can_melt()

        # Even though I'm not setting authority actions here, I have to set the header manually instead of using the
        # DAG builder because it doesn't know TKA is a NC.
        set_nano_header(
            tx=tx1,
            wallet=self.wallet,
            nc_id=tka.hash,
            nc_method='revoke_all',
            nc_args=(tka.hash,),
            blueprint=MyBlueprint,
            seqnum=1,
        )

        # After b12, all authorities are revoked
        artifacts.propagate_with(self.manager, up_to='b12')
        assert tx1.get_metadata().nc_execution == NCExecutionState.SUCCESS

        storage = self.manager.get_best_block_nc_storage(tka.hash)
        assert storage.get_balance(tka.hash) == Balance(value=0, can_mint=False, can_melt=False)

        token_info = self.tokens_index.get_token_info(tka.hash)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert not token_info.can_mint()
        assert not token_info.can_melt()

    def test_grant_action_then_reorg(self) -> None:
        artifacts = self.dag_builder.build_from_str('''
            blockchain genesis b[1..11]
            blockchain b10 a[11..12]
            b10 < dummy < TKA
            a12.weight = 3 # Necessary to force the reorg

            tx1.out[0] = 1000 TKA # To force TKA to be a token creation tx

            TKA <-- b11
            b11 < a11
        ''')
        artifacts.propagate_with(self.manager, up_to='dummy')
        b11, a11 = artifacts.get_typed_vertices(['b11', 'a11'], Block)
        tka = artifacts.get_typed_vertex('TKA', Transaction)

        # Remove authority outputs so no UTXOs have them
        assert tka.outputs[-1].is_token_authority()
        assert tka.outputs[-2].is_token_authority()
        tka.outputs = tka.outputs[:-2]
        # HACK: We don't clear the sighash cache on purpose so we don't need to re-sign the tx
        # tka.clear_sighash_cache()

        # Add GRANT action to TKA
        set_nano_header(
            tx=tka,
            wallet=self.wallet,
            nc_id=self.blueprint_id,
            nc_actions=[
                NanoHeaderAction(type=NCActionType.GRANT_AUTHORITY, token_index=1, amount=TxOutput.ALL_AUTHORITIES)
            ],
            nc_method='initialize',
            blueprint=MyBlueprint,
            seqnum=0,
        )

        # Before executing TKA, nobody can mint or melt
        artifacts.propagate_with(self.manager, up_to='TKA')
        token_info = self.tokens_index.get_token_info(tka.hash)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert not token_info.can_mint()
        assert not token_info.can_melt()

        # After b11, TKA is executed and holds authorities
        artifacts.propagate_with(self.manager, up_to='b11')
        assert b11.get_metadata().voided_by is None
        assert tka.get_metadata().first_block == b11.hash
        assert tka.get_metadata().nc_execution == NCExecutionState.SUCCESS

        storage = self.manager.get_best_block_nc_storage(tka.hash)
        assert storage.get_balance(tka.hash) == Balance(value=0, can_mint=True, can_melt=True)

        token_info = self.tokens_index.get_token_info(tka.hash)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert token_info.can_mint()
        assert token_info.can_melt()

        # After a12, a reorg happens un-executing TKA
        artifacts.propagate_with(self.manager, up_to='a12')
        assert b11.get_metadata().voided_by == {b11.hash}
        assert a11.get_metadata().voided_by is None
        assert tka.get_metadata().first_block is None
        assert tka.get_metadata().nc_execution == NCExecutionState.PENDING

        with pytest.raises(NanoContractDoesNotExist):
            self.manager.get_best_block_nc_storage(tka.hash)

        token_info = self.tokens_index.get_token_info(tka.hash)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert not token_info.can_mint()
        assert not token_info.can_melt()

    def test_acquire_action_then_revoke(self) -> None:
        artifacts = self.dag_builder.build_from_str(f'''
            blockchain genesis b[1..14]
            b10 < dummy

            nc1a.nc_id = "{self.blueprint_id.hex()}"
            nc1a.nc_method = initialize()

            nc1b.nc_id = nc1a
            nc1b.nc_method = create_token()
            nc1b.nc_deposit = 1000 HTR

            nc2a.nc_id = "{self.blueprint_id.hex()}"
            nc2a.nc_method = initialize()

            nc2b.nc_id = nc2a
            nc2b.nc_method = acquire_authority(`nc1a`)

            nc1c.nc_id = nc1a
            nc1c.nc_method = revoke_all(null)

            nc2c.nc_id = nc2a
            nc2c.nc_method = revoke_all(null)

            nc1a <-- nc1b <-- nc2a <-- nc2b <-- nc1c <-- nc2c
            nc1b <-- b11
            nc2b <-- b12
            nc1c <-- b13
            nc2c <-- b14
        ''')
        artifacts.propagate_with(self.manager, up_to='dummy')
        nc1a, nc1b, nc1c, nc2a, nc2b, nc2c = artifacts.get_typed_vertices(
            ['nc1a', 'nc1b', 'nc1c', 'nc2a', 'nc2b', 'nc2c'],
            Transaction
        )
        tka = derive_child_token_id(ContractId(VertexId(nc1a.hash)), 'TKA')

        # Before executing nc1b, the token doesn't exist
        artifacts.propagate_with(self.manager, up_to='nc1b')
        with pytest.raises(KeyError):
            self.tokens_index.get_token_info(tka)

        # After b11, nc1b is executed and holds authorities
        artifacts.propagate_with(self.manager, up_to='b11')
        assert nc1b.get_metadata().nc_execution == NCExecutionState.SUCCESS
        assert nc2b.get_metadata().nc_execution is None

        nc1_storage = self.manager.get_best_block_nc_storage(nc1a.hash)
        assert nc1_storage.get_balance(tka) == Balance(value=1000, can_mint=True, can_melt=True)

        token_info = self.tokens_index.get_token_info(tka)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert token_info.can_mint()
        assert token_info.can_melt()

        # After b12, nc2b is executed and also holds authorities
        artifacts.propagate_with(self.manager, up_to='b12')
        assert nc2b.get_metadata().nc_execution == NCExecutionState.SUCCESS

        nc1_storage = self.manager.get_best_block_nc_storage(nc1a.hash)
        nc2_storage = self.manager.get_best_block_nc_storage(nc2a.hash)
        assert nc1_storage.get_balance(tka) == Balance(value=1000, can_mint=True, can_melt=True)
        assert nc2_storage.get_balance(tka) == Balance(value=0, can_mint=True, can_melt=True)

        token_info = self.tokens_index.get_token_info(tka)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert token_info.can_mint()
        assert token_info.can_melt()

        # After b13, authorities are revoked from nc1a
        artifacts.propagate_with(self.manager, up_to='b13')
        assert nc1c.get_metadata().nc_execution == NCExecutionState.SUCCESS

        nc1_storage = self.manager.get_best_block_nc_storage(nc1a.hash)
        nc2_storage = self.manager.get_best_block_nc_storage(nc2a.hash)
        assert nc1_storage.get_balance(tka) == Balance(value=1000, can_mint=False, can_melt=False)
        assert nc2_storage.get_balance(tka) == Balance(value=0, can_mint=True, can_melt=True)

        token_info = self.tokens_index.get_token_info(tka)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert token_info.can_mint()
        assert token_info.can_melt()

        # Finally, after b14, authorities are revoked from nc2a and the token index reflects that nobody can mint/melt
        artifacts.propagate_with(self.manager, up_to='b14')
        assert nc2c.get_metadata().nc_execution == NCExecutionState.SUCCESS

        nc1_storage = self.manager.get_best_block_nc_storage(nc1a.hash)
        nc2_storage = self.manager.get_best_block_nc_storage(nc2a.hash)
        assert nc1_storage.get_balance(tka) == Balance(value=1000, can_mint=False, can_melt=False)
        assert nc2_storage.get_balance(tka) == Balance(value=0, can_mint=False, can_melt=False)

        token_info = self.tokens_index.get_token_info(tka)
        assert list(token_info.iter_mint_utxos()) == []
        assert list(token_info.iter_melt_utxos()) == []
        assert not token_info.can_mint()
        assert not token_info.can_melt()
