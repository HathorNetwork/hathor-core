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

# mypy: disable-error-code="no-untyped-def"

import unittest

from hathorlib.nanocontracts.exception import BlueprintSyntaxError, NCInvalidAction
from hathorlib.nanocontracts.types import (
    HATHOR_TOKEN_UID,
    Amount,
    BlueprintId,
    ContractId,
    NCAcquireAuthorityAction,
    NCActionType,
    NCDepositAction,
    NCGrantAuthorityAction,
    NCMethodType,
    NCRawArgs,
    NCWithdrawalAction,
    Timestamp,
    TokenUid,
    TxOutputScript,
    VertexId,
    _set_method_type,
    blueprint_id_from_bytes,
    set_checksig_backend,
)


class TestNCActionType(unittest.TestCase):
    def test_str(self) -> None:
        self.assertEqual(str(NCActionType.DEPOSIT), 'DEPOSIT')
        self.assertEqual(str(NCActionType.WITHDRAWAL), 'WITHDRAWAL')
        self.assertEqual(str(NCActionType.GRANT_AUTHORITY), 'GRANT_AUTHORITY')
        self.assertEqual(str(NCActionType.ACQUIRE_AUTHORITY), 'ACQUIRE_AUTHORITY')

    def test_to_bytes(self) -> None:
        self.assertEqual(NCActionType.DEPOSIT.to_bytes(), b'\x01')
        self.assertEqual(NCActionType.WITHDRAWAL.to_bytes(), b'\x02')
        self.assertEqual(NCActionType.GRANT_AUTHORITY.to_bytes(), b'\x03')
        self.assertEqual(NCActionType.ACQUIRE_AUTHORITY.to_bytes(), b'\x04')

    def test_from_bytes(self) -> None:
        self.assertEqual(NCActionType.from_bytes(b'\x01'), NCActionType.DEPOSIT)
        self.assertEqual(NCActionType.from_bytes(b'\x02'), NCActionType.WITHDRAWAL)
        self.assertEqual(NCActionType.from_bytes(b'\x03'), NCActionType.GRANT_AUTHORITY)
        self.assertEqual(NCActionType.from_bytes(b'\x04'), NCActionType.ACQUIRE_AUTHORITY)

    def test_roundtrip(self) -> None:
        for action_type in NCActionType:
            self.assertEqual(NCActionType.from_bytes(action_type.to_bytes()), action_type)


class TestNCActions(unittest.TestCase):
    def test_deposit_action(self) -> None:
        token = TokenUid(b'\x01')
        action = NCDepositAction(token_uid=token, amount=100)
        self.assertEqual(action.type, NCActionType.DEPOSIT)
        self.assertEqual(action.name, 'DEPOSIT')
        json_dict = action.to_json()
        self.assertEqual(json_dict['type'], 'deposit')
        self.assertEqual(json_dict['token_uid'], '01')
        self.assertEqual(json_dict['amount'], 100)

    def test_withdrawal_action(self) -> None:
        token = TokenUid(b'\x02')
        action = NCWithdrawalAction(token_uid=token, amount=50)
        self.assertEqual(action.type, NCActionType.WITHDRAWAL)
        json_dict = action.to_json()
        self.assertEqual(json_dict['type'], 'withdrawal')
        self.assertEqual(json_dict['amount'], 50)

    def test_grant_authority_action(self) -> None:
        token = TokenUid(b'\x01')
        action = NCGrantAuthorityAction(token_uid=token, mint=True, melt=False)
        self.assertEqual(action.type, NCActionType.GRANT_AUTHORITY)
        json_dict = action.to_json()
        self.assertEqual(json_dict['type'], 'grant_authority')
        self.assertTrue(json_dict['mint'])
        self.assertFalse(json_dict['melt'])

    def test_acquire_authority_action(self) -> None:
        token = TokenUid(b'\x01')
        action = NCAcquireAuthorityAction(token_uid=token, mint=False, melt=True)
        self.assertEqual(action.type, NCActionType.ACQUIRE_AUTHORITY)
        json_dict = action.to_json()
        self.assertEqual(json_dict['type'], 'acquire_authority')
        self.assertFalse(json_dict['mint'])
        self.assertTrue(json_dict['melt'])

    def test_authority_action_htr_token_forbidden(self) -> None:
        with self.assertRaises(NCInvalidAction):
            NCGrantAuthorityAction(token_uid=TokenUid(HATHOR_TOKEN_UID), mint=True, melt=False)

        with self.assertRaises(NCInvalidAction):
            NCAcquireAuthorityAction(token_uid=TokenUid(HATHOR_TOKEN_UID), mint=True, melt=False)


class TestCustomTypes(unittest.TestCase):
    def test_vertex_id(self) -> None:
        vid = VertexId(b'\x00' * 32)
        self.assertEqual(len(vid), 32)
        self.assertIsInstance(vid, bytes)

    def test_blueprint_id(self) -> None:
        bid = BlueprintId(VertexId(b'\x01' * 32))
        self.assertIsInstance(bid, VertexId)
        self.assertIsInstance(bid, bytes)

    def test_contract_id(self) -> None:
        cid = ContractId(VertexId(b'\x02' * 32))
        self.assertIsInstance(cid, VertexId)

    def test_token_uid(self) -> None:
        token = TokenUid(b'\x00')
        self.assertIsInstance(token, bytes)

    def test_tx_output_script(self) -> None:
        script = TxOutputScript(b'\x76\xa9')
        self.assertIsInstance(script, bytes)

    def test_amount(self) -> None:
        amount = Amount(100)
        self.assertIsInstance(amount, int)
        self.assertEqual(amount, 100)

    def test_timestamp(self) -> None:
        ts = Timestamp(1234567890)
        self.assertIsInstance(ts, int)

    def test_blueprint_id_from_bytes(self) -> None:
        data = b'\xab' * 32
        bid = blueprint_id_from_bytes(data)
        self.assertIsInstance(bid, BlueprintId)
        self.assertEqual(bid, data)


class TestSetMethodType(unittest.TestCase):
    def test_set_method_type(self) -> None:
        def my_func() -> None:
            pass

        _set_method_type(my_func, NCMethodType.PUBLIC)
        self.assertEqual(getattr(my_func, '__nc_method_type'), NCMethodType.PUBLIC)

    def test_double_set_raises(self) -> None:
        def my_func() -> None:
            pass

        _set_method_type(my_func, NCMethodType.PUBLIC)
        with self.assertRaises(BlueprintSyntaxError):
            _set_method_type(my_func, NCMethodType.VIEW)


class TestNCRawArgs(unittest.TestCase):
    def test_str(self) -> None:
        args = NCRawArgs(args_bytes=b'\xde\xad')
        self.assertEqual(str(args), 'dead')

    def test_repr(self) -> None:
        args = NCRawArgs(args_bytes=b'\xde\xad')
        self.assertEqual(repr(args), "NCRawArgs('dead')")


class TestChecksigBackend(unittest.TestCase):
    def test_set_checksig_backend(self) -> None:
        # Just test that set_checksig_backend doesn't raise
        def fake_backend(sighash_all_data: bytes, script_input: bytes, script: bytes) -> bool:
            return True

        set_checksig_backend(fake_backend)


class TestViewDecorator(unittest.TestCase):
    def test_view_decorator(self) -> None:
        from hathorlib.nanocontracts.types import NC_METHOD_TYPE_ATTR, NCMethodType, view

        def my_method(self, x: int) -> int:
            return x

        result = view(my_method)
        self.assertEqual(getattr(result, NC_METHOD_TYPE_ATTR), NCMethodType.VIEW)

    def test_view_on_initialize_raises(self) -> None:
        from hathorlib.nanocontracts.types import view

        def initialize(self, x: int) -> None:
            pass

        with self.assertRaises(BlueprintSyntaxError):
            view(initialize)

    def test_view_on_fallback_raises(self) -> None:
        from hathorlib.nanocontracts.types import view

        def fallback(self, x: int) -> None:
            pass

        with self.assertRaises(BlueprintSyntaxError):
            view(fallback)


class TestExportDecorator(unittest.TestCase):
    def test_export(self) -> None:
        from hathorlib.nanocontracts.types import export

        @export
        class MyBlueprint:
            pass

        # The class should still be usable
        self.assertIsNotNone(MyBlueprint)
