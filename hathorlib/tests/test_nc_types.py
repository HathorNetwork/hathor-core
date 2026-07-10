# SPDX-FileCopyrightText: Hathor Labs
# SPDX-License-Identifier: Apache-2.0

# mypy: disable-error-code="no-untyped-def"

import json
import unittest
from typing import Any, NewType

from hathorlib.nanocontracts.exception import BlueprintSyntaxError, NCInvalidAction
from hathorlib.nanocontracts.nc_types import (
    ESSENTIAL_TYPE_ALIAS_MAP,
    BytesLikeNCType,
    NCType,
    VarUint32NCType,
    make_nc_type_for_arg_type,
    make_nc_type_for_field_type,
    make_nc_type_for_return_type,
)
from hathorlib.nanocontracts.types import (
    NC_HTR_TOKEN_UID,
    Address,
    Amount,
    BlueprintId,
    CallerId,
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
            NCGrantAuthorityAction(token_uid=NC_HTR_TOKEN_UID, mint=True, melt=False)

        with self.assertRaises(NCInvalidAction):
            NCAcquireAuthorityAction(token_uid=NC_HTR_TOKEN_UID, mint=True, melt=False)


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


class TestActualTypeWrapping(unittest.TestCase):
    """Deserializing must yield the declared actual class (e.g. `Amount`), not its base type (e.g. `int`)."""

    def _json_roundtrip(self, nc_type: NCType, value: object) -> object:
        """Roundtrip a value through an actual JSON encode/decode cycle."""
        return nc_type.json_to_value(json.loads(json.dumps(nc_type.value_to_json(value))))

    def test_amount_all_factories(self) -> None:
        for make in (make_nc_type_for_field_type, make_nc_type_for_arg_type, make_nc_type_for_return_type):
            nc_type = make(Amount)
            value = nc_type.from_bytes(nc_type.to_bytes(Amount(100)))
            self.assertIsInstance(value, Amount)
            self.assertEqual(value, 100)

    def test_amount_from_plain_int(self) -> None:
        # values are serialized as plain ints, but must come back as Amount
        nc_type = make_nc_type_for_field_type(Amount)
        value = nc_type.from_bytes(nc_type.to_bytes(100))  # type: ignore[arg-type]
        self.assertIsInstance(value, Amount)
        self.assertEqual(value, 100)

    def test_amount_roundtrip_bytes(self) -> None:
        nc_type = make_nc_type_for_field_type(Amount)
        for raw in (0, 1, 100, 2**64, 2**128):
            value = nc_type.from_bytes(nc_type.to_bytes(Amount(raw)))
            self.assertIsInstance(value, Amount)
            self.assertEqual(value, raw)

    def test_amount_json(self) -> None:
        nc_type = make_nc_type_for_field_type(Amount)
        self.assertEqual(nc_type.value_to_json(Amount(7)), 7)
        value = self._json_roundtrip(nc_type, Amount(7))
        self.assertIsInstance(value, Amount)
        self.assertEqual(value, 7)

    def test_timestamp(self) -> None:
        nc_type = make_nc_type_for_field_type(Timestamp)
        value = nc_type.from_bytes(nc_type.to_bytes(Timestamp(1234567890)))
        self.assertIsInstance(value, Timestamp)
        self.assertEqual(value, 1234567890)
        json_value = self._json_roundtrip(nc_type, Timestamp(1234567890))
        self.assertIsInstance(json_value, Timestamp)

    def test_plain_int_is_not_wrapped(self) -> None:
        # a plain `int` field must not be turned into an Amount
        nc_type = make_nc_type_for_field_type(int)
        value = nc_type.from_bytes(nc_type.to_bytes(5))
        self.assertNotIsInstance(value, Amount)
        self.assertIs(type(value), int)
        self.assertEqual(value, 5)

    def test_directly_constructed_nc_type_is_not_wrapped(self) -> None:
        # an NCType built directly (not through `NCType.from_type`) has no declared actual type
        nc_type = VarUint32NCType()
        value = nc_type.from_bytes(nc_type.to_bytes(Amount(5)))
        self.assertIs(type(value), int)

    def test_containers_compose(self) -> None:
        token = TokenUid(b'\x03' * 32)

        dict_nc_type = make_nc_type_for_arg_type(dict[TokenUid, Amount])
        for out in (
            dict_nc_type.from_bytes(dict_nc_type.to_bytes({token: Amount(5)})),
            self._json_roundtrip(dict_nc_type, {token: Amount(5)}),
        ):
            assert isinstance(out, dict)
            (key, value), = out.items()
            self.assertIsInstance(key, TokenUid)
            self.assertIsInstance(value, Amount)

        opt_nc_type: NCType[Amount | None] = make_nc_type_for_arg_type(Amount | None)  # type: ignore[arg-type]
        self.assertIsInstance(opt_nc_type.from_bytes(opt_nc_type.to_bytes(Amount(7))), Amount)
        self.assertIsNone(opt_nc_type.from_bytes(opt_nc_type.to_bytes(None)))

        tuple_nc_type = make_nc_type_for_arg_type(tuple[Timestamp, ...])
        out = tuple_nc_type.from_bytes(tuple_nc_type.to_bytes((Timestamp(1), Timestamp(2))))
        assert isinstance(out, tuple)
        for item in out:
            self.assertIsInstance(item, Timestamp)

        # `list` is aliased to `tuple` in the field map
        list_nc_type = make_nc_type_for_field_type(list[Amount])
        out = list_nc_type.from_bytes(list_nc_type.to_bytes((Amount(1), Amount(2))))  # type: ignore[arg-type]
        assert isinstance(out, tuple)
        for item in out:
            self.assertIsInstance(item, Amount)

    def test_bytes_actual_types_no_regression(self) -> None:
        cases: list[tuple[type, bytes]] = [
            (BlueprintId, BlueprintId(b'\x01' * 32)),
            (ContractId, ContractId(b'\x02' * 32)),
            (VertexId, VertexId(b'\x03' * 32)),
            (TokenUid, TokenUid(b'\x04' * 32)),
            (TokenUid, NC_HTR_TOKEN_UID),
            (TxOutputScript, TxOutputScript(b'\x76\xa9')),
        ]
        for type_, value in cases:
            nc_type: NCType[Any] = make_nc_type_for_field_type(type_)
            out = nc_type.from_bytes(nc_type.to_bytes(value))
            self.assertIs(type(out), type_)
            self.assertEqual(out, value)
            json_out = self._json_roundtrip(nc_type, value)
            self.assertIsInstance(json_out, type_)
            self.assertEqual(json_out, value)

    def test_address_and_caller_id_no_regression(self) -> None:
        address = Address(bytes.fromhex('2873c0a326af979a12be89ee8a00e8871c8e2765022e9b803c'))
        contract_id = ContractId(b'\x05' * 32)

        address_nc_type = make_nc_type_for_field_type(Address)
        out = address_nc_type.from_bytes(address_nc_type.to_bytes(address))
        self.assertIs(type(out), Address)
        self.assertIsInstance(self._json_roundtrip(address_nc_type, address), Address)

        caller_id_nc_type: NCType[CallerId] = make_nc_type_for_field_type(CallerId)  # type: ignore[arg-type]
        for caller in (address, contract_id):
            caller_out = caller_id_nc_type.from_bytes(caller_id_nc_type.to_bytes(caller))
            self.assertIs(type(caller_out), type(caller))
            self.assertEqual(caller_out, caller)
            json_out = self._json_roundtrip(caller_id_nc_type, caller)
            self.assertIs(type(json_out), type(caller))

    def test_newtype_direct_construction_is_not_wrapped(self) -> None:
        # some NCTypes are constructed directly with a NewType instead of a class (e.g. `NodeNCType` builds
        # `BytesLikeNCType(NodeId)`), which must be skipped since a NewType cannot be isinstance-checked
        node_id_type = NewType('node_id_type', bytes)
        nc_type = BytesLikeNCType(node_id_type)
        value = nc_type.from_bytes(nc_type.to_bytes(node_id_type(b'\x01' * 32)))
        self.assertIs(type(value), bytes)
        self.assertEqual(value, b'\x01' * 32)
        json_value = self._json_roundtrip(nc_type, node_id_type(b'\x01' * 32))
        self.assertIs(type(json_value), bytes)

    def test_wrapping_is_mapping_independent(self) -> None:
        # the declared type is preserved no matter which plain NCType class it is mapped to
        type_map = NCType.TypeMap(ESSENTIAL_TYPE_ALIAS_MAP, {Amount: VarUint32NCType})
        nc_type = NCType.from_type(Amount, type_map=type_map)
        value = nc_type.from_bytes(nc_type.to_bytes(Amount(100)))
        self.assertIsInstance(value, Amount)
        self.assertEqual(value, 100)


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
