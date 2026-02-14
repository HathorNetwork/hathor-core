from collections.abc import Iterator
from sys import version_info
from types import MethodType
from typing import Any

from hathor.nanocontracts import Blueprint, Context, public
from hathor.nanocontracts.custom_builtins import EXEC_BUILTINS
from hathor.nanocontracts.sandbox import get_allowed_imports_dict
from hathor_tests.nanocontracts.blueprints.unittest import BlueprintTestCase

MAX_DEPTH = 20
NEW_PROP_NAME = 'some_new_attribute'

# XXX: if KNOWN_CASES is not empty then there is a bug
KNOWN_CASES = [
    'MyBlueprint.check',
    'MyBlueprint.initialize',
    'MyBlueprint.log',
    'MyBlueprint.some_new_attribute',
    'MyBlueprint.syscall',
    'all.some_new_attribute',
    'any.some_new_attribute',
    'enumerate.some_new_attribute',
    'hathor.Blueprint.log',
    'hathor.Blueprint.some_new_attribute',
    'hathor.Blueprint.syscall',
    'hathor.Context.actions',
    'hathor.Context.actions_list',
    'hathor.Context.block',
    'hathor.Context.caller_id',
    'hathor.Context.copy',
    'hathor.Context.create_from_vertex',
    'hathor.Context.get_caller_address',
    'hathor.Context.get_caller_contract_id',
    'hathor.Context.get_single_action',
    'hathor.Context.some_new_attribute',
    'hathor.Context.to_json',
    'hathor.Context.vertex',
    'hathor.NCAcquireAuthorityAction.melt',
    'hathor.NCAcquireAuthorityAction.mint',
    'hathor.NCAcquireAuthorityAction.name',
    'hathor.NCAcquireAuthorityAction.some_new_attribute',
    'hathor.NCAcquireAuthorityAction.to_json',
    'hathor.NCAcquireAuthorityAction.token_uid',
    'hathor.NCAcquireAuthorityAction.type',
    'hathor.NCActionType.ACQUIRE_AUTHORITY._name_',
    'hathor.NCActionType.ACQUIRE_AUTHORITY._sort_order_',
    'hathor.NCActionType.ACQUIRE_AUTHORITY._value_',
    'hathor.NCActionType.ACQUIRE_AUTHORITY.from_bytes',
    'hathor.NCActionType.ACQUIRE_AUTHORITY.some_new_attribute',
    'hathor.NCActionType.ACQUIRE_AUTHORITY.to_bytes',
    'hathor.NCActionType.DEPOSIT._name_',
    'hathor.NCActionType.DEPOSIT._sort_order_',
    'hathor.NCActionType.DEPOSIT._value_',
    'hathor.NCActionType.DEPOSIT.from_bytes',
    'hathor.NCActionType.DEPOSIT.some_new_attribute',
    'hathor.NCActionType.DEPOSIT.to_bytes',
    'hathor.NCActionType.GRANT_AUTHORITY._name_',
    'hathor.NCActionType.GRANT_AUTHORITY._sort_order_',
    'hathor.NCActionType.GRANT_AUTHORITY._value_',
    'hathor.NCActionType.GRANT_AUTHORITY.from_bytes',
    'hathor.NCActionType.GRANT_AUTHORITY.some_new_attribute',
    'hathor.NCActionType.GRANT_AUTHORITY.to_bytes',
    'hathor.NCActionType.WITHDRAWAL._name_',
    'hathor.NCActionType.WITHDRAWAL._sort_order_',
    'hathor.NCActionType.WITHDRAWAL._value_',
    'hathor.NCActionType.WITHDRAWAL.from_bytes',
    'hathor.NCActionType.WITHDRAWAL.some_new_attribute',
    'hathor.NCActionType.WITHDRAWAL.to_bytes',
    'hathor.NCActionType._generate_next_value_',
    'hathor.NCActionType._member_map_',
    'hathor.NCActionType._member_names_',
    'hathor.NCActionType._member_type_',
    'hathor.NCActionType._new_member_',
    'hathor.NCActionType._unhashable_values_',
    'hathor.NCActionType._use_args_',
    'hathor.NCActionType._value2member_map_',
    'hathor.NCActionType._value_repr_',
    'hathor.NCActionType.from_bytes',
    'hathor.NCActionType.some_new_attribute',
    'hathor.NCActionType.to_bytes',
    'hathor.NCDepositAction.amount',
    'hathor.NCDepositAction.name',
    'hathor.NCDepositAction.some_new_attribute',
    'hathor.NCDepositAction.to_json',
    'hathor.NCDepositAction.token_uid',
    'hathor.NCDepositAction.type',
    'hathor.NCFail.add_note',
    'hathor.NCFail.args',
    'hathor.NCFail.some_new_attribute',
    'hathor.NCFail.with_traceback',
    'hathor.NCFee.amount',
    'hathor.NCFee.get_htr_value',
    'hathor.NCFee.some_new_attribute',
    'hathor.NCFee.token_uid',
    'hathor.NCGrantAuthorityAction.melt',
    'hathor.NCGrantAuthorityAction.mint',
    'hathor.NCGrantAuthorityAction.name',
    'hathor.NCGrantAuthorityAction.some_new_attribute',
    'hathor.NCGrantAuthorityAction.to_json',
    'hathor.NCGrantAuthorityAction.token_uid',
    'hathor.NCGrantAuthorityAction.type',
    'hathor.NCParsedArgs.args',
    'hathor.NCParsedArgs.kwargs',
    'hathor.NCParsedArgs.some_new_attribute',
    'hathor.NCRawArgs.args_bytes',
    'hathor.NCRawArgs.some_new_attribute',
    'hathor.NCRawArgs.try_parse_as',
    'hathor.NCWithdrawalAction.amount',
    'hathor.NCWithdrawalAction.name',
    'hathor.NCWithdrawalAction.some_new_attribute',
    'hathor.NCWithdrawalAction.to_json',
    'hathor.NCWithdrawalAction.token_uid',
    'hathor.NCWithdrawalAction.type',
    'hathor.SignedData._get_raw_signed_data',
    'hathor.SignedData.checksig',
    'hathor.SignedData.get_data_bytes',
    'hathor.SignedData.some_new_attribute',
    'hathor.export.some_new_attribute',
    'hathor.fallback.some_new_attribute',
    'hathor.json_dumps.some_new_attribute',
    'hathor.public.some_new_attribute',
    'hathor.sha3.some_new_attribute',
    'hathor.verify_ecdsa.some_new_attribute',
    'hathor.view.some_new_attribute',
    'range._getitem_int',
    'range._getitem_slice',
    'range._start',
    'range._step',
    'range._stop',
    'range.count',
    'range.index',
    'range.some_new_attribute',
    'range.start',
    'range.step',
    'range.stop',
    'typing.NamedTuple.some_new_attribute',
    'typing.Optional._getitem',
    'typing.Optional._name',
    'typing.TypeAlias._getitem',
    'typing.TypeAlias._name',
    'typing.Union._getitem',
    'typing.Union._name',
]

# XXX: these only appear in Python 3.11
if version_info[1] == 11:
    KNOWN_CASES.extend([
        'hathor.SignedData._is_protocol',
    ])


# XXX: these only appear in Python 3.13
if version_info[1] == 13:
    KNOWN_CASES.extend([
        'hathor.NCActionType._hashable_values_',
        'hathor.NCActionType._unhashable_values_map_',
    ])

KNOWN_CASES.sort()


def is_writeable(obj: object, prop_name: str, value: Any) -> bool:
    """ Returns True if `obj.prop_name = value` succeeds."""
    if has_value := hasattr(obj, prop_name):
        orig_value = getattr(obj, prop_name)
    try:
        # try to overwrite the attribute
        setattr(obj, prop_name, value)
        # try to delete the attribute
        delattr(obj, prop_name)
        # restore original value if it had one
        if has_value:
            setattr(obj, prop_name, orig_value)
    except AttributeError:
        return False
    except TypeError:
        return False
    else:
        return True


def check_property_writeable(obj: object, prop_name: str) -> tuple[bool, object | None]:
    """ Checks the property value and returns a tuple (writeable: bool, possible_object: object | None).

    The first value, `writeable: bool`, tells whether the property is writeable or not.

    The second value, `possible_object: object | None` is the value to be used to continue the recursive check, if it's
    `None` there is no need to continue. Note: the value itself could be `None`, and we don't differentiate, we just
    don't continue the search eitherway.
    """
    prop_value = getattr(obj, prop_name)
    match prop_value:
        case list():
            # XXX: lists are inherently mutable and shouldn't be exposed
            prop_value.append(object())
            # XXX: is_writeable not called since True is always returned, but it's technically independant
            return True, None
        case dict():
            # XXX: dicts are inherently mutable and shouldn't be exposed
            prop_value[None] = object()
            # XXX: is_writeable not called since True is always returned, but it's technically independant
            return True, None
        case int():
            # XXX: no need to deep into int's properties
            return is_writeable(obj, prop_name, 999), None
        case str():
            # XXX: no need to deep into str's properties
            return is_writeable(obj, prop_name, 'foobar'), None
        case bytes():
            # XXX: no need to deep into bytes' properties
            return is_writeable(obj, prop_name, b'foobar'), None
        case tuple():
            # XXX: no need to deep into tuple's properties
            return is_writeable(obj, prop_name, ()), None
        case MethodType():
            # XXX: no need to deep into a method's properties
            return is_writeable(obj, prop_name, lambda: 'foo'), None
        case _ as value:
            return is_writeable(obj, prop_name, object()), value


def should_skip_attr(prop_name: str) -> bool:
    """Used to simulate AST restrictions and prevent loops."""
    return '__' in prop_name


def _search_writeable_properties(obj: object, *, path: tuple[str, ...], available_depth: int) -> Iterator[str]:
    if available_depth <= 0:
        assert 'MAX_DEPTH is not high enough to traverse everything'
    all_names = set(dir(obj)) | set(getattr(obj, '__dict__', ())) | set(getattr(obj, '__slots__', ()))
    prop_names = [prop_name for prop_name in all_names if not should_skip_attr(prop_name)]
    available_depth -= 1
    for prop_name in prop_names:
        next_path = path + (prop_name,)
        prop_path = '.'.join(path + (prop_name,))
        prop_writeable, prop_value = check_property_writeable(obj, prop_name)
        if prop_writeable:
            yield prop_path
        else:
            if prop_value is not None:
                yield from _search_writeable_properties(prop_value, path=next_path, available_depth=available_depth)
    if is_writeable(obj, NEW_PROP_NAME, object()):
        yield '.'.join(path + (NEW_PROP_NAME,))


def search_writeable_properties(obj: object, obj_name: str, /) -> Iterator[str]:
    """Searches for and returns a list of writeable properties, nested properties are joined with '.'"""
    yield from _search_writeable_properties(obj, path=(obj_name,), available_depth=MAX_DEPTH)


class MyBlueprint(Blueprint):
    @public
    def initialize(self, ctx: Context) -> None:
        pass

    @public
    def check(self, ctx: Context) -> list[str]:
        mutable_props: list[str] = []
        mutable_props.extend(search_writeable_properties(MyBlueprint, 'MyBlueprint'))
        mutable_props.extend(search_writeable_properties(self, 'self'))
        mutable_props.extend(search_writeable_properties(ctx, 'ctx'))
        custom_import = EXEC_BUILTINS['__import__']
        for module_name, import_names in get_allowed_imports_dict().items():
            module = custom_import(module_name, fromlist=list(import_names))
            for import_name in import_names:
                obj = getattr(module, import_name)
                obj_name = f'{module_name}.{import_name}'
                mutable_props.extend(search_writeable_properties(obj, obj_name))
        for builtin_name, builtin_obj in EXEC_BUILTINS.items():
            if should_skip_attr(builtin_name):
                continue
            mutable_props.extend(search_writeable_properties(builtin_obj, builtin_name))
        return mutable_props


class TestMutableAttributes(BlueprintTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.blueprint_id = self._register_blueprint_class(MyBlueprint)
        self.contract_id = self.gen_random_contract_id()
        self.runner.create_contract(self.contract_id, self.blueprint_id, self.create_context())

    def test_search_mutable_properties(self) -> None:
        mutable_props = sorted(self.runner.call_public_method(self.contract_id, 'check', self.create_context()))
        sorted_known_cases = sorted(KNOWN_CASES)
        debug = False
        if debug:
            for prop in mutable_props:
                print(f"    '{prop}',")
        self.assertEqual(mutable_props, sorted_known_cases)
