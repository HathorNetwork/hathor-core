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

"""Opcode and import allowlists for nano contract sandbox execution.

This module defines:
1. Which Python bytecode opcodes are allowed during nano contract execution.
2. Which Python modules and attributes can be imported by blueprints.

Both use an allowlist approach (fail-secure by default) so that new
opcodes/modules introduced in future Python versions are automatically
blocked until explicitly reviewed and added to the allowlists.
"""

import collections
import dis
import math
import typing
from functools import cache

# =============================================================================
# OPCODE ALLOWLIST
# =============================================================================

# Explicitly allowed opcodes for nano contract execution.
# New Python opcodes are blocked by default until reviewed.
# This list mirrors the restrictions enforced by OCB AST validation.
ALLOWED_OPCODES: frozenset[str] = frozenset({
    # Stack/Control operations
    'NOP',
    'CACHE',
    'EXTENDED_ARG',
    'RESUME',
    'POP_TOP',
    'PUSH_NULL',
    'SWAP',
    'COPY',

    # Load operations
    'LOAD_CONST',
    'LOAD_FAST',
    'LOAD_NAME',
    'LOAD_GLOBAL',
    'LOAD_ATTR',
    'LOAD_METHOD',
    'LOAD_DEREF',
    'LOAD_CLOSURE',
    'LOAD_CLASSDEREF',
    'MAKE_CELL',
    'COPY_FREE_VARS',

    # Store operations
    'STORE_FAST',
    'STORE_NAME',
    'STORE_GLOBAL',
    'STORE_ATTR',
    'STORE_DEREF',
    'STORE_SUBSCR',

    # Delete operations
    'DELETE_FAST',
    'DELETE_NAME',
    'DELETE_GLOBAL',
    'DELETE_ATTR',
    'DELETE_DEREF',
    'DELETE_SUBSCR',

    # Binary operations
    'BINARY_OP',
    'BINARY_SUBSCR',

    # Unary operations
    'UNARY_INVERT',
    'UNARY_NEGATIVE',
    'UNARY_NOT',
    'UNARY_POSITIVE',

    # Comparison operations
    'COMPARE_OP',
    'CONTAINS_OP',
    'IS_OP',

    # Control flow - forward jumps
    'JUMP_FORWARD',
    'POP_JUMP_FORWARD_IF_FALSE',
    'POP_JUMP_FORWARD_IF_TRUE',
    'POP_JUMP_FORWARD_IF_NONE',
    'POP_JUMP_FORWARD_IF_NOT_NONE',
    'JUMP_IF_FALSE_OR_POP',
    'JUMP_IF_TRUE_OR_POP',

    # Control flow - backward jumps
    'JUMP_BACKWARD',
    'JUMP_BACKWARD_NO_INTERRUPT',
    'POP_JUMP_BACKWARD_IF_FALSE',
    'POP_JUMP_BACKWARD_IF_TRUE',
    'POP_JUMP_BACKWARD_IF_NONE',
    'POP_JUMP_BACKWARD_IF_NOT_NONE',

    # Iteration
    'FOR_ITER',
    'GET_ITER',
    'GET_LEN',
    'RETURN_VALUE',

    # Build collections
    'BUILD_LIST',
    'BUILD_MAP',
    'BUILD_SET',
    'BUILD_TUPLE',
    'BUILD_STRING',
    'BUILD_CONST_KEY_MAP',
    'BUILD_SLICE',

    # Collection mutations
    'LIST_APPEND',
    'LIST_EXTEND',
    'LIST_TO_TUPLE',
    'SET_ADD',
    'SET_UPDATE',
    'MAP_ADD',
    'DICT_MERGE',
    'DICT_UPDATE',

    # Function calls
    'CALL',
    'PRECALL',
    'KW_NAMES',
    'CALL_FUNCTION_EX',
    'MAKE_FUNCTION',

    # Generators (sync only)
    'YIELD_VALUE',
    'GET_YIELD_FROM_ITER',
    'RETURN_GENERATOR',

    # Unpack/Match operations
    'UNPACK_SEQUENCE',
    'UNPACK_EX',
    'MATCH_CLASS',
    'MATCH_KEYS',
    'MATCH_MAPPING',
    'MATCH_SEQUENCE',

    # Context managers (sync only)
    'BEFORE_WITH',

    # Other allowed operations
    'FORMAT_VALUE',
    'SETUP_ANNOTATIONS',
    'LOAD_ASSERTION_ERROR',
    'RAISE_VARARGS',  # raise statements allowed, catching blocked
    'LOAD_BUILD_CLASS',  # class creation allowed per sandbox config

    # Import operations - allowed because import restrictions are enforced
    # via import_restrict_mode and allowed_imports at the sandbox level.
    # The OCB AST-level restrictions check WHICH modules are imported,
    # not that imports themselves are forbidden.
    'IMPORT_NAME',
    'IMPORT_FROM',
    # Note: IMPORT_STAR is NOT allowed - star imports are blocked at AST level

    # Sandbox-specific opcodes (CPython sandbox build)
    'SANDBOX_COUNT',  # operation counting opcode injected by PyCF_SANDBOX_COUNT flag
})

# Blocked opcodes (for documentation - computed automatically from allowlist)
# These mirror the OCB AST-level restrictions:
#
# Imports (OCB: visit_Import, visit_ImportFrom):
#   - IMPORT_STAR (star imports blocked at AST level)
#   Note: IMPORT_NAME and IMPORT_FROM are allowed because import restrictions
#   are enforced via import_restrict_mode and allowed_imports.
#
# Exception Handling (OCB: visit_Try):
#   - PUSH_EXC_INFO, POP_EXCEPT, CHECK_EXC_MATCH, CHECK_EG_MATCH
#   - PREP_RERAISE_STAR, RERAISE, WITH_EXCEPT_START
#
# Async (OCB: visit_AsyncFunctionDef, visit_Await, visit_AsyncFor, visit_AsyncWith):
#   - GET_AWAITABLE, GET_AITER, GET_ANEXT, END_ASYNC_FOR
#   - BEFORE_ASYNC_WITH, ASYNC_GEN_WRAP, SEND
#
# Other:
#   - PRINT_EXPR (interactive mode only)


def get_allowed_opcodes() -> frozenset[int]:
    """Get allowed opcodes as opcode numbers.

    Returns:
        frozenset of opcode numbers (integers) that are allowed.
    """
    return frozenset(
        dis.opmap[name] for name in ALLOWED_OPCODES if name in dis.opmap
    )


# =============================================================================
# IMPORT ALLOWLIST
# =============================================================================

@cache
def get_allowed_imports_dict() -> dict[str, dict[str, object]]:
    """Get the allowed imports dict, building it on first call.

    Uses @cache for lazy initialization to avoid circular import issues
    with the hathor module at import time.
    """
    import hathor

    return {
        # globals
        'math': dict(
            ceil=math.ceil,
            floor=math.floor,
        ),
        'typing': dict(
            Optional=typing.Optional,
            NamedTuple=typing.NamedTuple,
            TypeAlias=typing.TypeAlias,
            Union=typing.Union,
        ),
        'collections': dict(OrderedDict=collections.OrderedDict),
        # hathor
        'hathor': dict(
            Blueprint=hathor.Blueprint,
            HATHOR_TOKEN_UID=hathor.HATHOR_TOKEN_UID,
            Context=hathor.Context,
            NCFail=hathor.NCFail,
            NCAction=hathor.NCAction,
            NCFee=hathor.NCFee,
            NCActionType=hathor.NCActionType,
            SignedData=hathor.SignedData,
            public=hathor.public,
            view=hathor.view,
            export=hathor.export,
            fallback=hathor.fallback,
            Address=hathor.Address,
            Amount=hathor.Amount,
            Timestamp=hathor.Timestamp,
            TokenUid=hathor.TokenUid,
            TxOutputScript=hathor.TxOutputScript,
            BlueprintId=hathor.BlueprintId,
            ContractId=hathor.ContractId,
            VertexId=hathor.VertexId,
            CallerId=hathor.CallerId,
            NCDepositAction=hathor.NCDepositAction,
            NCWithdrawalAction=hathor.NCWithdrawalAction,
            NCGrantAuthorityAction=hathor.NCGrantAuthorityAction,
            NCAcquireAuthorityAction=hathor.NCAcquireAuthorityAction,
            NCArgs=hathor.NCArgs,
            NCRawArgs=hathor.NCRawArgs,
            NCParsedArgs=hathor.NCParsedArgs,
            sha3=hathor.sha3,
            verify_ecdsa=hathor.verify_ecdsa,
            json_dumps=hathor.json_dumps,
        ),
    }


def get_sandbox_allowed_imports() -> frozenset[str]:
    """Convert allowed imports to the format expected by sys.sandbox.allowed_imports.

    The sandbox API expects a set of dotted module.attribute strings to restrict
    which imports are allowed. This provides defense in depth - even if someone
    bypasses the custom __import__ builtin, the sandbox itself blocks unauthorized imports.

    Returns:
        frozenset of dotted strings like 'math.ceil', 'hathor.Blueprint', etc.
    """
    allowed_imports = get_allowed_imports_dict()
    return frozenset(
        f'{module_name}.{attr_name}'
        for module_name, attributes in allowed_imports.items()
        for attr_name in attributes
    )


def get_sandbox_allowed_modules() -> frozenset[str]:
    """Get the set of module names allowed by the sandbox.

    The sandbox API expects a frozenset of module names to restrict which modules
    can be accessed. This provides defense in depth - even if sandboxed code gets
    a reference to a disallowed module (e.g., passed via namespace), the sandbox
    blocks its usage.

    Returns:
        frozenset of module names
    """
    return frozenset(get_allowed_imports_dict().keys())
