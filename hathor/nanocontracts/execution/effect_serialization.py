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

"""Serialization module for NC execution effects.

This module provides serialization/deserialization of NC execution effects
for inter-process communication (IPC) when running NC execution in a subprocess.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from hathor.nanocontracts.runner.call_info import CallInfo


@dataclass(slots=True, frozen=True)
class SerializedRunner:
    """Minimal serializable representation of Runner state for IPC.

    Contains only the data needed to reconstruct runner state after
    subprocess execution:
    - call_info_json: Full call info serialized as JSON for logging/debugging
    - storage_root_ids: Map of contract_id -> storage root for commit verification
    - updated_tokens_totals: Token amounts changed via syscalls
    - paid_actions_fees: Fees paid during inter-contract calls
    """
    call_info_json: str
    storage_root_ids: dict[bytes, bytes]
    updated_tokens_totals: dict[bytes, int]
    paid_actions_fees: dict[bytes, int]


@dataclass(slots=True, frozen=True)
class SerializedNCTxExecutionSuccess:
    """Serialized form of NCTxExecutionSuccess for IPC."""
    tx_hash: bytes
    runner: SerializedRunner


@dataclass(slots=True, frozen=True)
class SerializedNCTxExecutionFailure:
    """Serialized form of NCTxExecutionFailure for IPC."""
    tx_hash: bytes
    runner: SerializedRunner
    exception_repr: str
    exception_cause_repr: str
    traceback: str


@dataclass(slots=True, frozen=True)
class SerializedNCTxExecutionSkipped:
    """Serialized form of NCTxExecutionSkipped for IPC."""
    tx_hash: bytes


@dataclass(slots=True, frozen=True)
class SerializedNCBeginBlock:
    """Serialized form of NCBeginBlock for IPC."""
    block_hash: bytes
    parent_root_id: bytes
    nc_sorted_call_hashes: list[bytes]


@dataclass(slots=True, frozen=True)
class SerializedNCBeginTransaction:
    """Serialized form of NCBeginTransaction for IPC."""
    tx_hash: bytes
    rng_seed: bytes


@dataclass(slots=True, frozen=True)
class SerializedNCEndTransaction:
    """Serialized form of NCEndTransaction for IPC."""
    tx_hash: bytes


@dataclass(slots=True, frozen=True)
class SerializedNCEndBlock:
    """Serialized form of NCEndBlock for IPC."""
    block_hash: bytes
    final_root_id: bytes
    trie_writes: dict[bytes, bytes] | None = None  # Cached trie writes from proxy storage


SerializedNCBlockEffect = (
    SerializedNCBeginBlock | SerializedNCBeginTransaction |
    SerializedNCTxExecutionSuccess | SerializedNCTxExecutionFailure | SerializedNCTxExecutionSkipped |
    SerializedNCEndTransaction | SerializedNCEndBlock
)


def serialize_runner(runner: Any, call_info: 'CallInfo') -> SerializedRunner:
    """Serialize runner state for IPC.

    Args:
        runner: The Runner instance after execution
        call_info: The CallInfo from the runner

    Returns:
        SerializedRunner with minimal data needed for reconstruction
    """
    # Serialize storage root IDs for all contracts that were modified
    storage_root_ids: dict[bytes, bytes] = {}
    for nc_id, nc_storage in runner._storages.items():
        storage_root_ids[bytes(nc_id)] = nc_storage.get_root_id()

    # Convert token totals to bytes keys
    updated_tokens_totals: dict[bytes, int] = {
        bytes(k): v for k, v in runner._updated_tokens_totals.items()
    }
    paid_actions_fees: dict[bytes, int] = {
        bytes(k): v for k, v in runner._paid_actions_fees.items()
    }

    # Serialize call_info to JSON for logging
    call_info_json = _serialize_call_info_to_json(call_info)

    return SerializedRunner(
        call_info_json=call_info_json,
        storage_root_ids=storage_root_ids,
        updated_tokens_totals=updated_tokens_totals,
        paid_actions_fees=paid_actions_fees,
    )


def _serialize_call_info_to_json(call_info: 'CallInfo') -> str:
    """Serialize CallInfo to JSON string for logging/debugging."""
    calls_data = []
    if call_info.calls:
        for call in call_info.calls:
            call_data: dict[str, Any] = {
                'type': call.type.value,
                'depth': call.depth,
                'contract_id': call.contract_id.hex(),
                'blueprint_id': call.blueprint_id.hex(),
                'method_name': call.method_name,
            }
            if call.ctx is not None:
                call_data['ctx'] = {
                    'caller_id': call.ctx.caller_id.hex() if call.ctx.caller_id else None,
                }
            if call.index_updates is not None:
                call_data['index_updates'] = [
                    _serialize_index_update(record) for record in call.index_updates
                ]
            calls_data.append(call_data)

    # Serialize events from nc_logger
    events_data = []
    if hasattr(call_info.nc_logger, '__events__'):
        for event in call_info.nc_logger.__events__:
            events_data.append({
                'nc_id': event.nc_id.hex(),
                'data': event.data.hex(),
            })

    data = {
        'call_counter': call_info.call_counter,
        'calls': calls_data,
        'events': events_data,
    }
    return json.dumps(data)


def _serialize_index_update(record: Any) -> dict[str, Any]:
    """Serialize an index update record to dict."""
    from hathor.nanocontracts.runner.index_records import (
        CreateContractRecord,
        CreateTokenRecord,
        UpdateAuthoritiesRecord,
        UpdateTokenBalanceRecord,
    )

    if isinstance(record, CreateContractRecord):
        return {
            'type': 'create_contract',
            'blueprint_id': record.blueprint_id.hex(),
            'contract_id': record.contract_id.hex(),
        }
    elif isinstance(record, CreateTokenRecord):
        return {
            'type': 'create_token',
            'token_uid': record.token_uid.hex(),
            'amount': record.amount,
            'token_version': record.token_version.value if record.token_version else None,
            'token_symbol': record.token_symbol,
            'token_name': record.token_name,
        }
    elif isinstance(record, UpdateTokenBalanceRecord):
        return {
            'type': 'update_token_balance',
            'token_uid': record.token_uid.hex(),
            'amount': record.amount,
        }
    elif isinstance(record, UpdateAuthoritiesRecord):
        return {
            'type': 'update_authorities',
            'token_uid': record.token_uid.hex(),
            'index_type': record.type.value,
            'mint': record.mint,
            'melt': record.melt,
        }
    else:
        return {'type': 'unknown', 'repr': repr(record)}


def serialize_effect(effect: Any) -> dict[str, Any]:
    """Serialize an NCBlockEffect to a dictionary for IPC.

    Args:
        effect: One of the NCBlockEffect types from block_executor

    Returns:
        Dictionary that can be serialized via msgpack/pickle
    """
    from hathor.nanocontracts.execution.block_executor import (
        NCBeginBlock,
        NCBeginTransaction,
        NCEndBlock,
        NCEndTransaction,
        NCTxExecutionFailure,
        NCTxExecutionSkipped,
        NCTxExecutionSuccess,
    )

    if isinstance(effect, NCBeginBlock):
        return {
            'type': 'begin_block',
            'block_hash': effect.block.hash,
            'parent_root_id': effect.parent_root_id,
            'nc_sorted_call_hashes': [tx.hash for tx in effect.nc_sorted_calls],
        }
    elif isinstance(effect, NCBeginTransaction):
        return {
            'type': 'begin_transaction',
            'tx_hash': effect.tx.hash,
            'rng_seed': effect.rng_seed,
        }
    elif isinstance(effect, NCTxExecutionSuccess):
        call_info = effect.runner.get_last_call_info()
        return {
            'type': 'tx_success',
            'tx_hash': effect.tx.hash,
            'runner': _serialize_runner_dict(effect.runner, call_info),
        }
    elif isinstance(effect, NCTxExecutionFailure):
        call_info = effect.runner.get_last_call_info()
        return {
            'type': 'tx_failure',
            'tx_hash': effect.tx.hash,
            'runner': _serialize_runner_dict(effect.runner, call_info),
            'exception_repr': repr(effect.exception),
            'exception_cause_repr': repr(effect.exception.__cause__),
            'traceback': effect.traceback,
        }
    elif isinstance(effect, NCTxExecutionSkipped):
        return {
            'type': 'tx_skipped',
            'tx_hash': effect.tx.hash,
        }
    elif isinstance(effect, NCEndTransaction):
        return {
            'type': 'end_transaction',
            'tx_hash': effect.tx.hash,
        }
    elif isinstance(effect, NCEndBlock):
        result: dict[str, Any] = {
            'type': 'end_block',
            'block_hash': effect.block.hash,
            'final_root_id': effect.final_root_id,
        }
        # trie_writes is added by subprocess worker if using proxy storage
        return result
    else:
        raise TypeError(f'Unknown effect type: {type(effect)}')


def _serialize_runner_dict(runner: Any, call_info: 'CallInfo') -> dict[str, Any]:
    """Serialize runner state to dict for IPC."""
    storage_root_ids: dict[bytes, bytes] = {}
    for nc_id, nc_storage in runner._storages.items():
        storage_root_ids[bytes(nc_id)] = nc_storage.get_root_id()

    updated_tokens_totals: dict[bytes, int] = {
        bytes(k): v for k, v in runner._updated_tokens_totals.items()
    }
    paid_actions_fees: dict[bytes, int] = {
        bytes(k): v for k, v in runner._paid_actions_fees.items()
    }

    return {
        'call_info_json': _serialize_call_info_to_json(call_info),
        'storage_root_ids': storage_root_ids,
        'updated_tokens_totals': updated_tokens_totals,
        'paid_actions_fees': paid_actions_fees,
    }


def deserialize_effect(data: dict[str, Any]) -> SerializedNCBlockEffect:
    """Deserialize an effect dictionary back to a SerializedNCBlockEffect.

    Args:
        data: Dictionary from serialize_effect

    Returns:
        Appropriate SerializedNC* dataclass
    """
    effect_type = data['type']

    if effect_type == 'begin_block':
        return SerializedNCBeginBlock(
            block_hash=data['block_hash'],
            parent_root_id=data['parent_root_id'],
            nc_sorted_call_hashes=data['nc_sorted_call_hashes'],
        )
    elif effect_type == 'begin_transaction':
        return SerializedNCBeginTransaction(
            tx_hash=data['tx_hash'],
            rng_seed=data['rng_seed'],
        )
    elif effect_type == 'tx_success':
        runner_data = data['runner']
        return SerializedNCTxExecutionSuccess(
            tx_hash=data['tx_hash'],
            runner=SerializedRunner(
                call_info_json=runner_data['call_info_json'],
                storage_root_ids=runner_data['storage_root_ids'],
                updated_tokens_totals=runner_data['updated_tokens_totals'],
                paid_actions_fees=runner_data['paid_actions_fees'],
            ),
        )
    elif effect_type == 'tx_failure':
        runner_data = data['runner']
        return SerializedNCTxExecutionFailure(
            tx_hash=data['tx_hash'],
            runner=SerializedRunner(
                call_info_json=runner_data['call_info_json'],
                storage_root_ids=runner_data['storage_root_ids'],
                updated_tokens_totals=runner_data['updated_tokens_totals'],
                paid_actions_fees=runner_data['paid_actions_fees'],
            ),
            exception_repr=data['exception_repr'],
            exception_cause_repr=data['exception_cause_repr'],
            traceback=data['traceback'],
        )
    elif effect_type == 'tx_skipped':
        return SerializedNCTxExecutionSkipped(
            tx_hash=data['tx_hash'],
        )
    elif effect_type == 'end_transaction':
        return SerializedNCEndTransaction(
            tx_hash=data['tx_hash'],
        )
    elif effect_type == 'end_block':
        # Decode trie_writes from hex if present
        trie_writes = None
        if 'trie_writes' in data and data['trie_writes'] is not None:
            trie_writes = {
                bytes.fromhex(k): bytes.fromhex(v)
                for k, v in data['trie_writes'].items()
            }
        return SerializedNCEndBlock(
            block_hash=data['block_hash'],
            final_root_id=data['final_root_id'],
            trie_writes=trie_writes,
        )
    else:
        raise ValueError(f'Unknown effect type: {effect_type}')


@dataclass(slots=True, frozen=True)
class BlockExecutionRequest:
    """Request to execute a block in subprocess.

    Contains minimal data needed to identify and execute the block.
    """
    block_hash: bytes
    parent_root_id: bytes
    should_skip_tx_hashes: frozenset[bytes]


def serialize_request(request: BlockExecutionRequest) -> dict[str, Any]:
    """Serialize BlockExecutionRequest for IPC."""
    return {
        'block_hash': request.block_hash,
        'parent_root_id': request.parent_root_id,
        'should_skip_tx_hashes': list(request.should_skip_tx_hashes),
    }


def deserialize_request(data: dict[str, Any]) -> BlockExecutionRequest:
    """Deserialize BlockExecutionRequest from IPC."""
    return BlockExecutionRequest(
        block_hash=data['block_hash'],
        parent_root_id=data['parent_root_id'],
        should_skip_tx_hashes=frozenset(data['should_skip_tx_hashes']),
    )
