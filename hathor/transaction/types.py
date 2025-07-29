# Copyright 2023 Hathor Labs
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

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Self

if TYPE_CHECKING:
    from hathor.nanocontracts.runner.types import CallRecord, NCIndexUpdateRecord


@dataclass(slots=True, frozen=True, kw_only=True)
class MetaNCCallRecord:
    """Dataclass to hold NC call information in transaction metadata."""
    blueprint_id: bytes
    contract_id: bytes
    method_name: str
    index_updates: list[NCIndexUpdateRecord]

    def to_json(self) -> dict[str, Any]:
        """Convert this record to a json dict."""
        return dict(
            blueprint_id=self.blueprint_id.hex(),
            contract_id=self.contract_id.hex(),
            method_name=self.method_name,
            index_updates=[syscall.to_json() for syscall in self.index_updates]
        )

    @classmethod
    def from_json(cls, json_dict: dict[str, Any]) -> Self:
        """Create an instance from a json dict."""
        from hathor.nanocontracts.runner.types import nc_index_update_record_from_json
        return cls(
            blueprint_id=bytes.fromhex(json_dict['blueprint_id']),
            contract_id=bytes.fromhex(json_dict['contract_id']),
            method_name=json_dict['method_name'],
            index_updates=[nc_index_update_record_from_json(syscall) for syscall in json_dict['index_updates']]
        )

    @classmethod
    def from_call_record(cls, call_record: CallRecord) -> Self:
        """Create an instance from a CallRecord."""
        assert call_record.index_updates is not None
        return cls(
            blueprint_id=call_record.blueprint_id,
            contract_id=call_record.contract_id,
            method_name=call_record.method_name,
            index_updates=call_record.index_updates,
        )
