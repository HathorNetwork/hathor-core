# Copyright 2021 Hathor Labs
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

from typing import TYPE_CHECKING, Any, Optional

from hathor.transaction import BaseTransaction, Transaction

if TYPE_CHECKING:
    from hathor.nanocontracts.nc_exec_logs import NCLogStorage
    from hathor.transaction.storage import TransactionStorage


class VertexJsonSerializer:
    """Helper class for vertex/transaction serialization."""

    def __init__(
        self,
        storage: 'TransactionStorage',
        nc_log_storage: Optional['NCLogStorage'] = None,
    ) -> None:
        self.tx_storage = storage
        self.nc_log_storage = nc_log_storage

    def to_json(
        self,
        tx: BaseTransaction,
        decode_script: bool = False,
        include_metadata: bool = False,
        include_nc_logs: bool = False,
        include_nc_events: bool = False,
    ) -> dict[str, Any]:
        """Serialize transaction to JSON."""
        # Get base JSON from transaction
        data = tx.to_json(decode_script=decode_script, include_metadata=include_metadata)

        # Add nano contract logs if requested
        if include_nc_logs:
            self._add_nc_logs_to_dict(tx, data)

        # Add nano contract events if requested
        if include_nc_events:
            self._add_nc_events_to_dict(tx, data)

        return data

    def to_json_extended(
        self,
        tx: BaseTransaction,
        include_nc_logs: bool = False,
        include_nc_events: bool = False,
    ) -> dict[str, Any]:
        """Serialize transaction to extended JSON format."""
        data = tx.to_json_extended()

        # Add nano contract logs if requested
        if include_nc_logs:
            self._add_nc_logs_to_dict(tx, data)

        # Add nano contract events if requested
        if include_nc_events:
            self._add_nc_events_to_dict(tx, data)

        # Add decoded arguments if applicable
        self._add_nc_args_decoded(tx, data)

        return data

    def _add_nc_logs_to_dict(self, tx: BaseTransaction, data: dict[str, Any]) -> None:
        """Add nano contract execution logs to the data dictionary."""
        if not tx.is_nano_contract():
            return

        nc_logs: dict[str, Any] | None
        if self.nc_log_storage is None:
            nc_logs = {}
        else:
            nc_logs = self.nc_log_storage.get_json_logs(tx.hash)

        data['nc_logs'] = nc_logs

    def _add_nc_events_to_dict(self, tx: BaseTransaction, data: dict[str, Any]) -> None:
        """Add nano contract events to the data dictionary."""
        if not tx.is_nano_contract():
            return

        meta = tx.get_metadata()
        if meta.nc_events is None:
            nc_events = []
        else:
            nc_events = [
                {'nc_id': nc_id.hex(), 'data': event_data.hex()}
                for nc_id, event_data in meta.nc_events
            ]

        data['nc_events'] = nc_events

    def _add_nc_args_decoded(self, tx: BaseTransaction, data: dict[str, Any]) -> None:
        if not tx.is_nano_contract():
            return

        assert isinstance(tx, Transaction)
        nc_args_decoded = self.decode_nc_args(tx)
        if nc_args_decoded is not None:
            data['nc_args_decoded'] = nc_args_decoded

    def decode_nc_args(self, tx: 'Transaction') -> Any:
        """Decode nano contract arguments.

        Returns a list of JSON-serialized argument strings, or None if decoding is not applicable.
        """
        from hathor.nanocontracts.exception import NCFail
        from hathor.nanocontracts.method import Method
        from hathor.nanocontracts.types import BlueprintId

        meta = tx.get_metadata()
        nano_header = tx.get_nano_header()

        if meta.nc_calls and len(meta.nc_calls) > 0:
            # Get blueprint_id from the first nc_calls record
            blueprint_id = BlueprintId(meta.nc_calls[0].blueprint_id)
        else:
            # Get blueprint_id from NanoHeader
            blueprint_id = nano_header.get_blueprint_id_for_json()

        try:
            blueprint_class = self.tx_storage.get_blueprint_class(blueprint_id)
        except NCFail:
            return None

        method_callable = getattr(blueprint_class, nano_header.nc_method, None)
        if method_callable is None:
            return None

        method = Method.from_callable(method_callable)

        try:
            args_tuple = method.deserialize_args_bytes(nano_header.nc_args_bytes)
        except NCFail:
            return None

        return method.args._value_to_json(args_tuple)
