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

from typing import Any, Optional

from typing_extensions import override

from hathor.conf.settings import HathorSettings
from hathor.nanocontracts.storage import NCBlockStorage
from hathor.serialization import Serializer
from hathor.transaction.base_transaction import TxInput, TxOutput, TxVersion
from hathor.transaction.storage import TransactionStorage  # noqa: F401
from hathor.transaction.token_info import TokenInfo, TokenInfoDict, TokenVersion
from hathor.transaction.transaction import Transaction
from hathor.transaction.util import VerboseCallback


class TokenCreationTransaction(Transaction):
    def __init__(
        self,
        nonce: int = 0,
        timestamp: Optional[int] = None,
        signal_bits: int = 0,
        version: TxVersion = TxVersion.TOKEN_CREATION_TRANSACTION,
        weight: float = 0,
        inputs: Optional[list[TxInput]] = None,
        outputs: Optional[list[TxOutput]] = None,
        parents: Optional[list[bytes]] = None,
        hash: Optional[bytes] = None,
        token_name: str = '',
        token_symbol: str = '',
        storage: Optional['TransactionStorage'] = None,
        settings: HathorSettings | None = None,
        token_version: TokenVersion = TokenVersion.DEPOSIT,
    ) -> None:
        super().__init__(
            nonce=nonce,
            timestamp=timestamp,
            signal_bits=signal_bits,
            version=version,
            weight=weight,
            inputs=inputs,
            outputs=outputs or [],
            parents=parents or [],
            hash=hash,
            storage=storage,
            settings=settings,
        )
        self.token_version = token_version
        self.token_name = token_name
        self.token_symbol = token_symbol
        # for this special tx, its own hash is used as the created token uid. We're artificially
        # creating the tokens list here
        self.tokens = [hash] if hash is not None else []

    def __str__(self) -> str:
        return ', '.join([
            'TokenCreationTransaction(',
            f'nonce={self.nonce}',
            f'timestamp={self.timestamp}',
            f'version={int(self.version)}',
            f'weight={self.weight}',
            f'hash={self.hash_hex}',
            f'token_name={self.token_name}',
            f'token_symbol={self.token_symbol}',
            f'token_version={self.token_version})'
        ])

    def update_hash(self) -> None:
        """ When we update the hash, we also have to update the tokens uid list
        """
        super().update_hash()
        self.tokens = [self.hash]

    @override
    def get_funds_struct(self) -> bytes:
        from hathor.transaction.vertex_parser._token_creation import serialize_token_creation_funds
        serializer = Serializer.build_bytes_serializer()
        serialize_token_creation_funds(serializer, self)
        return bytes(serializer.finalize())

    def serialize_token_info(self) -> bytes:
        """ Returns the serialization for token name and symbol
        """
        from hathor.transaction.vertex_parser import vertex_serializer
        return vertex_serializer.serialize_token_info(self)

    @classmethod
    def deserialize_token_info(
            cls,
            buf: bytes,
            *,
            verbose: VerboseCallback = None) -> tuple[str, str, TokenVersion, bytes]:
        """ Gets the token name, symbol and version from serialized format
        """
        from hathor.transaction.vertex_parser import vertex_deserializer
        return vertex_deserializer.deserialize_token_info(buf, verbose=verbose)

    def to_json(self, decode_script: bool = False, include_metadata: bool = False) -> dict[str, Any]:
        json = super().to_json(decode_script=decode_script, include_metadata=include_metadata)
        json['token_name'] = self.token_name
        json['token_symbol'] = self.token_symbol
        json['tokens'] = []
        return json

    def to_json_extended(self) -> dict[str, Any]:
        json = super().to_json_extended()
        json['token_name'] = self.token_name
        json['token_symbol'] = self.token_symbol
        json['tokens'] = []
        return json

    @override
    def _get_token_info_from_inputs(self, nc_block_storage: NCBlockStorage) -> TokenInfoDict:
        token_dict = super()._get_token_info_from_inputs(nc_block_storage)

        # we add the created token's info to token_dict, as the creation tx allows for mint/melt
        token_dict[self.hash] = TokenInfo(version=self.token_version, can_mint=True, can_melt=True)

        return token_dict
