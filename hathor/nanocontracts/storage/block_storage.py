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

from enum import Enum
from typing import NamedTuple, Optional

from hathor.nanocontracts.exception import NanoContractDoesNotExist
from hathor.nanocontracts.nc_types.dataclass_nc_type import make_dataclass_nc_type
from hathor.nanocontracts.storage.contract_storage import NCContractStorage
from hathor.nanocontracts.storage.patricia_trie import NodeId, PatriciaTrie
from hathor.nanocontracts.storage.token_proxy import TokenProxy
from hathor.nanocontracts.types import Address, ContractId, TokenUid
from hathor.transaction.headers.nano_header import ADDRESS_SEQNUM_SIZE
from hathor.utils import leb128


class _Tag(Enum):
    CONTRACT = b'\0'
    TOKEN = b'\1'
    ADDRESS = b'\2'


class ContractKey(NamedTuple):
    nc_id: bytes

    def __bytes__(self):
        return _Tag.CONTRACT.value + self.nc_id


class TokenKey(NamedTuple):
    token_id: bytes

    def __bytes__(self):
        return _Tag.TOKEN.value + self.token_id


class AddressKey(NamedTuple):
    address: Address

    def __bytes__(self):
        return _Tag.ADDRESS.value + self.address


class NCBlockStorage:
    """This is the storage used by NanoContracts.

    This implementation works for both memory and rocksdb backends."""
    from hathor.transaction.token_info import TokenDescription
    _TOKEN_DESCRIPTION_NC_TYPE = make_dataclass_nc_type(TokenDescription)

    def __init__(self, block_trie: PatriciaTrie) -> None:
        self._block_trie: PatriciaTrie = block_trie

    def has_contract(self, contract_id: ContractId) -> bool:
        try:
            self.get_contract_root_id(contract_id)
        except KeyError:
            return False
        else:
            return True

    def get_contract_root_id(self, contract_id: ContractId) -> bytes:
        """Return the root id of a contract's storage."""
        key = ContractKey(contract_id)
        return self._block_trie.get(bytes(key))

    def update_contract_trie(self, nc_id: ContractId, root_id: bytes) -> None:
        key = ContractKey(nc_id)
        self._block_trie.update(bytes(key), root_id)

    def commit(self) -> None:
        """Flush all local changes to the storage."""
        self._block_trie.commit()

    def get_root_id(self) -> bytes:
        """Return the current merkle root id of the trie."""
        return self._block_trie.root.id

    @staticmethod
    def bytes_to_node_id(node_id: Optional[bytes]) -> Optional[NodeId]:
        if node_id is None:
            return node_id
        return NodeId(node_id)

    def _get_trie(self, root_id: Optional[bytes]) -> 'PatriciaTrie':
        """Return a PatriciaTrie object with a given root."""
        from hathor.nanocontracts.storage.patricia_trie import PatriciaTrie
        store = self._block_trie.get_store()
        trie = PatriciaTrie(store, root_id=self.bytes_to_node_id(root_id))
        return trie

    def get_contract_storage(self, contract_id: ContractId) -> NCContractStorage:
        try:
            nc_root_id = self.get_contract_root_id(contract_id)
            trie = self._get_trie(nc_root_id)
        except KeyError:
            raise NanoContractDoesNotExist(contract_id.hex())
        token_proxy = TokenProxy(self)
        return NCContractStorage(trie=trie, nc_id=contract_id, token_proxy=token_proxy)

    def get_empty_contract_storage(self, contract_id: ContractId) -> NCContractStorage:
        """Create a new contract storage instance for a given contract."""
        trie = self._get_trie(None)
        token_proxy = TokenProxy(self)
        return NCContractStorage(trie=trie, nc_id=contract_id, token_proxy=token_proxy)

    def get_token_description(self, token_id: TokenUid) -> TokenDescription:
        """Return the token description for a given token_id."""
        key = TokenKey(token_id)
        token_description_bytes = self._block_trie.get(bytes(key))
        token_description = self._TOKEN_DESCRIPTION_NC_TYPE.from_bytes(token_description_bytes)
        return token_description

    def has_token(self, token_id: TokenUid) -> bool:
        """Return True if the token_id already exists in this block's nano state."""
        key = TokenKey(token_id)
        try:
            self._block_trie.get(bytes(key))
        except KeyError:
            return False
        else:
            return True

    def create_token(self, token_id: TokenUid, token_name: str, token_symbol: str) -> None:
        """Create a new token in this block's nano state."""
        from hathor.transaction.token_info import TokenDescription
        key = TokenKey(token_id)
        token_description = TokenDescription(token_id=token_id, token_name=token_name, token_symbol=token_symbol)
        token_description_bytes = self._TOKEN_DESCRIPTION_NC_TYPE.to_bytes(token_description)
        self._block_trie.update(bytes(key), token_description_bytes)

    def get_address_seqnum(self, address: Address) -> int:
        """Get the latest seqnum for an address.

        For clarity, new transactions must have a GREATER seqnum to be able to be executed."""
        key = AddressKey(address)
        try:
            seqnum_bytes = self._block_trie.get(bytes(key))
        except KeyError:
            return -1
        else:
            seqnum, buf = leb128.decode_unsigned(seqnum_bytes, max_bytes=ADDRESS_SEQNUM_SIZE)
            assert len(buf) == 0
            return seqnum

    def set_address_seqnum(self, address: Address, seqnum: int) -> None:
        """Update seqnum for an adress."""
        assert seqnum >= 0
        old_seqnum = self.get_address_seqnum(address)
        assert seqnum > old_seqnum
        key = AddressKey(address)
        seqnum_bytes = leb128.encode_unsigned(seqnum, max_bytes=ADDRESS_SEQNUM_SIZE)
        self._block_trie.update(bytes(key), seqnum_bytes)
