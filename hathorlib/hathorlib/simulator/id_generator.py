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

from __future__ import annotations

import hashlib

from hathorlib.nanocontracts.types import Address, BlueprintId, ContractId, TokenUid, VertexId
from hathorlib.utils.address import get_hash160


class IdGenerator:
    """Generates deterministic IDs for simulation.

    All IDs are derived from SHA-256 hashes, ensuring reproducibility
    within a simulation run (same seed + same operations = same IDs).
    """

    def __init__(self, seed: bytes, address_version_byte: bytes) -> None:
        self._counter: int = 0
        self._seed = seed
        self._addr_version_byte = address_version_byte

    def _next_counter(self) -> int:
        self._counter += 1
        return self._counter

    def create_address(self, name: str) -> Address:
        """Create a deterministic address from a human-readable name.

        Produces 25 bytes: version_byte + 20-byte hash + 4-byte checksum.
        This matches the P2PKH address format.
        """
        raw = get_hash160(f'address:{name}'.encode())
        payload = self._addr_version_byte + raw
        checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
        return Address(payload + checksum)

    def create_contract_id(self, name: str | None = None) -> ContractId:
        """Create a deterministic contract ID.

        Uses an internal counter to guarantee uniqueness even without a name.
        """
        counter = self._next_counter()
        label = name or str(counter)
        raw = hashlib.sha256(f'contract:{counter}:{label}:{self._seed.hex()}'.encode()).digest()
        return ContractId(raw)

    def create_blueprint_id(self, blueprint_class: type) -> BlueprintId:
        """Create a deterministic blueprint ID from the class name."""
        raw = hashlib.sha256(f'blueprint:{blueprint_class.__name__}'.encode()).digest()
        return BlueprintId(raw)

    def create_token_uid(self, name: str) -> TokenUid:
        """Create a deterministic token UID from a name."""
        raw = hashlib.sha256(f'token:{name}'.encode()).digest()
        return TokenUid(raw)

    def create_vertex_id(self, label: str) -> VertexId:
        """Create a deterministic vertex ID (used for tx_hash, block_hash)."""
        counter = self._next_counter()
        raw = hashlib.sha256(f'vertex:{counter}:{label}:{self._seed.hex()}'.encode()).digest()
        return VertexId(raw)

    @property
    def counter(self) -> int:
        return self._counter

    @counter.setter
    def counter(self, value: int) -> None:
        self._counter = value
