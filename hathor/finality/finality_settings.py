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

"""
Finality committee configuration.

The committee of finality validators, and each validator's voting weight, is fixed in the network
settings (PoA-style). We use weight-based BFT thresholds: with total weight ``W`` and at most ``f``
Byzantine weight calibrated as ``W = 3f + 1``, a quorum is any set of validators whose summed weight
is ``>= 2f + 1``. The thresholds are derived from the configured weights, and each validator's
proof-of-possession is verified when the committee is loaded (required for the rogue-key safety of
same-message aggregate verification).
"""

from __future__ import annotations

import hashlib
from typing import Any

from pydantic import PositiveInt, PrivateAttr, field_validator, model_validator

from hathor.finality.crypto import (
    BLS_PUBLIC_KEY_LEN,
    BLS_SIGNATURE_LEN,
    BLSPublicKey,
    BLSSignature,
    bls_pop_verify,
)
from hathor.util import json_dumpb
from hathor.utils.pydantic import BaseModel, Hex


class FinalityValidatorSettings(BaseModel):
    """Configuration for a single finality validator: its BLS public key, PoP, and voting weight."""

    public_key: Hex[bytes]
    pop: Hex[bytes]
    weight: PositiveInt = 1

    @field_validator('public_key')
    @classmethod
    def _validate_public_key(cls, public_key: bytes) -> bytes:
        if len(public_key) != BLS_PUBLIC_KEY_LEN:
            raise ValueError(f'public key must be {BLS_PUBLIC_KEY_LEN} bytes, got {len(public_key)}')
        return public_key

    @field_validator('pop')
    @classmethod
    def _validate_pop(cls, pop: bytes) -> bytes:
        if len(pop) != BLS_SIGNATURE_LEN:
            raise ValueError(f'proof-of-possession must be {BLS_SIGNATURE_LEN} bytes, got {len(pop)}')
        return pop

    def to_json_dict(self) -> dict[str, Any]:
        """Return this validator settings instance as a json dict (used for the committee hash)."""
        return self.model_dump()


class FinalitySettings(BaseModel):
    """The finality committee for a network.

    When ``enabled`` is False (the default), the two-tier finality subsystem is dormant and these
    settings carry no committee. When enabled, ``validators`` defines the committee and the derived
    quorum thresholds below are available.
    """

    enabled: bool = False
    validators: tuple[FinalityValidatorSettings, ...] = ()

    # Lazily-computed, committee-derived data (populated once at load when enabled).
    _committee_hash: str | None = PrivateAttr(default=None)
    _public_keys: tuple[BLSPublicKey, ...] = PrivateAttr(default=())
    _weights: tuple[int, ...] = PrivateAttr(default=())
    _committee_index: dict[bytes, int] = PrivateAttr(default_factory=dict)
    _total_weight: int = PrivateAttr(default=0)
    _f: int = PrivateAttr(default=0)
    _quorum_threshold: int = PrivateAttr(default=0)

    @model_validator(mode='after')
    def _validate_and_derive(self) -> 'FinalitySettings':
        if not self.enabled:
            return self

        if len(self.validators) == 0:
            raise ValueError('at least one validator must be provided when finality is enabled')

        seen: set[bytes] = set()
        for validator in self.validators:
            public_key = bytes(validator.public_key)
            if public_key in seen:
                raise ValueError('duplicate validator public key')
            seen.add(public_key)
            if not bls_pop_verify(BLSPublicKey(public_key), BLSSignature(bytes(validator.pop))):
                raise ValueError(f'invalid proof-of-possession for validator {public_key.hex()}')

        self._public_keys = tuple(BLSPublicKey(bytes(v.public_key)) for v in self.validators)
        self._weights = tuple(int(v.weight) for v in self.validators)
        self._committee_index = {bytes(v.public_key): i for i, v in enumerate(self.validators)}
        self._total_weight = sum(self._weights)
        # Calibrate W = 3f + 1, i.e. f is the largest value with 3f + 1 <= W.
        self._f = (self._total_weight - 1) // 3
        self._quorum_threshold = 2 * self._f + 1
        return self

    @property
    def total_weight(self) -> int:
        """Total voting weight ``W`` of the committee."""
        return self._total_weight

    @property
    def f(self) -> int:
        """Maximum tolerated Byzantine weight ``f``, calibrated so ``W = 3f + 1``."""
        return self._f

    @property
    def quorum_threshold(self) -> int:
        """Minimum summed weight for a quorum, ``2f + 1``."""
        return self._quorum_threshold

    @property
    def public_keys(self) -> tuple[BLSPublicKey, ...]:
        """The committee public keys, in bitmap-index order."""
        return self._public_keys

    @property
    def weights(self) -> tuple[int, ...]:
        """Per-validator voting weights, in bitmap-index order."""
        return self._weights

    def get_validator_index(self, public_key: bytes) -> int | None:
        """Return the bitmap index of a validator's public key, or None if it is not in the committee."""
        return self._committee_index.get(bytes(public_key))

    def weight_of_bitmap(self, bitmap: int) -> int:
        """Return the total voting weight of the validators whose bits are set in ``bitmap``."""
        total = 0
        for index, weight in enumerate(self._weights):
            if bitmap & (1 << index):
                total += weight
        return total

    def reaches_quorum(self, bitmap: int) -> bool:
        """Return whether the validators selected by ``bitmap`` reach a quorum (weight ``>= 2f+1``)."""
        return self.weight_of_bitmap(bitmap) >= self._quorum_threshold

    def public_keys_for_bitmap(self, bitmap: int) -> list[BLSPublicKey]:
        """Return the committee public keys selected by ``bitmap``, in bitmap-index order."""
        return [pk for index, pk in enumerate(self._public_keys) if bitmap & (1 << index)]

    def calculate_committee_hash(self) -> bytes:
        """Return a stable hash of the committee, used to bind votes and to gate peer connections.

        Mirrors `PoaSettings._calculate_peer_hello_hash`: a node only exchanges finality data with
        peers that share the same committee.
        """
        if self._committee_hash is None:
            data = b''
            for validator in self.validators:
                data += json_dumpb(validator.to_json_dict())
            self._committee_hash = hashlib.sha256(data).digest().hex()
        return bytes.fromhex(self._committee_hash)
