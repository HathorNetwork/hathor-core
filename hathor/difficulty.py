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

"""
# Terms

- u256: unsigned 256-bit integer
- hash: 256-bit hash, same for Bitcoin and Hathor
- target: 32-bit Bitcoin target
- bdiff: Bitcoin difficulty (which truncates diff 1), used for Bitcoin fullnode related calculations
- pdiff: Pool difficulty (which does not truncate diff 1), used for pool difficulty calculations
- weight: Logarithmic (base 2) work, as used in Hathor

# Conversions

Primitive:

- u256 -> hash
- u256 -> target
- u256 -> bdiff
- u256 -> pdiff
- u256 -> weight
- hash -> u256
- target -> u256
- bdiff -> u256
- pdiff -> u256
- weight -> u256

From the above conversions it is possible to make all conversions between (hash, target, bdiff, pdiff, weight) using
u256 as intermediary.

# References

- https://en.bitcoin.it/wiki/Difficulty
- https://en.bitcoin.it/wiki/Target
"""

from math import log2
from typing import Union

BDIFF_ONE = 0x00000000ffff0000000000000000000000000000000000000000000000000000
PDIFF_ONE = 0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff
U256_MAX = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
TARGET_MAX = 0x1d00ffff


class U256(int):
    def __new__(cls, value):
        if value > U256_MAX:
            raise ValueError('too big')
        if value < 0:
            raise ValueError('negative number not allowed')
        return int.__new__(cls, value)

    def __str__(self):
        return f'{self:064x}'

    def __repr__(self):
        return f'U256(0x{self:064x})'

    def to_hash(self) -> 'Hash':
        """ Convert to Hash

        Examples:

        >>> U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_hash()
        Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a)
        >>> U256(0x000000000000000000130c780000000000000000000000000000000000000000).to_hash()
        Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> U256(0x00000000000404cb000000000000000000000000000000000000000000000000).to_hash()
        Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> U256(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_hash()
        Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_hash()
        Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        """
        # ALIAS: u256 <- hash
        return Hash(self)

    def to_target(self) -> 'Target':
        """ Convert to Target

        WARNING: this process is lossy:

        >>> U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_target().to_u256()
        U256(0x0000000000000000000b0f270000000000000000000000000000000000000000)
        >>> U256(0x000000000000000000130c780000000000000000000000000000000000000000).to_target().to_u256()
        U256(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> U256(0x00000000000404cb000000000000000000000000000000000000000000000000).to_target().to_u256()
        U256(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> U256(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_target().to_u256()
        U256(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_target().to_u256()
        U256(0x00000000ffffff00000000000000000000000000000000000000000000000000)

        Examples:

        >>> U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_target()
        Target(0x170b0f27)
        >>> U256(0x000000000000000000130c780000000000000000000000000000000000000000).to_target()
        Target(0x17130c78)
        >>> U256(0x00000000000404cb000000000000000000000000000000000000000000000000).to_target()
        Target(0x1b0404cb)
        >>> U256(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_target()
        Target(0x1cffff00)
        >>> U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_target()
        Target(0x1cffffff)
        """
        # PRIMITIVE: u256 -> target
        high_bits = 3
        low_bits = int(self)
        while low_bits > 0xffffff and high_bits < 0xff:
            high_bits += 1
            low_bits >>= 8
        assert high_bits <= 0xff
        assert low_bits <= 0xffffff
        return Target((high_bits << 24) | low_bits)

    def to_bdiff(self) -> 'BDiff':
        """ Convert to BDiff

        WARNING: this process is lossy:

        >>> U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_bdiff().to_u256()
        U256(0x0000000000000000000b0f271558b6ae00000000000000000000000000000000)
        >>> U256(0x000000000000000000130c780000000000000000000000000000000000000000).to_bdiff().to_u256()
        U256(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> U256(0x00000000000404cb000000000000000000000000000000000000000000000000).to_bdiff().to_u256()
        U256(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> U256(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_bdiff().to_u256()
        U256(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_bdiff().to_u256()
        U256(0x0000000100000000000000000000000000000000000000000000000000000000)

        Examples:

        >>> U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_bdiff()
        BDiff(25451292437624.176)
        >>> U256(0x000000000000000000130c780000000000000000000000000000000000000000).to_bdiff()
        BDiff(14776367535688.639)
        >>> U256(0x00000000000404cb000000000000000000000000000000000000000000000000).to_bdiff()
        BDiff(16307.420938523983)
        >>> U256(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_bdiff()
        BDiff(1.0)
        >>> U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_bdiff()
        BDiff(0.9999847412109375)
        """
        # PRIMITIVE: u256 -> bdiff
        return BDiff(BDIFF_ONE / self)

    def to_pdiff(self) -> 'PDiff':
        """ Convert to PDiff

        WARNING: this process is lossy:

        >>> U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_pdiff().to_u256()
        U256(0x0000000000000000000b0f271558b6ae00000000000000000000000000000000)
        >>> U256(0x000000000000000000130c780000000000000000000000000000000000000000).to_pdiff().to_u256()
        U256(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> U256(0x00000000000404cb000000000000000000000000000000000000000000000000).to_pdiff().to_u256()
        U256(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> U256(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_pdiff().to_u256()
        U256(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_pdiff().to_u256()
        U256(0x0000000100000000000000000000000000000000000000000000000000000000)

        Examples:

        >>> U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_pdiff()
        PDiff(25451680799452.777)
        >>> U256(0x000000000000000000130c780000000000000000000000000000000000000000).to_pdiff()
        PDiff(14776593008604.42)
        >>> U256(0x00000000000404cb000000000000000000000000000000000000000000000000).to_pdiff()
        PDiff(16307.669773817162)
        >>> U256(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_pdiff()
        PDiff(1.0000152590218967)
        >>> U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_pdiff()
        PDiff(1.0)
        """
        # PRIMITIVE: u256 -> pdiff
        return PDiff(PDIFF_ONE / self)

    def to_weight(self) -> 'Weight':
        """ Convert to Weight

        WARNING: this process is lossy:

        >>> U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_weight().to_u256()
        U256(0x0000000000000000000b0f271558b6c000000000000000000000000000000000)
        >>> U256(0x000000000000000000130c780000000000000000000000000000000000000000).to_weight().to_u256()
        U256(0x000000000000000000130c77ffffffe100000000000000000000000000000000)
        >>> U256(0x00000000000404cb000000000000000000000000000000000000000000000000).to_weight().to_u256()
        U256(0x00000000000404cb000000060000000000000000000000000000000000000000)
        >>> U256(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_weight().to_u256()
        U256(0x00000000fffefffffffe38000000000000000000000000000000000000000000)
        >>> U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_weight().to_u256()
        U256(0x0000000100000000000000000000000000000000000000000000000000000000)

        Examples:

        >>> U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_weight()
        Weight(76.53282616688836)
        >>> U256(0x000000000000000000130c780000000000000000000000000000000000000000).to_weight()
        Weight(75.74837890381858)
        >>> U256(0x00000000000404cb000000000000000000000000000000000000000000000000).to_weight()
        Weight(45.993263027575125)
        >>> U256(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_weight()
        Weight(32.00002201394727)
        >>> U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_weight()
        Weight(32.0)
        """
        # PRIMITIVE: u256 -> weight
        return Weight(256 - log2(self + 1))


class Hash(bytes):
    def __new__(cls, value: Union[bytes, int]) -> 'Hash':
        """ Creates Hash instance, accepts bytes (32-byte long) or int.

        From bytes:

        >>> Hash(bytes.fromhex('0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a'))
        Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a)
        >>> Hash(bytes.fromhex('000000000000000000130c780000000000000000000000000000000000000000'))
        Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> Hash(bytes.fromhex('00000000000404cb000000000000000000000000000000000000000000000000'))
        Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> Hash(bytes.fromhex('00000000ffff0000000000000000000000000000000000000000000000000000'))
        Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> Hash(bytes.fromhex('00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff'))
        Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff)

        From int:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a)
        Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        """
        _value: bytes
        if isinstance(value, bytes):
            _value = value
        elif isinstance(value, int):
            # PRIMITIVE: u256 -> hash
            _value = value.to_bytes(32, 'big')
        else:
            raise TypeError(f'invalid type {value.__class__}')
        if len(_value) != 32:
            raise ValueError(f'value has invalid binary length {len(_value)}')
        return bytes.__new__(cls, _value)

    def __str__(self):
        return self.hex()

    def __repr__(self):
        return f'Hash(0x{self.hex()})'

    def to_u256(self) -> U256:
        """ Convert to U256

        Examples:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_u256()
        U256(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000).to_u256()
        U256(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000).to_u256()
        U256(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_u256()
        U256(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_u256()
        U256(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff)
        """
        # PRIMITIVE: hash -> u256
        return U256(int(self.hex(), 16))

    def to_target(self) -> 'Target':
        """ Convert to Target

        WARNING: this process is lossy:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_target().to_hash()
        Hash(0x0000000000000000000b0f270000000000000000000000000000000000000000)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000).to_target().to_hash()
        Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000).to_target().to_hash()
        Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_target().to_hash()
        Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_target().to_hash()
        Hash(0x00000000ffffff00000000000000000000000000000000000000000000000000)

        Examples:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_target()
        Target(0x170b0f27)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000).to_target()
        Target(0x17130c78)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000).to_target()
        Target(0x1b0404cb)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_target()
        Target(0x1cffff00)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_target()
        Target(0x1cffffff)
        """
        # ALIAS: hash -> u256 -> target
        return self.to_u256().to_target()

    def to_bdiff(self) -> 'BDiff':
        """ Convert to BDiff

        WARNING: this process is lossy:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_bdiff().to_hash()
        Hash(0x0000000000000000000b0f271558b6ae00000000000000000000000000000000)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000).to_bdiff().to_hash()
        Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000).to_bdiff().to_hash()
        Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_bdiff().to_hash()
        Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_bdiff().to_hash()
        Hash(0x0000000100000000000000000000000000000000000000000000000000000000)

        Examples:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_bdiff()
        BDiff(25451292437624.176)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000).to_bdiff()
        BDiff(14776367535688.639)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000).to_bdiff()
        BDiff(16307.420938523983)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_bdiff()
        BDiff(1.0)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_bdiff()
        BDiff(0.9999847412109375)
        """
        # ALIAS: hash -> u256 -> bdiff
        return self.to_u256().to_bdiff()

    def to_pdiff(self) -> 'PDiff':
        """ Convert to PDiff

        WARNING: this process is lossy:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_pdiff().to_hash()
        Hash(0x0000000000000000000b0f271558b6ae00000000000000000000000000000000)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000).to_pdiff().to_hash()
        Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000).to_pdiff().to_hash()
        Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_pdiff().to_hash()
        Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_pdiff().to_hash()
        Hash(0x0000000100000000000000000000000000000000000000000000000000000000)

        Examples:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_pdiff()
        PDiff(25451680799452.777)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000).to_pdiff()
        PDiff(14776593008604.42)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000).to_pdiff()
        PDiff(16307.669773817162)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_pdiff()
        PDiff(1.0000152590218967)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_pdiff()
        PDiff(1.0)
        """
        # ALIAS: hash -> u256 -> pdiff
        return self.to_u256().to_pdiff()

    def to_weight(self) -> 'Weight':
        """ Convert to Weight

        WARNING: this process is lossy:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_weight().to_hash()
        Hash(0x0000000000000000000b0f271558b6c000000000000000000000000000000000)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000).to_weight().to_hash()
        Hash(0x000000000000000000130c77ffffffe100000000000000000000000000000000)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000).to_weight().to_hash()
        Hash(0x00000000000404cb000000060000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_weight().to_hash()
        Hash(0x00000000fffefffffffe38000000000000000000000000000000000000000000)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_weight().to_hash()
        Hash(0x0000000100000000000000000000000000000000000000000000000000000000)

        Examples:

        >>> Hash(0x0000000000000000000b0f271558b6ae0bb31389d4072bb11f3b9cda51e1357a).to_weight()
        Weight(76.53282616688836)
        >>> Hash(0x000000000000000000130c780000000000000000000000000000000000000000).to_weight()
        Weight(75.74837890381858)
        >>> Hash(0x00000000000404cb000000000000000000000000000000000000000000000000).to_weight()
        Weight(45.993263027575125)
        >>> Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000).to_weight()
        Weight(32.00002201394727)
        >>> Hash(0x00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff).to_weight()
        Weight(32.0)
        """
        # ALIAS: hash -> u256 -> weight
        return self.to_u256().to_weight()


class Target(int):
    def __new__(cls, value):
        if value > TARGET_MAX:
            raise ValueError(f'too big: 0x{value:0x}')
        if value < 0:
            raise ValueError('negative number not allowed')
        return int.__new__(cls, value)

    def __str__(self):
        return f'{self:08x}'

    def __repr__(self):
        return f'Target(0x{self:08x})'

    def to_u256(self) -> U256:
        """ Convert to U256

        Examples:

        >>> Target(0x170b0f27).to_u256()
        U256(0x0000000000000000000b0f270000000000000000000000000000000000000000)
        >>> Target(0x17130c78).to_u256()
        U256(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> Target(0x1b0404cb).to_u256()
        U256(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> Target(0x1cffff00).to_u256()
        U256(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> Target(0x1cffffff).to_u256()
        U256(0x00000000ffffff00000000000000000000000000000000000000000000000000)

        Extra:

        >>> Target(0x1d00ffff).to_u256()
        U256(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        """
        # PRIMITIVE: target -> u256
        high_bits = self >> 24
        low_bits = self & 0xffffff
        return U256(low_bits << (8 * (high_bits - 3)))

    def to_hash(self) -> Hash:
        """ Convert to Hash

        Examples:

        >>> Target(0x170b0f27).to_hash()
        Hash(0x0000000000000000000b0f270000000000000000000000000000000000000000)
        >>> Target(0x17130c78).to_hash()
        Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> Target(0x1b0404cb).to_hash()
        Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> Target(0x1cffff00).to_hash()
        Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> Target(0x1cffffff).to_hash()
        Hash(0x00000000ffffff00000000000000000000000000000000000000000000000000)
        """
        # ALIAS: target -> u256 -> hash
        return self.to_u256().to_hash()

    def to_bdiff(self) -> 'BDiff':
        """ Convert to BDiff

        Examples:

        >>> Target(0x170b0f27).to_bdiff()
        BDiff(25451295365779.504)
        >>> Target(0x17130c78).to_bdiff()
        BDiff(14776367535688.639)
        >>> Target(0x1b0404cb).to_bdiff()
        BDiff(16307.420938523983)
        >>> Target(0x1cffff00).to_bdiff()
        BDiff(1.0)
        >>> Target(0x1cffffff).to_bdiff()
        BDiff(0.9999848008146763)
        """
        # ALIAS: target -> u256 -> bdiff
        return self.to_u256().to_bdiff()

    def to_pdiff(self) -> 'PDiff':
        """ Convert to PDiff

        Examples:

        >>> Target(0x170b0f27).to_pdiff()
        PDiff(25451683727652.793)
        >>> Target(0x17130c78).to_pdiff()
        PDiff(14776593008604.42)
        >>> Target(0x1b0404cb).to_pdiff()
        PDiff(16307.669773817162)
        >>> Target(0x1cffff00).to_pdiff()
        PDiff(1.0000152590218967)
        >>> Target(0x1cffffff).to_pdiff()
        PDiff(1.0000000596046483)
        """
        # ALIAS: target -> u256 -> pdiff
        return self.to_u256().to_pdiff()

    def to_weight(self) -> 'Weight':
        """ Convert to Weight

        WARNING: this process is lossy:

        >>> Target(0x170b0f27).to_weight().to_target()
        Target(0x170b0f27)
        >>> Target(0x17130c78).to_weight().to_target()
        Target(0x17130c77)
        >>> Target(0x1b0404cb).to_weight().to_target()
        Target(0x1b0404cb)
        >>> Target(0x1cffff00).to_weight().to_target()
        Target(0x1cfffeff)
        >>> Target(0x1cffffff).to_weight().to_target()
        Target(0x1cfffffe)

        Examples:

        >>> Target(0x170b0f27).to_weight()
        Weight(76.53282633286952)
        >>> Target(0x17130c78).to_weight()
        Weight(75.74837890381858)
        >>> Target(0x1b0404cb).to_weight()
        Weight(45.993263027575125)
        >>> Target(0x1cffff00).to_weight()
        Weight(32.00002201394727)
        >>> Target(0x1cffffff).to_weight()
        Weight(32.00000008599133)
        """
        # ALIAS: target -> u256 -> weight
        return self.to_u256().to_weight()


class BDiff(float):
    def __repr__(self):
        return f'BDiff({float(self)})'

    def to_u256(self) -> U256:
        """ Convert to U256

        Examples:

        >>> BDiff(25451292437624.176).to_u256()
        U256(0x0000000000000000000b0f271558b6ae00000000000000000000000000000000)
        >>> BDiff(14776367535688.639).to_u256()
        U256(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> BDiff(16307.420938523983).to_u256()
        U256(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> BDiff(1.0).to_u256()
        U256(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> BDiff(0.9999847412109375).to_u256()
        U256(0x0000000100000000000000000000000000000000000000000000000000000000)
        """
        # PRIMITIVE: bdiff -> u256
        return U256(BDIFF_ONE / self)

    def to_hash(self) -> Hash:
        """ Convert to Hash

        Examples:

        >>> BDiff(25451292437624.176).to_hash()
        Hash(0x0000000000000000000b0f271558b6ae00000000000000000000000000000000)
        >>> BDiff(14776367535688.639).to_hash()
        Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> BDiff(16307.420938523983).to_hash()
        Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> BDiff(1.0).to_hash()
        Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> BDiff(0.9999847412109375).to_hash()
        Hash(0x0000000100000000000000000000000000000000000000000000000000000000)
        """
        # ALIAS: bdiff -> u256 -> hash
        return self.to_u256().to_hash()

    def to_target(self) -> Target:
        """ Convert to Target

        Examples:

        >>> BDiff(25451295365779.504).to_target()
        Target(0x170b0f27)
        >>> BDiff(14776367535688.639).to_target()
        Target(0x17130c78)
        >>> BDiff(16307.420938523983).to_target()
        Target(0x1b0404cb)
        >>> BDiff(1.0).to_target()
        Target(0x1cffff00)
        >>> BDiff(0.9999848008146763).to_target()
        Target(0x1cffffff)
        """
        # ALIAS: bdiff -> u256 -> target
        return self.to_u256().to_target()

    def to_pdiff(self) -> 'PDiff':
        """ Convert to PDiff

        Examples:

        >>> BDiff(25451292437624.176).to_pdiff()
        PDiff(25451680799452.777)
        >>> BDiff(14776367535688.639).to_pdiff()
        PDiff(14776593008604.42)
        >>> BDiff(16307.420938523983).to_pdiff()
        PDiff(16307.669773817162)
        >>> BDiff(1.0).to_pdiff()
        PDiff(1.0000152590218967)
        >>> BDiff(0.9999847412109375).to_pdiff()
        PDiff(1.0)
        """
        # ALIAS: bdiff -> u256 -> pdiff
        return self.to_u256().to_pdiff()

    def to_weight(self) -> 'Weight':
        """ Convert to Weight

        WARNING: this process is lossy:

        >>> BDiff(25451292437624.176).to_weight().to_bdiff()
        BDiff(25451292437624.027)
        >>> BDiff(14776367535688.639).to_weight().to_bdiff()
        BDiff(14776367535688.725)
        >>> BDiff(16307.420938523983).to_weight().to_bdiff()
        BDiff(16307.420938523897)
        >>> BDiff(1.0).to_weight().to_bdiff()
        BDiff(1.0000000000000064)
        >>> BDiff(0.9999847412109375).to_weight().to_bdiff()
        BDiff(0.9999847412109375)

        Examples:

        >>> BDiff(25451292437624.176).to_weight()
        Weight(76.53282616688836)
        >>> BDiff(14776367535688.639).to_weight()
        Weight(75.74837890381858)
        >>> BDiff(16307.420938523983).to_weight()
        Weight(45.993263027575125)
        >>> BDiff(1.0).to_weight()
        Weight(32.00002201394727)
        >>> BDiff(0.9999847412109375).to_weight()
        Weight(32.0)
        """
        # ALIAS: bdiff -> u256 -> weight
        return self.to_u256().to_weight()


class PDiff(float):
    def __repr__(self):
        return f'PDiff({float(self)})'

    def to_u256(self) -> U256:
        """ Convert to U256

        Examples:

        >>> PDiff(25451680799452.777).to_u256()
        U256(0x0000000000000000000b0f271558b6ae00000000000000000000000000000000)
        >>> PDiff(14776593008604.42).to_u256()
        U256(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> PDiff(16307.669773817162).to_u256()
        U256(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> PDiff(1.0000152590218967).to_u256()
        U256(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> PDiff(1.0).to_u256()
        U256(0x0000000100000000000000000000000000000000000000000000000000000000)
        """
        # PRIMITIVE: pdiff -> u256
        return U256(PDIFF_ONE / self)

    def to_hash(self) -> Hash:
        """ Convert to Hash

        Examples:

        >>> PDiff(25451680799452.777).to_hash()
        Hash(0x0000000000000000000b0f271558b6ae00000000000000000000000000000000)
        >>> PDiff(14776593008604.42).to_hash()
        Hash(0x000000000000000000130c780000000000000000000000000000000000000000)
        >>> PDiff(16307.669773817162).to_hash()
        Hash(0x00000000000404cb000000000000000000000000000000000000000000000000)
        >>> PDiff(1.0000152590218967).to_hash()
        Hash(0x00000000ffff0000000000000000000000000000000000000000000000000000)
        >>> PDiff(1.0).to_hash()
        Hash(0x0000000100000000000000000000000000000000000000000000000000000000)
        """
        # ALIAS: pdiff -> u256 -> hash
        return self.to_u256().to_hash()

    def to_target(self) -> Target:
        """ Convert to Target

        Examples:

        >>> PDiff(25451683727652.793).to_target()
        Target(0x170b0f27)
        >>> PDiff(14776593008604.42).to_target()
        Target(0x17130c78)
        >>> PDiff(16307.669773817162).to_target()
        Target(0x1b0404cb)
        >>> PDiff(1.0000152590218967).to_target()
        Target(0x1cffff00)
        >>> PDiff(1.0000000596046483).to_target()
        Target(0x1cffffff)
        """
        # ALIAS: pdiff -> u256 -> target
        return self.to_u256().to_target()

    def to_bdiff(self) -> 'BDiff':
        """ Convert to BDiff

        Examples:

        >>> PDiff(25451680799452.777).to_bdiff()
        BDiff(25451292437624.176)
        >>> PDiff(14776593008604.42).to_bdiff()
        BDiff(14776367535688.639)
        >>> PDiff(16307.669773817162).to_bdiff()
        BDiff(16307.420938523983)
        >>> PDiff(1.0000152590218967).to_bdiff()
        BDiff(1.0)
        >>> PDiff(1.0).to_bdiff()
        BDiff(0.9999847412109375)
        """
        # ALIAS: pdiff -> u256 -> bdiff
        return self.to_u256().to_bdiff()

    def to_weight(self) -> 'Weight':
        """ Convert to Weight

        WARNING: this process is lossy:

        >>> PDiff(25451680799452.777).to_weight().to_pdiff()
        PDiff(25451680799452.633)
        >>> PDiff(14776593008604.42).to_weight().to_pdiff()
        PDiff(14776593008604.506)
        >>> PDiff(16307.669773817162).to_weight().to_pdiff()
        PDiff(16307.669773817077)
        >>> PDiff(1.0000152590218967).to_weight().to_pdiff()
        PDiff(1.0000152590219031)
        >>> PDiff(1.0).to_weight().to_pdiff()
        PDiff(1.0)

        Examples:

        >>> PDiff(25451680799452.777).to_weight()
        Weight(76.53282616688836)
        >>> PDiff(14776593008604.42).to_weight()
        Weight(75.74837890381858)
        >>> PDiff(16307.669773817162).to_weight()
        Weight(45.993263027575125)
        >>> PDiff(1.0000152590218967).to_weight()
        Weight(32.00002201394727)
        >>> PDiff(1.0).to_weight()
        Weight(32.0)
        """
        # ALIAS: pdiff -> u256 -> weight
        return self.to_u256().to_weight()


class Weight(float):
    def __repr__(self):
        return f'Weight({float(self)})'

    def logsum(self, other: 'Weight') -> 'Weight':
        """ Make a "logarithmic sum" on base 2.

        That is `x.logsum(y)` is equivalent to `log2(2**x + 2**y)`, although there are some precision differences.

        Currently is just a proxy to `hathor.transaction.sum_weights`.
        """
        from hathor.transaction import sum_weights
        return Weight(sum_weights(self, other))

    def to_u256(self) -> U256:
        """ Convert to U256

        Examples:

        >>> Weight(76.53282616688836).to_u256()
        U256(0x0000000000000000000b0f271558b6c000000000000000000000000000000000)
        >>> Weight(75.74837890381858).to_u256()
        U256(0x000000000000000000130c77ffffffe100000000000000000000000000000000)
        >>> Weight(45.993263027575125).to_u256()
        U256(0x00000000000404cb000000060000000000000000000000000000000000000000)
        >>> Weight(32.00002201394727).to_u256()
        U256(0x00000000fffefffffffe38000000000000000000000000000000000000000000)
        >>> Weight(32.0).to_u256()
        U256(0x0000000100000000000000000000000000000000000000000000000000000000)
        """
        # PRIMITIVE: weight -> u256
        return U256(2**(256 - self) - 1)

    def to_hash(self) -> Hash:
        """ Convert to Hash

        Examples:

        >>> Weight(76.53282616688836).to_hash()
        Hash(0x0000000000000000000b0f271558b6c000000000000000000000000000000000)
        >>> Weight(75.74837890381858).to_hash()
        Hash(0x000000000000000000130c77ffffffe100000000000000000000000000000000)
        >>> Weight(45.993263027575125).to_hash()
        Hash(0x00000000000404cb000000060000000000000000000000000000000000000000)
        >>> Weight(32.00002201394727).to_hash()
        Hash(0x00000000fffefffffffe38000000000000000000000000000000000000000000)
        >>> Weight(32.0).to_hash()
        Hash(0x0000000100000000000000000000000000000000000000000000000000000000)
        """
        # ALIAS: weight -> u256 -> hash
        return self.to_u256().to_hash()

    def to_target(self) -> Target:
        """ Convert to Target

        Examples:

        >>> Weight(76.53282616688836).to_target()
        Target(0x170b0f27)
        >>> Weight(75.74837890381858).to_target()
        Target(0x17130c77)
        >>> Weight(45.993263027575125).to_target()
        Target(0x1b0404cb)
        >>> Weight(32.00002201394727).to_target()
        Target(0x1cfffeff)

        #>>> Weight(32.0).to_target()
        #Target(0x1d010000)
        """
        # ALIAS: weight -> u256 -> target
        return self.to_u256().to_target()

    def to_bdiff(self) -> BDiff:
        """ Convert to BDiff

        Examples:

        >>> Weight(76.53282616688836).to_bdiff()
        BDiff(25451292437624.027)
        >>> Weight(75.74837890381858).to_bdiff()
        BDiff(14776367535688.725)
        >>> Weight(45.993263027575125).to_bdiff()
        BDiff(16307.420938523897)
        >>> Weight(32.00002201394727).to_bdiff()
        BDiff(1.0000000000000064)
        >>> Weight(32.0).to_bdiff()
        BDiff(0.9999847412109375)
        """
        # ALIAS: weight -> u256 -> bdiff
        return self.to_u256().to_bdiff()

    def to_pdiff(self) -> PDiff:
        """ Convert to PDiff

        >>> Weight(76.53282616688836).to_pdiff()
        PDiff(25451680799452.633)
        >>> Weight(75.74837890381858).to_pdiff()
        PDiff(14776593008604.506)
        >>> Weight(45.993263027575125).to_pdiff()
        PDiff(16307.669773817077)
        >>> Weight(32.00002201394727).to_pdiff()
        PDiff(1.0000152590219031)
        >>> Weight(32.0).to_pdiff()
        PDiff(1.0)
        """
        # ALIAS: weight -> u256 -> pdiff
        return self.to_u256().to_pdiff()
