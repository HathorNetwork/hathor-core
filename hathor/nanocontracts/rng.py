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

from typing import Any, Sequence, TypeVar

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from hathor.difficulty import Hash

T = TypeVar('T')


class NoMethodOverrideMeta(type):
    __slots__ = ()

    def __setattr__(cls, name: str, value: Any) -> None:
        raise AttributeError(f'Cannot override method `{name}`')


class NanoRNG(metaclass=NoMethodOverrideMeta):
    """Implement a deterministic random number generator that will be used by the sorter.

    This implementation uses the ChaCha20 encryption as RNG.
    """

    __slots__ = ('__seed', '__encryptor', '__frozen')

    def __init__(self, seed: bytes) -> None:
        self.__seed = Hash(seed)

        key = self.__seed
        nonce = self.__seed[:16]

        algorithm = algorithms.ChaCha20(key, nonce)
        cipher = Cipher(algorithm, mode=None)
        self.__encryptor = cipher.encryptor()

        self.__frozen = True

    @classmethod
    def create_with_shell(cls, seed: bytes) -> NanoRNG:
        """Create a NanoRNG instance wrapped in a lightweight shell subclass.

        This method dynamically creates a subclass of NanoRNG (a "shell" class) and instantiates it. The shell class is
        useful to prevent sharing classes and objects among different contracts.
        """
        class ShellNanoRNG(NanoRNG):
            __slots__ = ()

        return ShellNanoRNG(seed=seed)

    def __setattr__(self, name: str, value: Any) -> None:
        if getattr(self, '_NanoRNG__frozen', False):
            raise AttributeError("Cannot assign methods to this object.")
        super().__setattr__(name, value)

    @property
    def seed(self) -> Hash:
        """Return the seed used to create the RNG."""
        return self.__seed

    def randbytes(self, size: int) -> bytes:
        """Return a random string of bytes."""
        assert size >= 1
        ciphertext = self.__encryptor.update(b'\0' * size)
        assert len(ciphertext) == size
        return ciphertext

    def randbits(self, bits: int) -> int:
        """Return a random integer in the range [0, 2**bits)."""
        assert bits >= 1
        size = (bits + 7) // 8
        ciphertext = self.randbytes(size)
        x = int.from_bytes(ciphertext, byteorder='little', signed=False)
        return x % (2**bits)

    def randbelow(self, n: int) -> int:
        """Return a random integer in the range [0, n)."""
        assert n >= 1
        k = n.bit_length()
        r = self.randbits(k)  # 0 <= r < 2**k
        while r >= n:
            r = self.randbits(k)
        return r

    def randrange(self, start: int, stop: int, step: int = 1) -> int:
        """Return a random integer in the range [start, stop) with a given step.

        Roughly equivalent to `choice(range(start, stop, step))` but supports arbitrarily large ranges."""
        assert stop > start
        assert step >= 1
        qty = (stop - start + step - 1) // step
        k = self.randbelow(qty)
        return start + k * step

    def randint(self, a: int, b: int) -> int:
        """Return a random integer in the range [a, b]."""
        assert b >= a
        return a + self.randbelow(b - a + 1)

    def choice(self, seq: Sequence[T]) -> T:
        """Choose a random element from a non-empty sequence."""
        return seq[self.randbelow(len(seq))]

    def random(self) -> float:
        """Return a random float in the range [0, 1)."""
        # 2**53 is the maximum integer float can represent without loss of precision.
        return self.randbits(53) / 2**53
