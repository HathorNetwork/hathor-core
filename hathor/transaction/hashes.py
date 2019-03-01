from abc import ABC, abstractmethod
from hashlib import sha256
from typing import Optional

try:
    from hashlib import scrypt
except ImportError:
    import scrypt as _scrypt
    from typing import Union

    _DataType = Union[bytes, bytearray, memoryview]

    def scrypt(password: _DataType, *, salt: _DataType, n: int, r: int, p: int, maxmem: int = 0,
               dklen: int = 64) -> bytes:
        return _scrypt.hash(password, salt=salt, N=n, r=r, p=p, buflen=dklen)


class BaseHashAlgorithm(ABC):
    """ Base class for implementation of hash algorithms.
    """
    name: str

    @abstractmethod
    def __init__(self, data: Optional[bytes] = None):
        """ Initialize the hash using the data.
        """
        pass

    @abstractmethod
    def update(self, data: bytes) -> None:
        """ Update the hash with data.
        """
        pass

    @abstractmethod
    def digest(self) -> bytes:
        """ Return the digest value as bytes.
        """
        pass

    @abstractmethod
    def hexdigest(self) -> str:
        """ Return the dugest value as string of hexadecimal digits.
        """
        pass

    @abstractmethod
    def copy(self) -> 'BaseHashAlgorithm':
        """ Return a copy of the hash object.
        """
        pass


class SHA256dHash(BaseHashAlgorithm):
    name = 'sha256d'

    def __init__(self, data: Optional[bytes] = None, *, _is_copy: bool = False):
        if not _is_copy:
            self.hash = sha256()
            if data:
                if not isinstance(data, bytes):
                    raise TypeError('Unicode-objects must be encoded before hashing')
                self.hash.update(data)

    def update(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError('Unicode-objects must be encoded before hashing')
        self.hash.update(data)

    def digest(self) -> bytes:
        # SHA256D gets the hash in little-endian format. Reverse the bytes to get the big-endian representation.
        return sha256(self.hash.digest()).digest()[::-1]

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> BaseHashAlgorithm:
        h = SHA256dHash(_is_copy=True)
        h.hash = self.hash.copy()
        return h


class ScryptHash(BaseHashAlgorithm):
    name = 'scrypt'

    def __init__(self, data: Optional[bytes] = None):
        if not data:
            self.data = b''
        else:
            if not isinstance(data, bytes):
                raise TypeError('Unicode-objects must be encoded before hashing')
            self.data = data

    def update(self, data: bytes) -> None:
        if not isinstance(data, bytes):
            raise TypeError('Unicode-objects must be encoded before hashing')
        self.data += data

    def digest(self) -> bytes:
        return scrypt(self.data, salt=self.data, n=1024, r=1, p=1, dklen=32)

    def hexdigest(self) -> str:
        return self.digest().hex()

    def copy(self) -> BaseHashAlgorithm:
        return ScryptHash(self.data)
