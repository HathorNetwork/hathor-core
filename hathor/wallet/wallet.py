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

import hashlib
import json
import os
from typing import Any, Optional

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
from twisted.internet.interfaces import IDelayedCall

from hathor.crypto.util import get_public_key_bytes_compressed
from hathor.pubsub import HathorEvents
from hathor.wallet import BaseWallet
from hathor.wallet.exceptions import OutOfUnusedAddresses
from hathor.wallet.keypair import KeyPair


class Wallet(BaseWallet):
    def __init__(self, keys: Optional[Any] = None, directory: str = './', filename: str = 'keys.json',
                 pubsub: Optional[Any] = None, reactor: Optional[Any] = None) -> None:
        """ A wallet will hold key pair objects and the unspent and
        spent transactions associated with the keys.

        All files will be stored in the same directory, and it should
        only contain wallet associated files.

        :param keys: keys to initialize this wallet
        :type keys: dict[string(base58), :py:class:`hathor.wallet.keypair.KeyPair`]

        :param directory: where to store wallet associated files
        :type directory: string

        :param filename: name of keys file
        :type filename: string

        :param pubsub: If not given, a new one is created.
        :type pubsub: :py:class:`hathor.pubsub.PubSubManager`
        """
        super().__init__(directory=directory, pubsub=pubsub, reactor=reactor)

        self.filepath = os.path.join(directory, filename)
        self.keys: dict[str, Any] = keys or {}  # dict[string(b58_address), KeyPair]

        # set[string(base58)]
        self.unused_keys = set(key.address for key in self.keys.values() if not key.used)

        self.password: Optional[bytes] = None

        # Used in admin frontend to know which wallet is being used
        self.type = self.WalletType.KEY_PAIR

        # int(seconds)
        # 0=flush every change
        self.flush_to_disk_interval = 0
        self.last_flush_time = 0
        self.flush_schedule: Optional[IDelayedCall] = None

    def _manually_initialize(self) -> None:
        if os.path.isfile(self.filepath):
            self.log.info('load keys')
            self.read_keys_from_file()

    def read_keys_from_file(self):
        """Reads the keys from file and updates the keys dictionary

        Uses the directory and filename specified in __init__

        :rtype: None
        """
        new_keys = {}
        with open(self.filepath, 'r') as json_file:
            json_data = json.load(json_file)
            for data in json_data:
                keypair = KeyPair.from_json(data)
                assert keypair.address is not None
                new_keys[keypair.address] = keypair
                if not keypair.used:
                    self.unused_keys.add(keypair.address)

        self.keys.update(new_keys)

    def _write_keys_to_file_or_delay(self) -> None:
        dt = self.reactor.seconds() - self.last_flush_time
        if dt > self.flush_to_disk_interval:
            self._write_keys_to_file()
        else:
            if self.flush_schedule is None:
                remaining = self.flush_to_disk_interval - dt
                self.log.info('flush delayed', remaining_secs=remaining)
                assert remaining >= 0
                self.flush_schedule = self.reactor.callLater(remaining, self._write_keys_to_file)

    def _write_keys_to_file(self) -> None:
        self.flush_schedule = None
        self.last_flush_time = int(self.reactor.seconds())
        data = [keypair.to_json() for keypair in self.keys.values()]
        with open(self.filepath, 'w') as json_file:
            json.dump(data, json_file)
        self.log.info('keys successfully written to disk')

    def unlock(self, password: bytes) -> None:
        """ Validates if the password is valid
            Then saves the password as bytes.

            :type password: bytes

            :raises IncorrectPassword: when the password is incorrect

            :raises ValueError: when the password parameter is not bytes
        """
        # Get one keypair
        # XXX What if we don't have any keypair in the wallet?
        if isinstance(password, bytes):
            keypair_values = list(self.keys.values())
            if keypair_values:
                keypair = keypair_values[0]

                # Test if the password is correct
                # If not correct IncorrectPassword exception is raised
                keypair.get_private_key(password)

            self.password = password
        else:
            raise ValueError('Password must be in bytes')

    def lock(self) -> None:
        """ Lock wallet and clear all caches.
        """
        self.password = None
        for keypair in self.keys.values():
            keypair.clear_cache()

    def get_unused_address(self, mark_as_used: bool = True) -> str:
        """
        :raises OutOfUnusedAddresses: When there is no unused address left
            to be returned and wallet is locked
        """
        updated = False
        if len(self.unused_keys) == 0:
            if not self.password:
                raise OutOfUnusedAddresses
            else:
                self.generate_keys()
                updated = True

        address = next(iter(self.unused_keys))
        if mark_as_used:
            self.unused_keys.discard(address)
            keypair = self.keys[address]
            keypair.used = True
            updated = True

        if updated:
            self._write_keys_to_file_or_delay()

        return address

    def generate_keys(self, count: int = 20) -> None:
        for _ in range(count):
            key = KeyPair.create(self.password)
            assert key.address is not None
            self.keys[key.address] = key
            self.unused_keys.add(key.address)

        # Publish to pubsub that new keys were generated
        self.publish_update(HathorEvents.WALLET_KEYS_GENERATED, keys_count=count)

    def get_private_key(self, address58: str) -> EllipticCurvePrivateKey:
        """ Get private key from the address58

            :param address58: address in base58
            :type address58: string

            :return: Private key object.
            :rtype: :py:class:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
        """
        return self.keys[address58].get_private_key(self.password)

    def tokens_received(self, address58: str) -> None:
        """ Method called when the wallet receive new tokens

            We set the address as used and remove it from the unused_keys

            :param address58: address that received the token in base58
            :type address58: string
        """
        self.keys[address58].used = True
        self.unused_keys.discard(address58)

    def is_locked(self):
        return self.password is None

    def get_input_aux_data(self, data_to_sign: bytes, private_key: EllipticCurvePrivateKey) -> tuple[bytes, bytes]:
        """ Sign the data to be used in input and get public key compressed in bytes

            :param data_to_sign: Data to be signed
            :type data_to_sign: bytes

            :param private_key: private key to sign data
            :type private_key: pycoin.key.Key.Key

            :return: public key compressed in bytes and signature
            :rtype: tuple[bytes, bytes]
        """
        public_key_bytes = get_public_key_bytes_compressed(private_key.public_key())
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = private_key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
        return public_key_bytes, signature
