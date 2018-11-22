import os
import json
import hashlib

from twisted.logger import Logger

from hathor.wallet.keypair import KeyPair
from hathor.wallet.exceptions import OutOfUnusedAddresses
from hathor.wallet import BaseWallet
from hathor.pubsub import HathorEvents
from hathor.crypto.util import get_public_key_bytes_compressed, get_private_key_from_bytes

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes


class Wallet(BaseWallet):
    log = Logger()

    def __init__(self, keys=None, directory='./', filename='keys.json', history_file='history.json',
                 pubsub=None, reactor=None):
        """ A wallet will hold key pair objects and the unspent and
        spent transactions associated with the keys.

        All files will be stored in the same directory, and it should
        only contain wallet associated files.

        :param keys: keys to initialize this wallet
        :type keys: Dict[string(base58), :py:class:`hathor.wallet.keypair.KeyPair`]

        :param directory: where to store wallet associated files
        :type directory: string

        :param filename: name of keys file
        :type filename: string

        :param history_file: name of history file
        :type history_file: string

        :param pubsub: If not given, a new one is created.
        :type pubsub: :py:class:`hathor.pubsub.PubSubManager`
        """
        super().__init__(
            directory=directory,
            history_file=history_file,
            pubsub=pubsub,
        )

        self.filepath = os.path.join(directory, filename)
        self.keys = keys or {}  # Dict[string(b58_address), KeyPair]

        # Set[string(base58)]
        self.unused_keys = set(key.address for key in self.keys.values() if not key.used)

        self.password = None

        # Used in admin frontend to know which wallet is being used
        self.type = self.WalletType.KEY_PAIR

        # :py:class:`twisted.internet.Reactor`
        if reactor is None:
            from twisted.internet import reactor
        self.reactor = reactor

        # int(seconds)
        # 0=flush every change
        self.flush_to_disk_interval = 0
        self.last_flush_time = 0
        self.flush_schedule = None

    def _manually_initialize(self):
        if os.path.isfile(self.filepath):
            self.log.info('Loading keys...')
            self.read_keys_from_file()

    def read_keys_from_file(self):
        """Reads the keys from file and updates the keys dictionary

        Uses the directory and filename specified in __init__

        :rtype: None
        """
        new_keys = {}
        with open(self.filepath, 'r') as json_file:
            json_data = json.loads(json_file.read())
            for data in json_data:
                keypair = KeyPair.from_json(data)
                new_keys[keypair.address] = keypair
                if not keypair.used:
                    self.unused_keys.add(keypair.address)

        self.keys.update(new_keys)

    def _write_keys_to_file_or_delay(self):
        dt = self.reactor.seconds() - self.last_flush_time
        if dt > self.flush_to_disk_interval:
            self._write_keys_to_file()
        else:
            if self.flush_schedule is None:
                remaining = self.flush_to_disk_interval - dt
                self.log.info('Wallet: Flush delayed {} seconds...'.format(remaining))
                assert remaining > 0
                self.flush_schedule = self.reactor.callLater(remaining, self._write_keys_to_file)

    def _write_keys_to_file(self):
        self.flush_schedule = None
        self.last_flush_time = self.reactor.seconds()
        data = [keypair.to_json() for keypair in self.keys.values()]
        with open(self.filepath, 'w') as json_file:
            json_file.write(json.dumps(data, indent=4))
        self.log.info('Wallet: Keys successfully written to disk.')

    def unlock(self, password):
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

    def lock(self):
        self.password = None
        for keypair in self.keys.values():
            keypair.clear_cache()

    def get_unused_address(self, mark_as_used=True):
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

    def generate_keys(self, count=20):
        for _ in range(count):
            key = KeyPair.create(self.password)
            self.keys[key.address] = key
            self.unused_keys.add(key.address)

        # Publish to pubsub that new keys were generated
        self.publish_update(HathorEvents.WALLET_KEYS_GENERATED, keys_count=count)

    def get_private_key(self, address58):
        return self.keys[address58].private_key_bytes

    def tokens_received(self, address58):
        self.keys[address58].used = True
        self.unused_keys.discard(address58)

    def is_locked(self):
        return self.password is None

    def get_input_aux_data(self, data_to_sign, private_key):
        key = get_private_key_from_bytes(private_key, self.password)
        public_key_bytes = get_public_key_bytes_compressed(key.public_key())
        hashed_data = hashlib.sha256(data_to_sign).digest()
        signature = key.sign(hashed_data, ec.ECDSA(hashes.SHA256()))
        return public_key_bytes, signature
