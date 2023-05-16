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
from typing import TYPE_CHECKING, Any, Dict, Optional, Tuple

from mnemonic import Mnemonic

from hathor.pubsub import HathorEvents
from hathor.wallet import BaseWallet
from hathor.wallet.exceptions import InvalidWords

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey
    from pycoin.key.Key import Key

# TODO pycoin BIP32 uses their own ecdsa library to generate key that does not use OpenSSL
# We must check if this brings any security problem to us later

WORD_COUNT_CHOICES = [12, 15, 18, 21, 24]


_registered_pycoin = False


def _register_pycoin_networks() -> None:
    """ Register HTR (mainnet) and XHTR (testnet) in pycoin networks
    """
    import os

    global _registered_pycoin
    if _registered_pycoin:
        return
    _registered_pycoin = True

    paths = os.environ.get('PYCOIN_NETWORK_PATHS', '').split()
    if 'hathor.pycoin' not in paths:
        paths.append('hathor.pycoin')
    os.environ['PYCOIN_NETWORK_PATHS'] = ' '.join(paths)


class HDWallet(BaseWallet):
    """ Hierarchical Deterministic Wallet based on BIP32.

    See: https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki
    """

    def __init__(self, *, words: Optional[Any] = None, language: str = 'english', passphrase: bytes = b'',
                 gap_limit: int = 20, word_count: int = 24, directory: str = './', pubsub: Optional[Any] = None,
                 reactor: Optional[Any] = None, initial_key_generation: Optional[Any] = None) -> None:
        """
        :param words: words to generate the seed. It's a string with the words separated by a single space.
        If None we generate new words when starting the wallet
        :type words: string

        :param language: language of the words
        :type language: string

        :param passphrase: one more security level to generate the seed
        :type passphrase: bytes

        :param gap_limit: maximum of unused addresses in sequence
        (default value based in https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#address-gap-limit)
        :type gap_limit: int

        :param word_count: quantity of words that are gonna generate the seed
        Possible choices are [12, 15, 18, 21, 24]
        :type word_count: int

        :param initial_key_generation: number of keys that will be generated in the initialization
        If not set we make it equal to gap_limit
        :type initial_key_generation: int

        :raises ValueError: Raised on invalid word_count
        """
        super().__init__(directory=directory, pubsub=pubsub, reactor=reactor)

        # Dict[string(base58), BIP32Key]
        self.keys: Dict[str, Any] = {}

        # Last index that the address was shared
        # We use this index to know which address should be shared with the user
        # This index together with last_generated_index show us if the gap limit was achieved
        self.last_shared_index = 0

        # Last index that the address was generated
        self.last_generated_index = 0

        # Maximum gap between indexes of last generated address and last used address
        self.gap_limit = gap_limit

        # XXX Should we  save this data in the object?
        self.language = language
        self.words = words
        self.passphrase = passphrase
        self.mnemonic = None

        # Used in admin frontend to know which wallet is being used
        self.type = self.WalletType.HD

        # Validating word count
        if word_count not in WORD_COUNT_CHOICES:
            raise ValueError('Word count ({}) is not one of the options {}.'.format(word_count, WORD_COUNT_CHOICES))
        self.word_count = word_count

        # Number of keys that will be generated in the initialization
        self.initial_key_generation = initial_key_generation or gap_limit

    def _manually_initialize(self):
        """ Create words (if is None) and start seed and master node
            Then we generate the first addresses, so we can check if we already have transactions
        """
        self.mnemonic = Mnemonic(self.language)

        if not self.words:
            # Initialized but still locked
            return

        # Validate words first
        self.validate_words()

        assert isinstance(self.passphrase, bytes), 'Passphrase must be in bytes'

        # Master seed
        seed = self.mnemonic.to_seed(self.words, self.passphrase.decode('utf-8'))

        # Master node
        from pycoin.networks.registry import network_for_netcode
        _register_pycoin_networks()
        network = network_for_netcode('htr')
        key = network.keys.bip32_seed(seed)

        # Until account key should be hardened
        # Chain path = 44'/0'/0'/0
        # 44' (hardened) -> BIP44
        # 280' (hardened) -> Coin type (280 = hathor)
        # 0' (hardened) -> Account
        # 0 -> Chain
        self.chain_key = key.subkey_for_path('44H/280H/0H/0')

        for key in self.chain_key.children(self.initial_key_generation, 0, False):
            self._key_generated(key, key.child_index())

    def get_private_key(self, address58: str) -> 'EllipticCurvePrivateKey':
        """ We get the private key bytes and generate the cryptography object

            :param address58: address in base58
            :type address58: string

            :return: Private key object.
            :rtype: :py:class:`cryptography.hazmat.primitives.asymmetric.ec.EllipticCurvePrivateKey`
        """
        return self.keys[address58]

    def generate_new_key(self, index):
        """ Generate a new key in the tree at defined index
            We add this new key to self.keys and set last_generated_index

            :param index: index to generate the key
            :type index: int
        """
        new_key = self.chain_key.subkey(index)
        self._key_generated(new_key, index)

    def _key_generated(self, key, index):
        """ Add generated key to self.keys and set last_generated_index

            :param key: generated key of hd wallet
            :type key: pycoin.key.Key.Key

            :param index: index to generate the key
            :type index: int
        """
        self.keys[self.get_address(key)] = key
        self.last_generated_index = index

    def get_address(self, new_key):
        return new_key.address()

    def get_key_at_index(self, index):
        """ Return the key generated by the index in the parameter

            :param index: index to return the key
            :type index: int
        """
        return self.chain_key.subkey(index)

    def tokens_received(self, address58: str) -> None:
        """ Method called when the wallet receive new tokens

            If the gap limit is not yet achieved we generate more keys

            :param address58: address that received the token in base58
            :type address58: string
        """
        received_key = self.keys[address58]

        # If the gap now is less than the limit, we generate the new keys until the limit
        # Because we might be in sync phase, so we need those keys pre generated
        diff = self.last_generated_index - received_key.child_index()
        if (self.gap_limit - diff) > 0:
            for _ in range(self.gap_limit - diff):
                self.generate_new_key(self.last_generated_index + 1)

        # Last shared index should be at least the index after the received one
        self.last_shared_index = max(self.last_shared_index, received_key.child_index() + 1)

    def get_unused_address(self, mark_as_used: bool = True) -> str:
        """ Return an address that is not used yet

            :param mark_as_used: if True we consider that this address is already used
            :type mark_as_used: bool

            :return: unused address in base58
            :rtype: string
        """
        if self.last_shared_index != self.last_generated_index:
            # Only in case we are not yet in the gap limit
            if mark_as_used:
                self.last_shared_index += 1
        else:
            if mark_as_used:
                self.publish_update(HathorEvents.WALLET_GAP_LIMIT, limit=self.gap_limit)

        key = self.get_key_at_index(self.last_shared_index)
        return self.get_address(key)

    def is_locked(self) -> bool:
        """ Return if wallet is currently locked
            The wallet is locked if self.words is None

            :return: if wallet is locked
            :rtype: bool
        """
        return self.words is None

    def lock(self):
        """ Lock the wallet
            Set all parameters to default values
        """
        self.words = None
        self.keys = {}
        self.passphrase = b''
        self.language = ''
        self.unspent_txs = {}
        self.spent_txs = []
        self.balance = 0
        self.last_shared_index = 0
        self.last_generated_index = 0

    def unlock(self, tx_storage, words=None, passphrase=b'', language='english'):
        """ Unlock the wallet
            Set all parameters to initialize the wallet and load the txs

            :param tx_storage: storage from where I should load the txs
            :type tx_storage: :py:class:`hathor.transaction.storage.transaction_storage.TransactionStorage`

            :param words: words to generate the seed. It's a string with the words separated by a single space.
            If None we generate new words when starting the wallet
            :type words: string

            :param language: language of the words
            :type language: string

            :param passphrase: one more security level to generate the seed
            :type passphrase: bytes

            :return: hd wallet words. Generated in this method or passed as parameter
            :rtype: string
        """
        self.language = language
        if not words:
            # Decide to choose words automatically
            # Can be a different language than self.mnemonic
            m = Mnemonic(self.language)
            # We can't pass the word_count to generate method, only the strength
            # Multiplying by 10.67 gives the result we expect
            words = m.generate(strength=int(self.word_count * 10.67))
        self.words = words
        self.passphrase = passphrase
        self._manually_initialize()
        self.load_txs(tx_storage)
        return words

    def load_txs(self, tx_storage):
        """ Load all saved txs to fill the wallet txs

            :param tx_storage: storage from where I should load the txs
            :type tx_storage: :py:class:`hathor.transaction.storage.transaction_storage.TransactionStorage`
        """
        for tx in tx_storage._topological_sort_dfs():
            self.on_new_tx(tx)

    def validate_words(self):
        """ Validate if set of words is valid
            If words is None or is not valid we raise error

            :raises InvalidWords: when the words are invalid
        """
        if not self.words or not self.mnemonic.check(self.words):
            raise InvalidWords

    def get_input_aux_data(self, data_to_sign: bytes, private_key: 'Key') -> Tuple[bytes, bytes]:
        """ Sign the data to be used in input and get public key compressed in bytes

            :param data_to_sign: Data to be signed
            :type data_to_sign: bytes

            :param private_key: private key to sign data
            :type private_key: pycoin.key.Key.Key

            :return: public key compressed in bytes and signature
            :rtype: tuple[bytes, bytes]
        """
        prehashed_msg = hashlib.sha256(hashlib.sha256(data_to_sign).digest()).digest()
        signature = private_key.sign(prehashed_msg)
        return private_key.sec(), signature
