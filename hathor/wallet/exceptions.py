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

from hathor.exception import HathorError


class HathorWalletError(HathorError):
    """Base class for wallet exceptions in Hathor.
    """
    pass


class WalletOutOfSync(HathorWalletError):
    """Error when wallet performs illegal operation because it's state is not synced with latest txs.
    """


class PrivateKeyNotFound(HathorWalletError):
    """Wallet is asked to sign a transaction spending outputs for which it does not hold the private key
    """


class WalletLocked(HathorWalletError):
    """Some of the wallet operations require the user's password
    """


class IncorrectPassword(HathorWalletError):
    """User supplied the wrong password to the wallet
    """


class InsufficientFunds(HathorWalletError):
    """Wallet does not have enough funds for the total outputs
    """


class OutOfUnusedAddresses(HathorWalletError):
    """Wallet does not have unused addresses and is locked (so it can't create new ones)
    """


class InvalidWords(HathorWalletError):
    """HD Wallet was initialized with invalid set of words
    """


class InputDuplicated(HathorWalletError):
    """User is trying to use same input more than one time
    """


class InvalidAddress(HathorWalletError):
    """Address used in the wallet is invalid
    """
