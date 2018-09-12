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


class InsuficientFunds(HathorWalletError):
    """Wallet does not have enough funds for the total outputs
    """


class OutOfUnusedAddresses(HathorWalletError):
    """Wallet does not have unused addresses and is locked (so it can't create new ones)
    """
