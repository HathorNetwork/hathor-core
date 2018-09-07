from hathor.exception import HathorError


class WalletOutOfSync(HathorError):
    """Error when wallet performs illegal operation
    because it's state is not synced with latest txs.
    """
