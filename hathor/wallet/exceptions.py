from hathor.exception import HathorError


class WalletOutOfSync(HathorError):
    """Some input has already been spent"""
