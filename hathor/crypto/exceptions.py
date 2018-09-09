from hathor.exception import HathorError


class InputSignatureError(HathorError):
    """Incorrect input signature"""


class InputPublicKeyError(HathorError):
    """Public key does not match address"""
