class HathorError(Exception):
    """Base class for exceptions in Hathor."""
    pass


class InvalidNewTransaction(HathorError):
    """Raised when a new received tx/block is not valid.
    """
    pass
