from hathor.exception import HathorError


class InvalidBlockHashesSequence(HathorError):
    """Sequence of hashes are inconsistent.

    When a sequence of hashes is received, we may know only part of the hashes.
    But, after a hash is unknown, all hashes must be unknown as well.
    """
