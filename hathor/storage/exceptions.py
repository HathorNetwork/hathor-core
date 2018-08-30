from hathor.exception import HathorError


class TransactionDoesNotExist(HathorError):
    """You are trying to get a transaction that does not exist"""


class TransactionMetadataDoesNotExist(HathorError):
    """You are trying to get a metadata (of a transaction) that does not exist"""
