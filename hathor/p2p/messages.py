from enum import Enum
from typing import List, NamedTuple


class GetNextPayload(NamedTuple):
    timestamp: int
    offset: int = 0


class NextPayload(NamedTuple):
    timestamp: int
    next_timestamp: int
    next_offset: int
    hashes: List[bytes]


class GetTipsPayload(NamedTuple):
    timestamp: int
    include_hashes: bool
    offset: int = 0


class TipsPayload(NamedTuple):
    length: int
    timestamp: int
    prev_timestamp: int
    next_timestamp: int
    merkle_tree: str
    hashes: List[str]
    has_more: bool


class ProtocolMessages(Enum):
    # ---
    # General Error Messages
    # ---
    # Notifies an error.
    ERROR = 'ERROR'

    # Notifies a throttle.
    THROTTLE = 'THROTTLE'

    # ---
    # Peer-to-peer Control Messages
    # ---
    # Identifies the app and network the peer would like to connect to.
    HELLO = 'HELLO'

    # Identifies the peer.
    PEER_ID = 'PEER-ID'

    # Request a list of peers.
    GET_PEERS = 'GET-PEERS'

    # Usually it is a response to a GET-PEERS command. But it can be sent
    # without request when a new peer connects.
    PEERS = 'PEERS'

    # Ping is used to prevent an idle connection.
    PING = 'PING'

    # Pong is a response to a PING command.
    PONG = 'PONG'

    # ---
    # Hathor Specific Messages
    # ---
    NOTIFY_DATA = 'NOTIFY-DATA'  # Notify about a new piece of data.
    GET_DATA = 'GET-DATA'  # Request the data for a specific transaction.
    DATA = 'DATA'  # Send the data for a specific transaction.

    GET_TIPS = 'GET-TIPS'
    TIPS = 'TIPS'

    GET_NEXT = 'GET-NEXT'
    NEXT = 'NEXT'

    GET_BLOCKS = 'GET-BLOCKS'  # Request a list of hashes for blocks. Payload is the current latest block.
    BLOCKS = 'BLOCKS'  # Send a list of hashes for blocks. Payload is a list of hashes.

    GET_TRANSACTIONS = 'GET-TRANSACTIONS'  # Request a list of hashes for transactions.
    TRANSACTIONS = 'TRANSACTIONS'  # Send a list of hashes for transactions.

    HASHES = 'HASHES'
