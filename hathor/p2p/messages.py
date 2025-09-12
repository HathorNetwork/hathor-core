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

from enum import Enum
from typing import NamedTuple


class GetNextPayload(NamedTuple):
    timestamp: int
    offset: int = 0


class NextPayload(NamedTuple):
    timestamp: int
    next_timestamp: int
    next_offset: int
    hashes: list[bytes]


class GetTipsPayload(NamedTuple):
    timestamp: int
    include_hashes: bool
    offset: int = 0


class TipsPayload(NamedTuple):
    length: int
    timestamp: int
    merkle_tree: bytes
    hashes: list[str]
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

    # Tell the other peer your peer-id validations were completed and you are ready
    READY = 'READY'

    # Request a list of peers.
    GET_PEERS = 'GET-PEERS'

    # Usually it is a response to a GET-PEERS command. But it can be sent
    # without request when a new peer connects.
    PEERS = 'PEERS'

    # Ping is used to prevent an idle connection.
    PING = 'PING'

    # Pong is a response to a PING command.
    PONG = 'PONG'

    # Request a list of blocks from the best blockchain
    GET_BEST_BLOCKCHAIN = 'GET-BEST-BLOCKCHAIN'

    # Send back the blockchain requested
    BEST_BLOCKCHAIN = 'BEST-BLOCKCHAIN'

    # ---
    # Hathor Specific Messages
    # ---
    GET_DATA = 'GET-DATA'  # Request the data for a specific transaction.
    DATA = 'DATA'  # Send the data for a specific transaction.
    NOT_FOUND = 'NOT-FOUND'  # Used when a requested tx from GET-DATA is not found in the peer

    GET_TIPS = 'GET-TIPS'
    TIPS = 'TIPS'
    TIPS_END = 'TIPS-END'

    RELAY = 'RELAY'

    GET_NEXT = 'GET-NEXT'
    NEXT = 'NEXT'

    # Sync-v2 messages

    GET_NEXT_BLOCKS = 'GET-NEXT-BLOCKS'
    GET_PREV_BLOCKS = 'GET-PREV-BLOCKS'
    BLOCKS = 'BLOCKS'
    BLOCKS_END = 'BLOCKS-END'

    GET_BEST_BLOCK = 'GET-BEST-BLOCK'  # Request the best block of the peer
    BEST_BLOCK = 'BEST-BLOCK'  # Send the best block to your peer

    GET_TRANSACTIONS_BFS = 'GET-TRANSACTIONS-BFS'
    TRANSACTION = 'TRANSACTION'
    TRANSACTIONS_END = 'TRANSACTIONS-END'

    GET_MEMPOOL = 'GET-MEMPOOL'
    MEMPOOL_END = 'MEMPOOL-END'

    GET_PEER_BLOCK_HASHES = 'GET-PEER-BLOCK-HASHES'
    PEER_BLOCK_HASHES = 'PEER-BLOCK-HASHES'

    STOP_BLOCK_STREAMING = 'STOP-BLOCK-STREAMING'
    STOP_TRANSACTIONS_STREAMING = 'STOP-TRANSACTIONS-STREAMING'

    # Nano-state commands

    GET_BLOCK_NC_ROOT_ID = 'GET-BLOCK-NC-ROOT-ID'
    BLOCK_NC_ROOT_ID = 'BLOCK-NC-ROOT-ID'
    GET_NC_DB_NODE = 'GET-NC-DB-NODE'
    NC_DB_NODE = 'NC-DB-NODE'
