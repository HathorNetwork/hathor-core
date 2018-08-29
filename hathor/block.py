# Hathor blockchain.

import datetime
import hashlib
import json
import sys


_TEST = True
_TEST_DIFFICULTY = 4

_MAX_INT = sys.maxsize


class HashUtil:
    @staticmethod
    def hash_is_below_difficulty(hash_str, difficulty):
        """Verify that the hash string (hexdigest) is below the desired difficulty"""
        return hash_str[:difficulty] == '0' * difficulty


class Blockchain:
    """The Hathor Blockchain."""
    def __init__(self):
        self.blocks = []
        self.create_block(block_id=0, proof=42, prev_hash='0')

    def create_block(self, nonce, parent_hash):
        """Create a new block and add to the chain."""
        block = Block(block_id=self.get_last_block().block_id + 1,
                      nonce=nonce,
                      parent_hash=parent_hash)
        self.blocks.append(block)

    def get_last_block(self):
        """Return the final Block in the chain."""
        return self.blocks[-1]

    def compute_difficulty(self):
        """Compute a difficulty value.

        Currenty returns the # of leading 0s.
        TODO: make a regular int?
        """
        if _TEST:
            return _TEST_DIFFICULTY
        else:
            return None # TODO

    def mine_block(self, block, prev_nonce):
        """Trivial CPU mining for testing. Gives up at _MAX_INT; only works with low difficulty."""
        for nonce in range(_MAX_INT):
            block.nonce = nonce
            hash_str = block.calculate_hash()
            difficulty = self.compute_difficulty()
            if HashUtil.hash_is_below_difficulty(hash_str, difficulty):
                return nonce

        return None

    def is_valid(self):
        """Verify blockchain is valid."""
        return self.is_block_list_valid(self.blocks)

    def is_block_list_valid(self, blocks):
        """Verify subchain is valid."""
        prev_block = blocks[0]
        for idx, block in enumerate(blocks):
            if block.parent_hash != prev_block.calculate_hash():
                return False
            hash_str = block.calculate_hash()
            difficulty = self.compute_difficulty()
            if not HashUtil.hash_is_below_difficulty(hash_str, difficulty):
                return False
            prev_block = block
        return True


class Block:
    """A Hathor Block."""
    def __init__(self, block_id, nonce, parent_hash):
        self.version = 1
        self.nonce = 0
        self.block_id = block_id
        self.timestamp = int(datetime.datetime.now().timestamp())
        self.transactions = []
        self.parent_hash = parent_hash
        self.hash = None

    def calculate_hash(self):
        json_block = json.dumps(self, sort_keys=True).encode()
        return hashlib.sha256(hashlib.sha256(json_block)).hexdigest()