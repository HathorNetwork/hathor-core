# Copyright 2019 Hathor Labs
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

"""
Module for abstractions around generating mining templates.
"""

import random
from typing import Dict, Iterable, List, NamedTuple, Optional, Set, Tuple, Type, Union

from hathor.transaction import BaseTransaction, Block, MergeMinedBlock
from hathor.transaction.storage import TransactionStorage


class BlockTemplate(NamedTuple):
    versions: Set[int]
    reward: int  # reward unit value, 64.00 HTR is 6400
    weight: float  # calculated from the DAA
    timestamp_now: int  # the reference timestamp the template was generated for
    timestamp_min: int  # min valid timestamp
    timestamp_max: int  # max valid timestamp
    parents: List[bytes]  # required parents, will always have a block and at most 2 txs
    parents_any: List[bytes]  # list of extra parents to choose from when there are more options
    height: int  # metadata
    score: float  # metadata

    def generate_minimaly_valid_block(self) -> BaseTransaction:
        """ Generates a block, without any extra information that is valid for this template. No random choices."""
        from hathor.transaction import TxOutput, TxVersion
        return TxVersion(min(self.versions)).get_cls()(
            timestamp=self.timestamp_min,
            parents=self.parents[:] + sorted(self.parents_any)[:(3 - len(self.parents))],
            outputs=[TxOutput(self.reward, b'')],
            weight=self.weight,
        )

    def generate_mining_block(self, merge_mined: bool = False, address: Optional[bytes] = None,
                              timestamp: Optional[int] = None, data: Optional[bytes] = None,
                              storage: Optional[TransactionStorage] = None, include_metadata: bool = False,
                              ) -> Union[Block, MergeMinedBlock]:
        """ Generates a block by filling the template with the given options and random parents (if multiple choices).

        Note that if a timestamp is given it will be coerced into the [timestamp_min, timestamp_max] range.
        """
        # XXX: importing these here to try to contain hathor dependencies as much as possible
        from hathor.transaction import TransactionMetadata, TxOutput
        from hathor.transaction.scripts import create_output_script

        parents = list(self.get_random_parents())
        output_script = create_output_script(address) if address is not None else b''
        base_timestamp = timestamp if timestamp is not None else self.timestamp_now
        block_timestamp = min(max(base_timestamp, self.timestamp_min), self.timestamp_max)
        tx_outputs = [TxOutput(self.reward, output_script)]
        cls: Union[Type['Block'], Type['MergeMinedBlock']] = MergeMinedBlock if merge_mined else Block
        block = cls(outputs=tx_outputs, parents=parents, timestamp=block_timestamp,
                    data=data or b'', storage=storage, weight=self.weight)
        if include_metadata:
            block._metadata = TransactionMetadata(height=self.height, score=self.score)
        block.get_metadata(use_storage=False)
        return block

    def get_random_parents(self) -> Tuple[bytes, bytes, bytes]:
        """ Get parents from self.parents plus a random choice from self.parents_any to make it 3 in total.

        Return type is tuple just to make it clear that the length is always 3.
        """
        more_parents = [x for _, x in sorted(random.sample(list(enumerate(self.parents_any)), 3 - len(self.parents)))]
        p1, p2, p3 = self.parents[:] + more_parents
        return p1, p2, p3

    def to_dict(self) -> Dict:
        return {
            'data': self.generate_minimaly_valid_block().get_struct_without_nonce().hex(),
            'versions': sorted(self.versions),
            'reward': self.reward,
            'weight': self.weight,
            'timestamp_now': self.timestamp_now,
            'timestamp_min': self.timestamp_min,
            'timestamp_max': self.timestamp_max,
            'parents': [p.hex() for p in self.parents],
            'parents_any': [p.hex() for p in self.parents_any],
            'height': self.height,
            'score': self.score,
        }

    @classmethod
    def from_dict(cls, data: Dict) -> 'BlockTemplate':
        return cls(
            versions=set(data['versions']),
            reward=int(data['reward']),
            weight=float(data['weight']),
            timestamp_now=int(data['timestamp_now']),
            timestamp_min=int(data['timestamp_min']),
            timestamp_max=int(data['timestamp_max']),
            parents=[bytes.fromhex(p) for p in data['parents']],
            parents_any=[bytes.fromhex(p) for p in data['parents_any']],
            height=int(data['height']),
            score=int(data['score']),
        )


class BlockTemplates(List[BlockTemplate]):
    def __init__(self, templates: Iterable[BlockTemplate], storage: Optional[TransactionStorage] = None):
        super().__init__(templates)
        self.storage = storage
        assert len(self) > 0, 'This class requires at least one block template.'

    def generate_mining_block(self, merge_mined: bool = False, address: Optional[bytes] = None,
                              timestamp: Optional[int] = None, data: Optional[bytes] = None,
                              storage: Optional[TransactionStorage] = None, include_metadata: bool = False,
                              ) -> Union[Block, MergeMinedBlock]:
        """ Randomly choose a template and use that for generating a block, see BlockTemplate.generate_mining_block"""
        return random.choice(self).generate_mining_block(merge_mined=merge_mined, address=address,
                                                         timestamp=timestamp, data=data,
                                                         storage=storage or self.storage,
                                                         include_metadata=include_metadata)
