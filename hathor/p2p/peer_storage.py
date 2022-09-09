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

from typing import Dict

from hathor.p2p.peer_id import PeerId


class PeerStorage(Dict[str, PeerId]):
    """ PeerStorage is used to store all known peers in memory.
    It is a dict of peer objects, and peers can be retrieved by their `peer.id`.
    """

    def add(self, peer: PeerId) -> None:
        """ Add a new peer to the storage.

        Raises a `ValueError` if the peer has already been added.
        """
        assert peer.id is not None
        if peer.id in self:
            raise ValueError('Peer has already been added')
        self[peer.id] = peer

    def add_or_merge(self, peer: PeerId) -> PeerId:
        """ Add a peer to the storage if it has not been added yet.
        Otherwise, merge the current peer with the given one.
        """
        assert peer.id is not None
        if peer.id not in self:
            self.add(peer)
            return peer
        else:
            current = self[peer.id]
            current.merge(peer)
            return current

    def remove(self, peer: PeerId) -> None:
        """ Remove a peer from the storage
        """
        assert peer.id is not None
        if peer.id in self:
            del self[peer.id]
