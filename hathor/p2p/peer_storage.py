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

from typing import Protocol, TypeVar

from typing_extensions import Self

from hathor.p2p.peer import PublicPeer, UnverifiedPeer
from hathor.p2p.peer_id import PeerId


class GenericPeer(Protocol):
    @property
    def id(self) -> PeerId:
        pass

    def merge(self, other: Self) -> None:
        pass


PeerType = TypeVar('PeerType', bound=GenericPeer)


class _BasePeerStorage(dict[PeerId, PeerType]):
    """ Base class for VerifiedPeerStorage and UnverifiedPeerStorage, do not use directly.
    """

    def add(self, peer: PeerType) -> None:
        """ Add a new peer to the storage.

        Raises a `ValueError` if the peer has already been added.
        """
        assert peer.id is not None
        if peer.id in self:
            raise ValueError('Peer has already been added')
        self[peer.id] = peer

    def add_or_merge(self, peer: PeerType) -> PeerType:
        """ Add a peer to the storage if it has not been added yet. Otherwise, merge it with the existing peer.
        """
        assert peer.id is not None
        if peer.id not in self:
            self.add(peer)
            return peer
        else:
            current = self[peer.id]
            current.merge(peer)
            return current

    def add_or_replace(self, peer: PeerType) -> PeerType:
        """ Add a peer to the storage if it has not been added yet. Otherwise, replace the existing peer.
        """
        assert peer.id is not None
        if peer.id in self:
            del self[peer.id]
        self.add(peer)
        return peer

    def remove(self, peer: GenericPeer) -> None:
        """ Remove a peer from the storage
        """
        assert peer.id is not None
        if peer.id in self:
            del self[peer.id]


class VerifiedPeerStorage(_BasePeerStorage[PublicPeer]):
    """ VerifiedPeerStorage is used to store all peers that we have connected to and verified.

    It is a dict of PublicPeer objects, and peers can be retrieved by their `peer.id`.
    """


class UnverifiedPeerStorage(_BasePeerStorage[UnverifiedPeer]):
    """ UnverifiedPeerStorage is used to store all received peers, we haven't verified their ids/entrypoints yet.

    It is a dict of Peer objects, and peers can be retrieved by their `peer.id`.
    """
