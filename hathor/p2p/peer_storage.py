# encoding: utf-8


class PeerStorage(dict):
    """ PeerStorage is used to store all known peers in memory.
    It is a dict of peer objects, and peers can be retrieved by their `peer.id`.
    """

    def add(self, peer):
        """ Add a new peer to the storage.

        Raises a `ValueError` if the peer has already been added.
        """
        if peer.id in self:
            raise ValueError('Peer has already been added')
        self[peer.id] = peer

    def add_or_merge(self, peer):
        """ Add a peer to the storage if it has not been added yet.
        Otherwise, merge the current peer with the given one.
        """
        if peer.id not in self:
            self.add(peer)
        else:
            current = self[peer.id]
            current.merge(peer)
