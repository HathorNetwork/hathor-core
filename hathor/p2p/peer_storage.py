# encoding: utf-8


class PeerStorage(dict):
    def add(self, peer):
        if peer.id in self:
            raise ValueError('Peer has already been added')
        self[peer.id] = peer

    def add_or_merge(self, peer):
        if peer.id not in self:
            self.add(peer)
        else:
            current = self[peer.id]
            current.merge(peer)
