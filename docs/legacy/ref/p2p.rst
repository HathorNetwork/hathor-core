==============
``hathor.p2p``
==============

.. currentmodule:: hathor.p2p

The Hathor Peer-to-Peer Network connects peers in a distributed network and allows them to exchange messages
about transaction and blocks. This module is divided in the following submodules:

#. Peer-to-Peer Protocol,
#. Peer Discovery,
#. Peer Identification, and
#. DAG Synchonizer.

The :py:class:`hathor.p2p.manager.HathorManager` coordinates all these submodules, and its objective
is to keep the network up and running.

The :py:class:`hathor.p2p.protocol.HathorProtocol` manages a specific connection between you and one peer. If you are
connected to four other peers, then you will have four instances of :py:class:`hathor.p2p.protocol.HathorProtocol`.

The :py:class:`hathor.p2p.factory.HathorServerFactory` and :py:class:`hathor.p2p.factory.HathorClientFactory` are responsible
to create the protocols when a new connection is established. If you have opened the connection, then the
py:class:`hathor.p2p.factory.HathorClientFactory` will be used. If you are listening to new connections and one arrives
then the :py:class:`hathor.p2p.factory.HathorServerFactory` will be used.

The :py:mod:`hathor.p2p.states` has all states and messages of the p2p network. It is used by the :py:class:`hathor.p2p.protocol.HathorProtocol`
to send new messages and handle the new incoming ones.


The :py:class:`hathor.p2p.peer.Peer` stores the peer's identity, entrypoint, reputation and history.



``hathor.p2p.manager``
=======================

.. automodule:: hathor.p2p.manager
   :members:
   :undoc-members:

``hathor.p2p.protocol``
=======================

.. automodule:: hathor.p2p.protocol
   :members:
   :undoc-members:


``hathor.p2p.factory``
=======================

.. automodule:: hathor.p2p.factory
   :members:
   :undoc-members:


``hathor.p2p.peer_id``
======================

.. automodule:: hathor.p2p.peer_id
   :members:
   :undoc-members:


``hathor.p2p.states``
=======================

.. automodule:: hathor.p2p.states
   :members:
   :undoc-members:
