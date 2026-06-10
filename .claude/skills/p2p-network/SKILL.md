---
description: "Investigate the P2P network protocol, peer connections, sync v2, peer discovery, and message propagation"
---

# P2P Network Protocol

When the user asks about P2P networking, peer connections, sync, or message propagation, follow these steps:

## Step 1: Read the core P2P files
- `hathor/p2p/manager.py` — `ConnectionsManager` manages all peer connections
- `hathor/p2p/protocol.py` — protocol state machine for peer connections
- `hathor/p2p/states/` — protocol states (HELLO, PEER_ID, READY, etc.)

## Step 2: Understand the sync protocol
- `hathor/p2p/sync_v2/` — sync v2 implementation (current sync protocol)
- Look for `NodeBlockSync` (sync agent) and `SyncV2Factory` in `hathor/p2p/sync_v2/`
- Understand how nodes exchange block and transaction data
- Check `hathor/p2p/sync_v2/mempool.py` for mempool synchronization

## Step 3: Check peer discovery
- How peers find each other (DNS seeds, bootstrap nodes, peer exchange)
- Peer management: connection limits, peer scoring, ban logic

## Step 4: Check message types
- Look for message definitions and handlers
- Understand the message serialization format
- Check how vertices are propagated to peers

## Step 5: Check connection lifecycle
- Connection establishment (TCP, TLS)
- Handshake protocol (version negotiation, capabilities exchange)
- Connection maintenance (heartbeat/ping-pong)
- Disconnection handling

## Step 6: Explain
Present the relevant P2P mechanism, protocol flow, or configuration based on the user's specific question.
