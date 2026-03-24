---
description: "Investigate the event system, WebSocket protocol, pub/sub, event types, and event streaming in hathor-core"
---

# Event System & WebSocket

When the user asks about events, WebSocket, or pub/sub, follow these steps:

## Step 1: Read the event module
- `hathor/event/` — event system implementation
- Understand event types and how they're generated
- Check event storage and retrieval

## Step 2: Read the WebSocket module
- `hathor/websocket/` — WebSocket protocol implementation
- Understand the WebSocket message format
- Check subscription/filtering mechanisms

## Step 3: Read the pub/sub system
- `hathor/pubsub.py` — publish/subscribe system for internal event distribution
- How components subscribe to and emit events
- Event propagation flow

## Step 4: Understand event types
- What events are emitted (new vertex, confirmation, reorg, etc.)
- Event payload structure
- How events relate to the transaction lifecycle

## Step 5: Check event streaming
- How events are streamed to external consumers
- Event ordering guarantees
- Replay and catch-up mechanisms

## Step 6: Explain
Present the event mechanism, WebSocket protocol detail, or pub/sub flow relevant to the user's question.
