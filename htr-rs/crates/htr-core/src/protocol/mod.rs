// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0
/*!
## Wire level specification

### Transport & Framing

- Transport: TLS over TCP by default, or QUIC (feature-gated) using the same TLS configuration. SAN must be empty and the certificate’s public key must match the peer’s declared pubKey.
- Line protocol: one ASCII line per message, terminated by CRLF. Message = COMMAND[ SP payload].
- Maximum line length: 65536 bytes (excluding delimiter). Lines exceeding this or invalid ASCII must close the connection.
- Unknown command or command invalid in the current state: send ERROR <reason> then close.

### States

- HELLO: Both sides send/accept only HELLO, ERROR, THROTTLE.
- PEER_ID: Both sides send PEER-ID, then READY. Accept PEER-ID, READY, ERROR, THROTTLE.
- READY: Normal operation. Accept control messages and sync messages (see below).

A connection advances: HELLO → PEER_ID → READY. Enter READY only after both peers exchanged READY.

### Hello Handshake

- Command: HELLO {json}
- Payload fields (JSON):
  - app: string (e.g., "Hathor vX.Y.Z"). Mismatch is allowed (logged) but not fatal.
  - network: must equal local network.
  - remote_address: free-form string (peer’s view of our address).
  - genesis_short_hash: 7-hex prefix; must match.
  - timestamp: remote wall-clock seconds; abs(diff) must be ≤ MAX_FUTURE_TIMESTAMP_ALLOWED/2.
  - settings_dict (optional): JSON snapshot of fields that must match exactly when present.
  - capabilities: string list. Common values: whitelist, sync-version, get-best-blockchain, ipv6, nano-state.
  - If capabilities contains sync-version, must include sync_versions: list of supported protocol versions by label. Known: "v1.1", "v2".
- Version negotiation: choose the highest common version; if none, send ERROR and close.
- On any mismatch (network, genesis, timestamp drift, settings_dict), send ERROR and close.
- After a valid HELLO, transition to PEER_ID.

### Peer Identity & Readiness

- Command: PEER-ID {json}
- Payload fields (JSON):
  - id: 64-hex peer ID. Must equal SHA256(SHA256(pubKey DER)).
  - pubKey: base64 DER public key.
  - entrypoints: array of endpoints as strings, format tcp://host:port (optionally may appear as tcp://host:port/?id=<peerid> when relayed).
- Acceptance rules:
  - If an expected peer-id is set for the outbound dial, it must match id.
  - If whitelist enforcement applies, block non-whitelisted peers per local policy.
  - Must not be the same peer-id as ourselves; and must not already be connected.
  - entrypoints count ≤ PEER_MAX_ENTRYPOINTS. At least one entrypoint must match the actual remote connection (directly or via DNS resolution).
  - If TLS is enabled: certificate public key must equal pubKey.
- On success: accept peer, then send READY. When both sides have sent/received READY, transition to READY.

### Control Messages (READY state)

- PING <salt_hex>: respond with PONG <salt_hex>. Salts are hex of 32 random bytes.
- PONG <salt_hex>: only meaningful if a PING was pending; otherwise ignore.
- GET-PEERS: request peers.
- PEERS {json}: payload is a JSON array of peers with shape {"id": "...", "entrypoints": ["tcp://..."]}. If ipv6 capability is not common, only IPv4 entrypoints are relayed. Multiple PEERS messages may be sent to answer one GET-PEERS.
- THROTTLE <key> <reason>: advisory; indicates sender is rate limiting a key (e.g., global).

### Optional capability get-best-blockchain:

- GET-BEST-BLOCKCHAIN N: N ∈ [1, MAX_BEST_BLOCKCHAIN_BLOCKS]. Response:
- BEST-BLOCKCHAIN {json}: JSON array of pairs [height:int, hash_hex:str] representing the last N blocks of the best chain (descending).

### Nano-state (only if both advertise nano-state):

- GET-BLOCK-NC-ROOT-ID <block_hash_hex> → BLOCK-NC-ROOT-ID <block_hash_hex> <root_id_hex>
- GET-NC-DB-NODE <node_id_hex> → NC-DB-NODE {json} with keys: id, key, optional content, optional children mapping.

### Sync v2 Messages (READY state, negotiated v2)

Binary payloads are base64-encoded ASCII.

- Best block:
  - GET-BEST-BLOCK → BEST-BLOCK {"block":"hex","height":int}
- Block streaming:
  - GET-NEXT-BLOCKS {"start_hash":"hex","end_hash":"hex","quantity":int}
  - Response is a stream: zero or more BLOCKS <base64(block_bytes)> followed by exactly one BLOCKS-END <code_int>.
  - End codes (int): 0 END_HASH_REACHED, 1 NO_MORE_BLOCKS, 2 LIMIT_EXCEEDED, 3 STREAM_BECAME_VOIDED, 6 INTERNAL_ERROR, 7 PER_REQUEST.
  - STOP-BLOCK-STREAMING: request the server to stop; server responds with BLOCKS-END 7.
  - Receiving BLOCKS or BLOCKS-END is valid only while syncing blocks; otherwise send ERROR and close.
- Transactions BFS streaming:
  - GET-TRANSACTIONS-BFS {"start_from":["hex"...], "first_block_hash":"hex", "last_block_hash":"hex"}
    - start_from length ≤ 8. Each item must exist and be confirmed by first_block_hash. If not, reply TRANSACTIONS-END 5 (INVALID_PARAMS) or NOT-FOUND <hex>.
  - Response: zero or more TRANSACTION <base64(tx_bytes)> followed by TRANSACTIONS-END <code_int> (same code set as blocks; 4 indicates reached an unconfirmed tx).
  - STOP-TRANSACTIONS-STREAMING: server replies TRANSACTIONS-END 7.
  - Receiving TRANSACTION or TRANSACTIONS-END is valid only while syncing transactions; otherwise ERROR and close.
- Tips (mempool heads):
  - GET-TIPS → zero or more TIPS ["hex", ...] (typically one id per message), then TIPS-END.
  - Receiver should aggregate tips until TIPS-END. If the number of pending collected tips exceeds MAX_MEMPOOL_RECEIVING_TIPS, send ERROR and close.
- Vertex fetch/relay:
  - GET-DATA {"txid":"hex", "origin":"mempool"?} → DATA [origin ]<base64(vertex_bytes)> or NOT-FOUND <txid_hex>.
  - RELAY true|false (payload is JSON boolean, or empty meaning true): toggles unsolicited relay acceptance/delivery. Unsolicited DATA while inbound relay is disabled increases misbehavior score and may lead to disconnect.

### Message Validation & Limits

- Length and encoding: whole line ≤ 65536 bytes; all bytes must be ASCII. Base64 payloads must decode; JSON payloads must parse (ASCII JSON is required).
- Hex identifiers: 32-byte hashes serialized as 64 hex chars.
- GET-PEER-BLOCK-HASHES:
  - GET-PEER-BLOCK-HASHES [height,int,...] (max 20 heights) → PEER-BLOCK-HASHES [[height,"hex"], ...]. Stops at first missing/voided height.
- Idle timeout: if no message is received for PEER_IDLE_TIMEOUT seconds (default 60), the connection is closed.
- Timestamp drift in HELLO: |remote_now - local_now| ≤ MAX_FUTURE_TIMESTAMP_ALLOWED/2.
- Misbehavior: peers accrue a score on violations (e.g., unsolicited relay when disabled); reaching a threshold closes the connection.

### ERROR Semantics

- ERROR <reason> is advisory; implementations should log and will usually close the connection immediately after sending one.
- On protocol violation or invalid payload, send ERROR <reason> and close.

### Throttling & Backpressure

- Per‑connection leaky bucket
  - Every connection maintains a rate limiter keyed by strings; currently global is used for all inbound messages on that connection.
  - Before dispatching any received line, the peer attempts add_hit('global'). If the bucket is full, the line is not processed and a throttle notice is sent.
  - Decay model: leaky bucket over a window; hits leak linearly with time. Limits are configured as “max_hits per window_seconds”.
- THROTTLE message
  - Command: THROTTLE <key> At most <max_hits> hits every <window_seconds> seconds
  - Sent immediately when a message is dropped due to rate limiting. The offending message is ignored (not queued or retried by the receiver).
  - May be sent in any state (HELLO, PEER_ID, READY); it does not change state.
  - Semantics are advisory: receivers SHOULD back off. A simple policy is to limit sending for that key to ≤ ceil(max_hits/window_seconds) per second (or add randomized jitter). The format is stable text; unknown key values are allowed.
- Typical limits
  - Not fixed by the wire protocol. Implementations MAY set connection‑local global limits (e.g., 120 hits per 60s).
  - A node MAY also impose feature‑specific global limits internally (e.g., “send tips” fanout) that aren’t signaled with THROTTLE.
- Misbehavior vs throttling
  - Separate from THROTTLE, peers track a “misbehavior” score using the same leaky‑bucket mechanics (threshold 100 over 3600s).
  - Certain protocol violations (e.g., unsolicited DATA when inbound relay is disabled) add weight to this score. Crossing the threshold triggers ERROR <reason> and disconnect. This is not a throttle; it is enforcement.
- Sender behavior on THROTTLE
  - Receiving THROTTLE ... is not an error; do not close or change states.
  - Back off sending for that key; a conservative approach is to delay next attempt so that average rate ≤ max_hits/window_seconds.
  - Because the message that triggered THROTTLE was discarded, idempotent or query messages SHOULD be retried later; streaming senders SHOULD pause until within allowance.
- Receiver behavior when limiting
  - If rate exceeded for the enforced key, drop the triggering message, send one THROTTLE line with the current limit, then return to idle.
  - Continue processing future messages that arrive within allowance; no cooldown is enforced beyond the leaky‑bucket capacity.
- Examples
  - Inbound limit: 120 hits / 60s. If exceeded:
  - Send: THROTTLE global At most 120 hits every 60 seconds
  - Ignore the offending line (do not dispatch its handler).
  - After receiving that line, a well‑behaved peer reduces its send rate to ≤ 2 msgs/s (plus jitter) for that connection/key.
- Implementation notes (sans‑IO)
  - Maintain a per‑connection limiter keyed by global. On each inbound line, consult limiter; if denied, emit THROTTLE and drop.
  - Parse THROTTLE payload into a struct: {key, max_hits:int, window_seconds:float} and update your peer‑specific backoff scheduler.
  - Treat THROTTLE as stateless; do not require an ACK; limits may change over time (new THROTTLE supersedes previous guidance).

## Examples

- HELLO: HELLO {"app":"Hathor v0.66.0","network":"mainnet","remote_address":"1.2.3.4:40403","genesis_short_hash":"abc1234","timestamp":1732567890,"settings_dict":{...},"capabilities":["whitelist","sync-version","ipv6","get-best-blockchain","nano-state"],"sync_versions":
  ["v2","v1.1"]}
- PEER-ID: PEER-ID {"id":"<64-hex>","pubKey":"<base64 DER>","entrypoints":["tcp://node.example.com:40403"]}
- PING/PONG: PING a1b2...f0; PONG a1b2...f0
- GET-NEXT-BLOCKS: GET-NEXT-BLOCKS {"start_hash":"<hex>","end_hash":"<hex>","quantity":1000}
- BLOCKS: BLOCKS <base64>
- BLOCKS-END: BLOCKS-END 0
- GET-TRANSACTIONS-BFS: GET-TRANSACTIONS-BFS {"start_from":["<hex>"],"first_block_hash":"<hex>","last_block_hash":"<hex>"}
- TRANSACTION: TRANSACTION <base64>
- TRANSACTIONS-END: TRANSACTIONS-END 0
- GET-DATA: GET-DATA {"txid":"<hex>","origin":"mempool"}
- DATA: DATA <base64>  or  DATA mempool <base64>
- GET-TIPS/TIPS/TIPS-END: GET-TIPS → TIPS ["<hex>"] ... → TIPS-END
- GET-PEERS/PEERS: GET-PEERS → PEERS [{"id":"<hex>","entrypoints":["tcp://h:40403"]}]
*/

use crate::common::Hash32ParseError;
use crate::peer::{PeerId, PrivatePeer, PublicPeer};
use der::{Decode, Encode};
use std::fmt;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::TlsStream;

use tracing::*;
use x509_cert::Certificate;

pub(crate) mod codec;
pub mod driver;
pub mod drivers;
pub mod engine;
pub mod message;
pub mod state;
pub use self::driver::{DriverAction, ProtocolDriver};
pub use self::message::{
    AnyStateMessage, Capability, ControlMessage, GetDataReq, HelloData, HelloMessage,
    HelloStateMessage, HelloTimestamp, NextBlocksReq, PeerIdMessage, PeerIdStateMessage,
    ReadyMessage, ReadyStateMessage, SyncV2Message, SyncVersion, ThrottleScope, TransactionsBfsReq,
};
// Engine types are private to the engine module; top-level exports focus on message types.

pub const MAX_LINE_LENGTH: usize = 65536;
pub static APP_STRING: &str = "Hathor-experimental v0.0.0";

#[derive(Error, Debug)]
pub enum Error {
    #[error("formatting error")]
    Format(#[from] fmt::Error),
    #[error("I/O error")]
    Io(#[from] std::io::Error),
    #[error("JSON error")]
    Json(#[from] serde_json::Error),
    #[error("Hex encoding error")]
    Hex(#[from] Hash32ParseError),
    #[error("the given word message is not valid")]
    InvalidMessageWord,
    #[error("data was expected")]
    MissingData,
    #[error("connection dropped before a message could be fully received")]
    Disconnected,
    #[error("line too long")]
    MaxLineLengthExceeded,
    #[error("invalid encoding")]
    InvalidEncoding,
    #[error("bad certificate")]
    BadCertificate,
}

pub trait TlsStreamExt {
    /// Attempt to derive the expected remote `PeerId` from the server certificate
    /// presented in a `tokio_rustls` client-side stream.
    fn gen_peer_id_from_conn_cert(&self) -> Option<PeerId>;
}

impl<IO: fmt::Debug + AsyncWrite + AsyncRead + std::marker::Unpin> TlsStreamExt for TlsStream<IO> {
    fn gen_peer_id_from_conn_cert(&self) -> Option<PeerId> {
        let (_io, conn) = self.get_ref();
        peer_id_from_rustls_chain(conn.peer_certificates()?)
    }
}

impl<IO: fmt::Debug + AsyncWrite + AsyncRead + std::marker::Unpin> TlsStreamExt
    for tokio_rustls::client::TlsStream<IO>
{
    fn gen_peer_id_from_conn_cert(&self) -> Option<PeerId> {
        let (_io, conn) = self.get_ref();
        peer_id_from_rustls_chain(conn.peer_certificates()?)
    }
}

impl<IO: fmt::Debug + AsyncWrite + AsyncRead + std::marker::Unpin> TlsStreamExt
    for tokio_rustls::server::TlsStream<IO>
{
    fn gen_peer_id_from_conn_cert(&self) -> Option<PeerId> {
        let (_io, conn) = self.get_ref();
        peer_id_from_rustls_chain(conn.peer_certificates()?)
    }
}

pub(crate) fn peer_id_from_rustls_chain(
    chain: &[rustls_pki_types::CertificateDer<'_>],
) -> Option<PeerId> {
    let end_entity = chain.first()?;
    peer_id_from_certificate_bytes(end_entity.as_ref())
}

pub(crate) fn peer_id_from_certificate_bytes(der: &[u8]) -> Option<PeerId> {
    let cert = Certificate::from_der(der).ok()?;
    let spki = cert
        .tbs_certificate()
        .subject_public_key_info()
        .to_der()
        .ok()?;
    Some(PeerId::from_spki_der(&spki))
}

// conn_handler moved to engine::run
