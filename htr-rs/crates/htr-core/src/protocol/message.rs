// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::Error;
use crate::nano::{Node as NcNode, NodeId as NcNodeId};
use crate::peer::{PublicPeer, UnverifiedPeer};
use crate::utils::forward_try_from_serde_str;
use crate::vertex::{
    AnyBlockData, AnyTransactionData, AnyVertexData, BlockId, TransactionId, VertexId,
    decode_any_block_data, decode_any_transaction_data, decode_any_vertex_data,
    encode_any_block_data, encode_any_transaction_data, encode_any_vertex_data,
};
use base64::prelude::*;
use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use smallvec::SmallVec;
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use time::OffsetDateTime;
use typed_floats::{InvalidNumber, PositiveFinite};

const NANOS_PER_SECOND: f64 = 1_000_000_000.0;

/// Timestamp attached to HELLO messages.
///
/// Backed by a `PositiveFinite<f64>` with a helper constructor that sources the current
/// `OffsetDateTime`. Keeping this as a dedicated newtype avoids making callers pull in
/// `typed_floats` directly and centralizes the now()/to-seconds helpers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HelloTimestamp(PositiveFinite<f64>);

impl HelloTimestamp {
    /// Fallible constructor from a raw `f64`.
    pub fn try_new(value: f64) -> Result<Self, InvalidNumber> {
        PositiveFinite::<f64>::new(value).map(Self)
    }

    /// Infalible constructor from a `PositiveFinite`.
    pub fn from_positive(value: PositiveFinite<f64>) -> Self {
        Self(value)
    }

    /// Current wall-clock timestamp (UTC), in fractional seconds.
    pub fn now() -> Self {
        Self::from_datetime(OffsetDateTime::now_utc())
    }

    /// Construct from an `OffsetDateTime`.
    pub fn from_datetime(now: OffsetDateTime) -> Self {
        let timestamp = now.unix_timestamp() as f64 + now.nanosecond() as f64 / NANOS_PER_SECOND;
        Self::try_new(timestamp).expect("current wall clock time must be finite and non-negative")
    }

    /// Expose the underlying `PositiveFinite`.
    pub fn as_positive(&self) -> PositiveFinite<f64> {
        self.0
    }

    /// Return the timestamp as a bare `f64`.
    pub fn as_seconds(&self) -> f64 {
        self.0.get()
    }
}

impl From<PositiveFinite<f64>> for HelloTimestamp {
    fn from(value: PositiveFinite<f64>) -> Self {
        Self::from_positive(value)
    }
}

impl From<HelloTimestamp> for PositiveFinite<f64> {
    fn from(value: HelloTimestamp) -> Self {
        value.0
    }
}

impl From<HelloTimestamp> for f64 {
    fn from(value: HelloTimestamp) -> Self {
        value.as_seconds()
    }
}

impl TryFrom<f64> for HelloTimestamp {
    type Error = InvalidNumber;

    fn try_from(value: f64) -> Result<Self, Self::Error> {
        Self::try_new(value)
    }
}

/// Tri-state parser used to compose parsers across message groups.
/// - Ok(Some(T)) → successfully parsed this message type
/// - Ok(None) → this message word does not belong to this type (try next type)
/// - Err(Error) → the message word belongs here but payload is malformed
pub trait PartialParse: Sized {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error>;
}

// No runtime conversion for words; use static &'static str literals in Display/parse.

fn split_word_payload(s: &str) -> Result<(&str, Option<&str>), Error> {
    let mut split = s.splitn(2, ' ');
    let word = split.next().ok_or(Error::InvalidMessageWord)?.trim();
    let payload = split.next();
    Ok((word, payload))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Capability {
    Whitelist,
    SyncVersion,
    GetBestBlockchain,
    Ipv6,
    NanoState,
    Quic,
    #[serde(untagged)]
    Other(String),
}

impl Capability {
    pub fn default_capabilities() -> Vec<Self> {
        #[allow(unused_mut)]
        let mut caps = vec![
            Capability::Whitelist,
            Capability::SyncVersion,
            Capability::GetBestBlockchain,
            Capability::Ipv6,
            Capability::NanoState,
        ];
        #[cfg(feature = "transport-quic")]
        {
            caps.push(Capability::Quic);
        }
        caps
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum SyncVersion {
    #[serde(rename = "v1.1")]
    SyncV11,
    #[serde(rename = "v2")]
    #[default]
    SyncV2,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HelloData {
    pub app: String,     // own info is static, we might avoid allocating a String
    pub network: String, // needs runtime settings (NetworkInfo currently)
    pub remote_address: SocketAddr, // needs connection info
    pub genesis_short_hash: String, // needs runtime settings (NetworkInfo currently)
    pub timestamp: HelloTimestamp, // needs clock
    pub capabilities: Vec<Capability>, // own info is static, we might avoid allocating a Vec
    pub sync_versions: Vec<SyncVersion>, // own info is static, we might avoid allocating a Vec
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HeightInfo(u64, BlockId);

impl HeightInfo {
    pub fn height(&self) -> u64 {
        self.0
    }

    pub fn block_id(&self) -> BlockId {
        self.1
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NextBlocksReq {
    pub start_hash: VertexId,
    pub end_hash: VertexId,
    pub quantity: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransactionsBfsReq {
    pub start_from: Vec<VertexId>,
    pub first_block_hash: BlockId,
    pub last_block_hash: BlockId,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataOrigin {
    Mempool,
}
forward_try_from_serde_str!(DataOrigin);
impl fmt::Display for DataOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DataOrigin::Mempool => write!(f, "mempool"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetDataReq {
    pub txid: VertexId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub origin: Option<DataOrigin>,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum StreamEnd {
    EndHashReached = 0,
    NoMoreBlocks = 1,
    LimitExceeded = 2,
    StreamBecameVoided = 3,
    TxNotConfirmed = 4,
    InvalidParams = 5,
    InternalError = 6,
    PerRequest = 7,
}
impl fmt::Display for StreamEnd {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", *self as u8)
    }
}
impl core::convert::TryFrom<u8> for StreamEnd {
    type Error = ();
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => StreamEnd::EndHashReached,
            1 => StreamEnd::NoMoreBlocks,
            2 => StreamEnd::LimitExceeded,
            3 => StreamEnd::StreamBecameVoided,
            4 => StreamEnd::TxNotConfirmed,
            5 => StreamEnd::InvalidParams,
            6 => StreamEnd::InternalError,
            7 => StreamEnd::PerRequest,
            _ => return Err(()),
        })
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum ThrottleScope {
    #[default]
    Global,
}
forward_try_from_serde_str!(ThrottleScope);
impl fmt::Display for ThrottleScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ThrottleScope::Global => write!(f, "global"),
        }
    }
}

/// Base enum of the messages that are common to every state
#[derive(Clone, Debug, PartialEq)]
pub enum ControlMessage {
    Error(String),
    Throttle { key: ThrottleScope, reason: String },
}

impl fmt::Display for ControlMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControlMessage::Error(reason) => write!(f, "ERROR {}", reason),
            ControlMessage::Throttle { key, reason } => write!(f, "THROTTLE {} {}", key, reason),
        }
    }
}

impl PartialParse for ControlMessage {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error> {
        if word == "ERROR" {
            let data = payload.ok_or(Error::MissingData)?;
            return Ok(Some(ControlMessage::Error(data.to_string())));
        }
        if word == "THROTTLE" {
            let data = payload.ok_or(Error::MissingData)?;
            let mut parts = data.splitn(2, ' ');
            let key = ThrottleScope::try_from(parts.next().unwrap_or(""))
                .map_err(|_| Error::MissingData)?;
            let reason = parts.next().unwrap_or("").to_string();
            return Ok(Some(ControlMessage::Throttle { key, reason }));
        }
        Ok(None)
    }
}

impl FromStr for ControlMessage {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (word, payload) = split_word_payload(s)?;
        match <Self as PartialParse>::parse_partial(word, payload)? {
            Some(v) => Ok(v),
            None => Err(Error::InvalidMessageWord),
        }
    }
}

/// Messages specific to the HELLO state
#[derive(Clone, Debug, PartialEq, Eq, derive_more::From)]
pub enum HelloMessage {
    Hello(HelloData),
}

impl fmt::Display for HelloMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HelloMessage::Hello(hello) => write!(
                f,
                "HELLO {}",
                serde_json::to_string(hello).map_err(|_| fmt::Error)?
            ),
        }
    }
}

impl PartialParse for HelloMessage {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error> {
        if word == "HELLO" {
            let data = payload.ok_or(Error::MissingData)?;
            let hello_data: HelloData = serde_json::from_str(data)?;
            return Ok(Some(HelloMessage::Hello(hello_data)));
        }
        Ok(None)
    }
}

impl FromStr for HelloMessage {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (word, payload) = split_word_payload(s)?;
        match <Self as PartialParse>::parse_partial(word, payload)? {
            Some(v) => Ok(v),
            None => Err(Error::InvalidMessageWord),
        }
    }
}

/// Messages specific to the PEER-ID state
#[derive(Clone, Debug, PartialEq, derive_more::From)]
pub enum PeerIdMessage {
    PeerId(PublicPeer),
    Ready,
}

impl fmt::Display for PeerIdMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerIdMessage::PeerId(peer) => write!(
                f,
                "PEER-ID {}",
                serde_json::to_string(peer).map_err(|_| fmt::Error)?
            ),
            PeerIdMessage::Ready => write!(f, "READY"),
        }
    }
}

impl PartialParse for PeerIdMessage {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error> {
        if word == "PEER-ID" {
            let data = payload.ok_or(Error::MissingData)?;
            let public_peer: PublicPeer = serde_json::from_str(data)?;
            return Ok(Some(PeerIdMessage::PeerId(public_peer)));
        }
        if word == "READY" {
            return Ok(Some(PeerIdMessage::Ready));
        }
        Ok(None)
    }
}

impl FromStr for PeerIdMessage {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (word, payload) = split_word_payload(s)?;
        match <Self as PartialParse>::parse_partial(word, payload)? {
            Some(v) => Ok(v),
            None => Err(Error::InvalidMessageWord),
        }
    }
}

/// Messages specific to the READY-ID state
#[derive(Clone, Debug, PartialEq)]
pub enum ReadyMessage {
    Ping(String),
    Pong(String),
    GetPeers,
    Peers(SmallVec<[UnverifiedPeer; 1]>),
    GetBestBlockchain(Option<u8>),
    BestBlockchain(Vec<HeightInfo>),
    GetBlockNcRootId(BlockId),
    BlockNcRootId(BlockId, NcNodeId),
    GetNcDbNode(NcNodeId),
    NcDbNode(NcNode),
}

impl fmt::Display for ReadyMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadyMessage::Ping(s) => write!(f, "PING {}", s),
            ReadyMessage::Pong(s) => write!(f, "PONG {}", s),
            ReadyMessage::GetPeers => write!(f, "GET-PEERS"),
            ReadyMessage::Peers(list) => write!(
                f,
                "PEERS {}",
                serde_json::to_string(list).map_err(|_| fmt::Error)?
            ),
            ReadyMessage::GetBestBlockchain(n) => {
                if let Some(n) = n {
                    write!(f, "GET-BEST-BLOCKCHAIN {}", n)
                } else {
                    write!(f, "GET-BEST-BLOCKCHAIN")
                }
            }
            ReadyMessage::BestBlockchain(list) => write!(
                f,
                "BEST-BLOCKCHAIN {}",
                serde_json::to_string(list).map_err(|_| fmt::Error)?
            ),
            ReadyMessage::GetBlockNcRootId(block_id) => {
                write!(f, "GET-BLOCK-NC-ROOT-ID {}", block_id,)
            }
            ReadyMessage::BlockNcRootId(block_id, node_id) => {
                write!(f, "BLOCK-NC-ROOT-ID {} {}", block_id, node_id,)
            }
            ReadyMessage::GetNcDbNode(node_id) => write!(f, "GET-NC-DB-NODE {}", node_id,),
            ReadyMessage::NcDbNode(node) => write!(
                f,
                "NC-DB-NODE {}",
                serde_json::to_string(node).map_err(|_| fmt::Error)?
            ),
        }
    }
}

impl PartialParse for ReadyMessage {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error> {
        Ok(match word {
            "PING" => {
                let data = payload.ok_or(Error::MissingData)?.to_string();
                Some(ReadyMessage::Ping(data))
            }
            "PONG" => {
                let data = payload.ok_or(Error::MissingData)?;
                Some(ReadyMessage::Pong(data.to_string()))
            }
            "GET-PEERS" => Some(ReadyMessage::GetPeers),
            "PEERS" => {
                let data = payload.ok_or(Error::MissingData)?;
                let list: SmallVec<[UnverifiedPeer; 1]> = serde_json::from_str(data)?;
                Some(ReadyMessage::Peers(list))
            }
            "GET-BEST-BLOCKCHAIN" => {
                let opt = payload
                    .map(|s| s.trim().parse::<u8>())
                    .transpose()
                    .ok()
                    .flatten();
                Some(ReadyMessage::GetBestBlockchain(opt))
            }
            "BEST-BLOCKCHAIN" => {
                let data = payload.ok_or(Error::MissingData)?;
                let list: Vec<HeightInfo> = serde_json::from_str(data)?;
                Some(ReadyMessage::BestBlockchain(list))
            }
            "GET-BLOCK-NC-ROOT-ID" => {
                let data = payload.ok_or(Error::MissingData)?;
                let block_id: BlockId = data.parse()?;
                Some(ReadyMessage::GetBlockNcRootId(block_id))
            }
            "BLOCK-NC-ROOT-ID" => {
                let data = payload.ok_or(Error::MissingData)?;
                let mut parts = data.splitn(2, ' ');
                let block_id: BlockId = parts.next().ok_or(Error::MissingData)?.parse()?;
                let node_id: NcNodeId = parts.next().ok_or(Error::MissingData)?.parse()?;
                Some(ReadyMessage::BlockNcRootId(block_id, node_id))
            }
            "GET-NC-DB-NODE" => {
                let data = payload.ok_or(Error::MissingData)?;
                let node_id: NcNodeId = data.parse()?;
                Some(ReadyMessage::GetNcDbNode(node_id))
            }
            "NC-DB-NODE" => {
                let data = payload.ok_or(Error::MissingData)?;
                let node: NcNode = serde_json::from_str(data)?;
                Some(ReadyMessage::NcDbNode(node))
            }
            _ => None,
        })
    }
}

impl FromStr for ReadyMessage {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (word, payload) = split_word_payload(s)?;
        match <Self as PartialParse>::parse_partial(word, payload)? {
            Some(v) => Ok(v),
            None => Err(Error::InvalidMessageWord),
        }
    }
}

/// Messages specific to the READY-ID state's sync-v2 agent (currently the only supported agent,
/// but it wasn't always the case and it might not be the case again in the future)
#[derive(Clone, Debug, PartialEq)]
pub enum SyncV2Message {
    GetBestBlock,
    GetNextBlocks(NextBlocksReq),
    Blocks(AnyBlockData),
    BlocksEnd(StreamEnd),
    StopBlockStreaming,
    GetTransactionsBfs(TransactionsBfsReq),
    Transaction(AnyTransactionData),
    TransactionsEnd(StreamEnd),
    StopTransactionsStreaming,
    GetTips,
    Tips(Vec<TransactionId>),
    TipsEnd,
    MempoolEnd,
    GetData(GetDataReq),
    Data {
        vertex: AnyVertexData,
        origin: Option<DataOrigin>,
    },
    NotFound(VertexId),
    Relay(Option<bool>),
    GetPeerBlockHashes(Vec<u64>),
    PeerBlockHashes(Vec<(u64, BlockId)>),
}

impl fmt::Display for SyncV2Message {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncV2Message::GetBestBlock => write!(f, "GET-BEST-BLOCK"),
            SyncV2Message::GetNextBlocks(req) => write!(
                f,
                "GET-NEXT-BLOCKS {}",
                serde_json::to_string(req).map_err(|_| fmt::Error)?
            ),
            SyncV2Message::Blocks(b) => {
                let mut buf = BytesMut::new();
                encode_any_block_data(&mut buf, b).map_err(|_| fmt::Error)?;
                let b64 = BASE64_STANDARD.encode(buf.freeze());
                write!(f, "BLOCKS {}", b64)
            }
            SyncV2Message::BlocksEnd(code) => {
                write!(f, "BLOCKS-END {}", code)
            }
            SyncV2Message::StopBlockStreaming => write!(f, "STOP-BLOCK-STREAMING"),
            SyncV2Message::GetTransactionsBfs(req) => write!(
                f,
                "GET-TRANSACTIONS-BFS {}",
                serde_json::to_string(req).map_err(|_| fmt::Error)?
            ),
            SyncV2Message::Transaction(t) => {
                let mut buf = BytesMut::new();
                encode_any_transaction_data(&mut buf, t).map_err(|_| fmt::Error)?;
                let b64 = BASE64_STANDARD.encode(buf.freeze());
                write!(f, "TRANSACTION {}", b64)
            }
            SyncV2Message::TransactionsEnd(code) => write!(f, "TRANSACTIONS-END {}", code),
            SyncV2Message::StopTransactionsStreaming => write!(f, "STOP-TRANSACTIONS-STREAMING"),
            SyncV2Message::GetTips => write!(f, "GET-TIPS"),
            SyncV2Message::Tips(list) => write!(
                f,
                "TIPS {}",
                serde_json::to_string(list).map_err(|_| fmt::Error)?
            ),
            SyncV2Message::TipsEnd => write!(f, "TIPS-END"),
            SyncV2Message::MempoolEnd => write!(f, "MEMPOOL-END"),
            SyncV2Message::GetData(req) => write!(
                f,
                "GET-DATA {}",
                serde_json::to_string(req).map_err(|_| fmt::Error)?
            ),
            SyncV2Message::Data { vertex, origin } => {
                let mut buf = BytesMut::new();
                encode_any_vertex_data(&mut buf, vertex).map_err(|_| fmt::Error)?;
                let b64 = BASE64_STANDARD.encode(buf.freeze());
                if let Some(o) = origin {
                    write!(f, "DATA {} {}", o, b64)
                } else {
                    write!(f, "DATA {}", b64)
                }
            }
            SyncV2Message::NotFound(txid) => write!(f, "NOT-FOUND {}", txid),
            SyncV2Message::Relay(v) => match v {
                Some(b) => write!(f, "RELAY {}", b),
                None => write!(f, "RELAY"),
            },
            SyncV2Message::GetPeerBlockHashes(heights) => write!(
                f,
                "GET-PEER-BLOCK-HASHES {}",
                serde_json::to_string(heights).map_err(|_| fmt::Error)?
            ),
            SyncV2Message::PeerBlockHashes(pairs) => write!(
                f,
                "PEER-BLOCK-HASHES {}",
                serde_json::to_string(pairs).map_err(|_| fmt::Error)?
            ),
        }
    }
}

impl PartialParse for SyncV2Message {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error> {
        if word == "GET-BEST-BLOCK" {
            return Ok(Some(SyncV2Message::GetBestBlock));
        }
        if word == "GET-NEXT-BLOCKS" {
            let data = payload.ok_or(Error::MissingData)?;
            let req: NextBlocksReq = serde_json::from_str(data)?;
            return Ok(Some(SyncV2Message::GetNextBlocks(req)));
        }
        if word == "BLOCKS" {
            let b64 = payload.ok_or(Error::MissingData)?;
            let bytes = BASE64_STANDARD
                .decode(b64.trim())
                .map_err(|_| Error::InvalidEncoding)?;
            let data =
                decode_any_block_data(bytes.as_slice()).map_err(|_| Error::InvalidEncoding)?;
            return Ok(Some(SyncV2Message::Blocks(data)));
        }
        if word == "BLOCKS-END" {
            let n = payload
                .ok_or(Error::MissingData)?
                .trim()
                .parse::<u8>()
                .map_err(|_| Error::MissingData)?;
            let code = StreamEnd::try_from(n).map_err(|_| Error::MissingData)?;
            return Ok(Some(SyncV2Message::BlocksEnd(code)));
        }
        if word == "STOP-BLOCK-STREAMING" {
            return Ok(Some(SyncV2Message::StopBlockStreaming));
        }
        if word == "GET-TRANSACTIONS-BFS" {
            let data = payload.ok_or(Error::MissingData)?;
            let req: TransactionsBfsReq = serde_json::from_str(data)?;
            return Ok(Some(SyncV2Message::GetTransactionsBfs(req)));
        }
        if word == "TRANSACTION" {
            let b64 = payload.ok_or(Error::MissingData)?;
            let bytes = BASE64_STANDARD
                .decode(b64.trim())
                .map_err(|_| Error::InvalidEncoding)?;
            let data = decode_any_transaction_data(bytes.as_slice())
                .map_err(|_| Error::InvalidEncoding)?;
            return Ok(Some(SyncV2Message::Transaction(data)));
        }
        if word == "TRANSACTIONS-END" {
            let n = payload
                .ok_or(Error::MissingData)?
                .trim()
                .parse::<u8>()
                .map_err(|_| Error::MissingData)?;
            let code = StreamEnd::try_from(n).map_err(|_| Error::MissingData)?;
            return Ok(Some(SyncV2Message::TransactionsEnd(code)));
        }
        if word == "STOP-TRANSACTIONS-STREAMING" {
            return Ok(Some(SyncV2Message::StopTransactionsStreaming));
        }
        if word == "GET-TIPS" {
            return Ok(Some(SyncV2Message::GetTips));
        }
        if word == "TIPS" {
            let data = payload.ok_or(Error::MissingData)?;
            let list: Vec<TransactionId> = serde_json::from_str(data)?;
            return Ok(Some(SyncV2Message::Tips(list)));
        }
        if word == "TIPS-END" {
            return Ok(Some(SyncV2Message::TipsEnd));
        }
        if word == "MEMPOOL-END" {
            return Ok(Some(SyncV2Message::MempoolEnd));
        }
        if word == "GET-DATA" {
            let data = payload.ok_or(Error::MissingData)?;
            let req: GetDataReq = serde_json::from_str(data)?;
            return Ok(Some(SyncV2Message::GetData(req)));
        }
        if word == "DATA" {
            let data = payload.ok_or(Error::MissingData)?;
            let mut parts = data.splitn(2, ' ');
            let first = parts.next().unwrap_or("");
            let second = parts.next();
            if let Some(b64) = second {
                let bytes = BASE64_STANDARD
                    .decode(b64.trim())
                    .map_err(|_| Error::InvalidEncoding)?;
                let vertex =
                    decode_any_vertex_data(bytes.as_slice()).map_err(|_| Error::InvalidEncoding)?;
                return Ok(Some(SyncV2Message::Data {
                    vertex,
                    origin: Some(DataOrigin::try_from(first).map_err(|_| Error::MissingData)?),
                }));
            } else {
                let bytes = BASE64_STANDARD
                    .decode(first.trim())
                    .map_err(|_| Error::InvalidEncoding)?;
                let vertex =
                    decode_any_vertex_data(bytes.as_slice()).map_err(|_| Error::InvalidEncoding)?;
                return Ok(Some(SyncV2Message::Data {
                    vertex,
                    origin: None,
                }));
            }
        }
        if word == "NOT-FOUND" {
            let txid = payload.ok_or(Error::MissingData)?;
            let id: VertexId = txid.parse()?;
            return Ok(Some(SyncV2Message::NotFound(id)));
        }
        if word == "RELAY" {
            let val = payload.map(|s| s.trim()).filter(|s| !s.is_empty());
            let opt_bool = val.map(|s| s.parse::<bool>().unwrap_or(true));
            return Ok(Some(SyncV2Message::Relay(opt_bool)));
        }
        if word == "GET-PEER-BLOCK-HASHES" {
            let data = payload.ok_or(Error::MissingData)?;
            let heights: Vec<u64> = serde_json::from_str(data)?;
            return Ok(Some(SyncV2Message::GetPeerBlockHashes(heights)));
        }
        if word == "PEER-BLOCK-HASHES" {
            let data = payload.ok_or(Error::MissingData)?;
            let pairs: Vec<(u64, BlockId)> = serde_json::from_str(data)?;
            return Ok(Some(SyncV2Message::PeerBlockHashes(pairs)));
        }
        Ok(None)
    }
}

impl FromStr for SyncV2Message {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (word, payload) = split_word_payload(s)?;
        match <Self as PartialParse>::parse_partial(word, payload)? {
            Some(v) => Ok(v),
            None => Err(Error::InvalidMessageWord),
        }
    }
}

/// Every message that can be accepted in the HELLO state
#[derive(Clone, Debug, PartialEq, derive_more::From)]
pub enum HelloStateMessage {
    Control(ControlMessage),
    Hello(HelloMessage),
}

impl fmt::Display for HelloStateMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HelloStateMessage::Control(m) => write!(f, "{}", m),
            HelloStateMessage::Hello(m) => write!(f, "{}", m),
        }
    }
}

impl PartialParse for HelloStateMessage {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error> {
        if let Some(m) = <ControlMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(HelloStateMessage::Control(m)));
        }
        if let Some(m) = <HelloMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(HelloStateMessage::Hello(m)));
        }
        Ok(None)
    }
}

impl FromStr for HelloStateMessage {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (word, payload) = split_word_payload(s)?;
        match <Self as PartialParse>::parse_partial(word, payload)? {
            Some(v) => Ok(v),
            None => Err(Error::InvalidMessageWord),
        }
    }
}

/// Every message that can be accepted in the PEER-ID state
#[derive(Clone, Debug, PartialEq, derive_more::From)]
pub enum PeerIdStateMessage {
    Control(ControlMessage),
    PeerId(PeerIdMessage),
}

impl fmt::Display for PeerIdStateMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PeerIdStateMessage::Control(m) => write!(f, "{}", m),
            PeerIdStateMessage::PeerId(m) => write!(f, "{}", m),
        }
    }
}

impl PartialParse for PeerIdStateMessage {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error> {
        if let Some(m) = <ControlMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(PeerIdStateMessage::Control(m)));
        }
        if let Some(m) = <PeerIdMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(PeerIdStateMessage::PeerId(m)));
        }
        Ok(None)
    }
}

impl FromStr for PeerIdStateMessage {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (word, payload) = split_word_payload(s)?;
        match <Self as PartialParse>::parse_partial(word, payload)? {
            Some(v) => Ok(v),
            None => Err(Error::InvalidMessageWord),
        }
    }
}

/// Every message that can be accepted in the READY state (assuming sync-v2)
#[derive(Clone, Debug, PartialEq, derive_more::From)]
pub enum ReadyStateMessage {
    Control(ControlMessage),
    Ready(ReadyMessage),
    Sync(SyncV2Message),
}

impl fmt::Display for ReadyStateMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReadyStateMessage::Control(m) => write!(f, "{}", m),
            ReadyStateMessage::Ready(m) => write!(f, "{}", m),
            ReadyStateMessage::Sync(m) => write!(f, "{}", m),
        }
    }
}

impl PartialParse for ReadyStateMessage {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error> {
        if let Some(m) = <ControlMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(ReadyStateMessage::Control(m)));
        }
        if let Some(m) = <ReadyMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(ReadyStateMessage::Ready(m)));
        }
        if let Some(m) = <SyncV2Message as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(ReadyStateMessage::Sync(m)));
        }
        Ok(None)
    }
}

impl FromStr for ReadyStateMessage {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (word, payload) = split_word_payload(s)?;
        match <Self as PartialParse>::parse_partial(word, payload)? {
            Some(v) => Ok(v),
            None => Err(Error::InvalidMessageWord),
        }
    }
}

/// Every message that can be parsed (this helpful for debug tools and tests)
#[derive(Clone, Debug, PartialEq, derive_more::From)]
pub enum AnyStateMessage {
    Control(ControlMessage),
    Hello(HelloMessage),
    PeerId(PeerIdMessage),
    Ready(ReadyMessage),
    Sync(SyncV2Message),
}

impl fmt::Display for AnyStateMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AnyStateMessage::Control(m) => write!(f, "{}", m),
            AnyStateMessage::Hello(m) => write!(f, "{}", m),
            AnyStateMessage::PeerId(m) => write!(f, "{}", m),
            AnyStateMessage::Ready(m) => write!(f, "{}", m),
            AnyStateMessage::Sync(m) => write!(f, "{}", m),
        }
    }
}

impl PartialParse for AnyStateMessage {
    fn parse_partial(word: &str, payload: Option<&str>) -> Result<Option<Self>, Error> {
        if let Some(m) = <ControlMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(AnyStateMessage::Control(m)));
        }
        if let Some(m) = <HelloMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(AnyStateMessage::Hello(m)));
        }
        if let Some(m) = <PeerIdMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(AnyStateMessage::PeerId(m)));
        }
        if let Some(m) = <ReadyMessage as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(AnyStateMessage::Ready(m)));
        }
        if let Some(m) = <SyncV2Message as PartialParse>::parse_partial(word, payload)? {
            return Ok(Some(AnyStateMessage::Sync(m)));
        }
        Ok(None)
    }
}

impl FromStr for AnyStateMessage {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (word, payload) = split_word_payload(s)?;
        match <Self as PartialParse>::parse_partial(word, payload)? {
            Some(v) => Ok(v),
            None => Err(Error::InvalidMessageWord),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_test::{Token, assert_tokens};

    #[test]
    fn ser_de_capability() {
        assert_tokens(
            &Capability::Whitelist,
            &[Token::UnitVariant {
                name: "Capability",
                variant: "whitelist",
            }],
        );
        assert_tokens(
            &Capability::SyncVersion,
            &[Token::UnitVariant {
                name: "Capability",
                variant: "sync-version",
            }],
        );
        assert_tokens(
            &Capability::GetBestBlockchain,
            &[Token::UnitVariant {
                name: "Capability",
                variant: "get-best-blockchain",
            }],
        );
        assert_tokens(
            &Capability::Ipv6,
            &[Token::UnitVariant {
                name: "Capability",
                variant: "ipv6",
            }],
        );
    }

    #[cfg(feature = "transport-quic")]
    #[test]
    fn default_caps_include_quic() {
        let caps = Capability::default_capabilities();
        assert!(
            caps.contains(&Capability::Quic),
            "expected QUIC capability in defaults when feature is enabled"
        );
    }

    #[cfg(not(feature = "transport-quic"))]
    #[test]
    fn default_caps_exclude_quic() {
        let caps = Capability::default_capabilities();
        assert!(
            !caps.contains(&Capability::Quic),
            "QUIC capability should not be advertised when feature is disabled"
        );
    }

    #[test]
    fn parse_format_throttle_and_peers() {
        let m = ControlMessage::Throttle {
            key: ThrottleScope::Global,
            reason: "rate-limit".into(),
        };
        let s = m.to_string();
        assert_eq!(s, "THROTTLE global rate-limit");
        let parsed: ControlMessage = s.parse().unwrap();
        match parsed {
            ControlMessage::Throttle { key, reason } => {
                assert_eq!(key, ThrottleScope::Global);
                assert_eq!(reason, "rate-limit");
            }
            _ => panic!("wrong variant"),
        }

        #[cfg(feature = "crypto-graviola")]
        let params =
            crate::crypto::KeygenParams::Ecdsa(crate::crypto::EcdsaKeygenParams::EcdsaP256Sha256);
        #[cfg(not(feature = "crypto-graviola"))]
        let params: crate::crypto::KeygenParams = Default::default();
        let (_sk, pk) = crate::crypto::gen_keypair(params).expect("gen");
        let peers = vec![UnverifiedPeer {
            peer_id: pk.gen_peer_id(),
            endpoints: vec![],
        }];
        let pmsg = ReadyMessage::Peers(peers.clone().into());
        let s2 = pmsg.to_string();
        let p2: ReadyMessage = s2.parse().unwrap();
        match p2 {
            ReadyMessage::Peers(v) => assert_eq!(v.len(), 1),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn parse_format_all_messages() {
        // Control: ERROR/THROTTLE
        assert_eq!(
            ControlMessage::Error("oops".into()).to_string(),
            "ERROR oops"
        );
        let _: ControlMessage = "ERROR oops".parse().unwrap();
        assert_eq!(
            ControlMessage::Throttle {
                key: ThrottleScope::Global,
                reason: "rate-limit".into()
            }
            .to_string(),
            "THROTTLE global rate-limit"
        );
        let _: ControlMessage = "THROTTLE global rate-limit".parse().unwrap();

        // HELLO / PEER-ID
        let hello = crate::network_info::NETWORK_INFO_TESTNET_HOTEL.make_hello_data();
        let s = HelloMessage::Hello(hello.clone()).to_string();
        assert!(s.starts_with("HELLO "));
        let _: HelloMessage = s.parse().unwrap();
        #[cfg(feature = "crypto-graviola")]
        let params =
            crate::crypto::KeygenParams::Ecdsa(crate::crypto::EcdsaKeygenParams::EcdsaP256Sha256);
        #[cfg(not(feature = "crypto-graviola"))]
        let params: crate::crypto::KeygenParams = Default::default();
        let (_sk2, pk2) = crate::crypto::gen_keypair(params).expect("gen");
        let p = PublicPeer {
            peer_id: pk2.gen_peer_id(),
            pub_key: pk2,
            endpoints: vec![],
        };
        let s = PeerIdMessage::PeerId(p).to_string();
        assert!(s.starts_with("PEER-ID "));
        let _: PeerIdMessage = s.parse().unwrap();
        assert_eq!(PeerIdMessage::Ready.to_string(), "READY");
        let _: PeerIdMessage = "READY".parse().unwrap();

        // READY: GET-PEERS / PEERS / PING / PONG / GET-BEST-BLOCKCHAIN / BEST-BLOCKCHAIN
        assert_eq!(ReadyMessage::GetPeers.to_string(), "GET-PEERS");
        let _: ReadyMessage = "GET-PEERS".parse().unwrap();
        let peers: Vec<UnverifiedPeer> = vec![];
        let s = ReadyMessage::Peers(peers.clone().into()).to_string();
        assert!(s.starts_with("PEERS "));
        assert!(matches!(
            s.parse::<ReadyMessage>().unwrap(),
            ReadyMessage::Peers(v) if v.as_slice()==peers.as_slice()
        ));
        assert_eq!(ReadyMessage::Ping("abc".into()).to_string(), "PING abc");
        let _: ReadyMessage = "PING abc".parse().unwrap();
        assert_eq!(ReadyMessage::Pong("abc".into()).to_string(), "PONG abc");
        let _: ReadyMessage = "PONG abc".parse().unwrap();
        assert_eq!(
            ReadyMessage::GetBestBlockchain(None).to_string(),
            "GET-BEST-BLOCKCHAIN"
        );
        assert_eq!(
            ReadyMessage::GetBestBlockchain(Some(10)).to_string(),
            "GET-BEST-BLOCKCHAIN 10"
        );
        assert!(matches!(
            "GET-BEST-BLOCKCHAIN 10".parse::<ReadyMessage>().unwrap(),
            ReadyMessage::GetBestBlockchain(Some(10))
        ));

        // Sync v2: GET-BEST-BLOCK / GET-NEXT-BLOCKS / BLOCKS / BLOCKS-END / STOP-BLOCK-STREAMING
        assert_eq!(SyncV2Message::GetBestBlock.to_string(), "GET-BEST-BLOCK");
        let _: SyncV2Message = "GET-BEST-BLOCK".parse().unwrap();
        let req = NextBlocksReq {
            start_hash: (&[0u8; 32][..]).try_into().unwrap(),
            end_hash: (&[1u8; 32][..]).try_into().unwrap(),
            quantity: 100,
        };
        let s = SyncV2Message::GetNextBlocks(req.clone()).to_string();
        assert!(s.starts_with("GET-NEXT-BLOCKS "));
        assert!(
            matches!(s.parse::<SyncV2Message>().unwrap(), SyncV2Message::GetNextBlocks(r) if r==req)
        );
        // BLOCKS round-trip with real AnyBlockData (base64 payload)
        let gb = crate::vertex::GenesisBlockData {
            outputs: vec![],
            weight: crate::vertex::Weight::new(1.0).unwrap(),
            timestamp: crate::vertex::Timestamp(1),
            nonce: 0u128,
        };
        let blocks_msg = SyncV2Message::Blocks(crate::vertex::AnyBlockData::from(gb));
        let s_blocks = blocks_msg.to_string();
        assert!(s_blocks.starts_with("BLOCKS "));
        let parsed_blocks: SyncV2Message = s_blocks.parse().unwrap();
        assert_eq!(parsed_blocks, blocks_msg);
        assert_eq!(
            SyncV2Message::BlocksEnd(StreamEnd::LimitExceeded).to_string(),
            "BLOCKS-END 2"
        );
        let _: SyncV2Message = "BLOCKS-END 2".parse().unwrap();
        assert_eq!(
            SyncV2Message::StopBlockStreaming.to_string(),
            "STOP-BLOCK-STREAMING"
        );
        let _: SyncV2Message = "STOP-BLOCK-STREAMING".parse().unwrap();

        // Transactions BFS
        let bfs = TransactionsBfsReq {
            start_from: vec![(&[2u8; 32][..]).try_into().unwrap()],
            first_block_hash: (&[3u8; 32][..]).try_into().unwrap(),
            last_block_hash: (&[4u8; 32][..]).try_into().unwrap(),
        };
        let s = SyncV2Message::GetTransactionsBfs(bfs.clone()).to_string();
        assert!(s.starts_with("GET-TRANSACTIONS-BFS "));
        assert!(
            matches!(s.parse::<SyncV2Message>().unwrap(), SyncV2Message::GetTransactionsBfs(x) if x==bfs)
        );
        // TRANSACTION round-trip with real AnyTransactionData (base64 payload)
        let outputs = vec![crate::vertex::TxOutput {
            value: core::num::NonZero::new(1u64).unwrap(),
            token_data: 0,
            script: bytes::Bytes::new(),
        }];
        let gt = crate::vertex::GenesisTransactionData {
            outputs,
            weight: crate::vertex::Weight::new(0.5).unwrap(),
            timestamp: crate::vertex::Timestamp(1),
            nonce: 1u32,
        };
        let tx_msg = SyncV2Message::Transaction(crate::vertex::AnyTransactionData::from(gt));
        let s_tx = tx_msg.to_string();
        assert!(s_tx.starts_with("TRANSACTION "));
        let parsed_tx: SyncV2Message = s_tx.parse().unwrap();
        assert_eq!(parsed_tx, tx_msg);
        assert_eq!(
            SyncV2Message::TransactionsEnd(StreamEnd::PerRequest).to_string(),
            "TRANSACTIONS-END 7"
        );
        let _: SyncV2Message = "TRANSACTIONS-END 7".parse().unwrap();
        assert_eq!(
            SyncV2Message::StopTransactionsStreaming.to_string(),
            "STOP-TRANSACTIONS-STREAMING"
        );
        let _: SyncV2Message = "STOP-TRANSACTIONS-STREAMING".parse().unwrap();

        // GET-TIPS / TIPS / TIPS-END
        assert_eq!(SyncV2Message::GetTips.to_string(), "GET-TIPS");
        let _: SyncV2Message = "GET-TIPS".parse().unwrap();
        let tips: Vec<TransactionId> = vec![
            (&[5u8; 32][..]).try_into().unwrap(),
            (&[6u8; 32][..]).try_into().unwrap(),
        ];
        let s = SyncV2Message::Tips(tips.clone()).to_string();
        assert!(s.starts_with("TIPS "));
        assert!(matches!(s.parse::<SyncV2Message>().unwrap(), SyncV2Message::Tips(v) if v==tips));
        assert_eq!(SyncV2Message::TipsEnd.to_string(), "TIPS-END");
        let _: SyncV2Message = "TIPS-END".parse().unwrap();

        // GET-DATA / DATA / NOT-FOUND / RELAY
        let gd = GetDataReq {
            txid: (&[7u8; 32][..]).try_into().unwrap(),
            origin: Some(DataOrigin::Mempool),
        };
        let s = SyncV2Message::GetData(gd.clone()).to_string();
        assert!(s.starts_with("GET-DATA "));
        assert!(matches!(s.parse::<SyncV2Message>().unwrap(), SyncV2Message::GetData(x) if x==gd));
        // DATA round-trip (without and with origin)
        let v_block = crate::vertex::AnyVertexData::from(crate::vertex::GenesisBlockData {
            outputs: vec![],
            weight: crate::vertex::Weight::new(1.0).unwrap(),
            timestamp: crate::vertex::Timestamp(2),
            nonce: 0u128,
        });
        let data_msg1 = SyncV2Message::Data {
            vertex: v_block.clone(),
            origin: None,
        };
        let s_data1 = data_msg1.to_string();
        assert!(s_data1.starts_with("DATA "));
        let parsed_data1: SyncV2Message = s_data1.parse().unwrap();
        assert_eq!(parsed_data1, data_msg1);
        let data_msg2 = SyncV2Message::Data {
            vertex: v_block,
            origin: Some(DataOrigin::Mempool),
        };
        let s_data2 = data_msg2.to_string();
        assert!(s_data2.starts_with("DATA mempool "));
        let parsed_data2: SyncV2Message = s_data2.parse().unwrap();
        assert_eq!(parsed_data2, data_msg2);
        // NOT-FOUND now carries VertexId
        let vid = crate::vertex::VertexId(crate::common::Hash32([0xAB; 32]));
        assert_eq!(
            SyncV2Message::NotFound(vid).to_string(),
            format!(
                "NOT-FOUND {}",
                crate::vertex::VertexId(crate::common::Hash32([0xAB; 32]))
            )
        );
        let s_nf = format!(
            "NOT-FOUND {}",
            crate::vertex::VertexId(crate::common::Hash32([0xCD; 32]))
        );
        let _: SyncV2Message = s_nf.parse().unwrap();
        assert_eq!(SyncV2Message::Relay(None).to_string(), "RELAY");
        assert!(matches!(
            "RELAY".parse::<SyncV2Message>().unwrap(),
            SyncV2Message::Relay(None)
        ));
        assert_eq!(SyncV2Message::Relay(Some(true)).to_string(), "RELAY true");
        assert!(matches!(
            "RELAY true".parse::<SyncV2Message>().unwrap(),
            SyncV2Message::Relay(Some(true))
        ));

        // GET-PEER-BLOCK-HASHES / PEER-BLOCK-HASHES
        let heights = vec![1u64, 2, 3];
        let s = SyncV2Message::GetPeerBlockHashes(heights.clone()).to_string();
        assert!(s.starts_with("GET-PEER-BLOCK-HASHES "));
        assert!(
            matches!(s.parse::<SyncV2Message>().unwrap(), SyncV2Message::GetPeerBlockHashes(v) if v==heights)
        );
        let pairs = vec![
            (100u64, (&[8u8; 32][..]).try_into().unwrap()),
            (101u64, (&[9u8; 32][..]).try_into().unwrap()),
        ];
        let s = SyncV2Message::PeerBlockHashes(pairs.clone()).to_string();
        assert!(s.starts_with("PEER-BLOCK-HASHES "));
        assert!(
            matches!(s.parse::<SyncV2Message>().unwrap(), SyncV2Message::PeerBlockHashes(v) if v==pairs)
        );
    }
}
