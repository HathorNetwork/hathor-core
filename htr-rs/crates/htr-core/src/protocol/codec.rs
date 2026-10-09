// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::protocol::message::{
    HelloStateMessage, PartialParse, PeerIdStateMessage, ReadyStateMessage,
};
use tokio_util::bytes::{Bytes, BytesMut};
use tokio_util::codec::{Decoder, Encoder};

// removed old MessagesCodec (use stateful codecs + CommandCodec instead)

// Stateful codecs: decode/encode only the messages valid in a given state

#[derive(Clone, Debug)]
struct MessageBytes {
    word: Bytes,
    payload: Option<Bytes>,
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
struct MessageCodec {
    max_length: usize,
}

impl MessageCodec {
    pub fn new() -> Self {
        Self {
            max_length: MAX_LINE_LENGTH,
        }
    }
}

impl Decoder for MessageCodec {
    type Item = MessageBytes;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        // Fast-path: find LF
        let lf_pos = match buf.iter().take(self.max_length).position(|&b| b == b'\n') {
            Some(i) => i,
            None => {
                if buf.len() > self.max_length {
                    return Err(Error::MaxLineLengthExceeded);
                }
                return Ok(None);
            }
        };

        // Enforce length (excluding delimiter) and split frame [0..=lf]
        let mut content_end = lf_pos;
        if content_end > 0 && buf[content_end - 1] == b'\r' {
            content_end -= 1;
        }
        if content_end > self.max_length {
            return Err(Error::MaxLineLengthExceeded);
        }

        let line = buf.split_to(lf_pos + 1).freeze();
        let line_end = content_end; // relative to line (same index)
        let data = &line[..line_end];

        // ASCII validation (cheaper than UTF-8)
        if !data.is_ascii() {
            return Err(Error::InvalidEncoding);
        }

        // Find word start (skip leading spaces like previous trim())
        let mut word_start = 0;
        while word_start < data.len() && data[word_start] == b' ' {
            word_start += 1;
        }
        if word_start >= data.len() {
            return Err(Error::InvalidMessageWord);
        }

        // Find first space after the word
        let rest = &data[word_start..];
        let word_rel_end = match rest.iter().position(|&b| b == b' ') {
            Some(p) => p + word_start,
            None => line_end,
        };
        let payload_start = if word_rel_end < line_end {
            Some(word_rel_end + 1)
        } else {
            None
        };

        {
            let line = line.slice(word_start..line_end);
            trace!(?line, "decode");
        }
        let word = line.slice(word_start..word_rel_end);
        let payload = payload_start.map(|i| line.slice(i..line_end));
        Ok(Some(MessageBytes { word, payload }))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct HelloCodec {
    split: MessageCodec,
}

impl HelloCodec {
    pub fn new() -> Self {
        HelloCodec {
            split: MessageCodec::new(),
        }
    }
}

impl Decoder for HelloCodec {
    type Item = HelloStateMessage;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let cmd = match self.split.decode(buf)? {
            Some(c) => c,
            None => return Ok(None),
        };
        // Safety: MessageCodec enforces ASCII, which is valid UTF-8
        let word = unsafe { std::str::from_utf8_unchecked(&cmd.word) };
        let payload = cmd
            .payload
            .as_ref()
            .map(|b| unsafe { std::str::from_utf8_unchecked(b) });
        let msg = <HelloStateMessage as PartialParse>::parse_partial(word, payload)?
            .ok_or(Error::InvalidMessageWord)?;
        Ok(Some(msg))
    }
}

impl Encoder<HelloStateMessage> for HelloCodec {
    type Error = Error;

    fn encode(&mut self, msg: HelloStateMessage, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let line_str = msg.to_string();
        let line = line_str.as_bytes();
        trace!(?line, "encode");
        buf.extend_from_slice(line);
        buf.extend_from_slice(b"\r\n");
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct PeerIdCodec {
    split: MessageCodec,
}

impl PeerIdCodec {
    pub fn new() -> Self {
        PeerIdCodec {
            split: MessageCodec::new(),
        }
    }
}

impl Decoder for PeerIdCodec {
    type Item = PeerIdStateMessage;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let cmd = match self.split.decode(buf)? {
            Some(c) => c,
            None => return Ok(None),
        };
        // Safety: MessageCodec enforces ASCII, which is valid UTF-8
        let word = unsafe { std::str::from_utf8_unchecked(&cmd.word) };
        let payload = cmd
            .payload
            .as_ref()
            .map(|b| unsafe { std::str::from_utf8_unchecked(b) });
        let msg = <PeerIdStateMessage as PartialParse>::parse_partial(word, payload)?
            .ok_or(Error::InvalidMessageWord)?;
        Ok(Some(msg))
    }
}

impl Encoder<PeerIdStateMessage> for PeerIdCodec {
    type Error = Error;

    fn encode(&mut self, msg: PeerIdStateMessage, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let line_str = msg.to_string();
        let line = line_str.as_bytes();
        trace!(?line, "encode");
        buf.extend_from_slice(line);
        buf.extend_from_slice(b"\r\n");
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ReadyCodec {
    split: MessageCodec,
}

impl ReadyCodec {
    pub fn new() -> Self {
        ReadyCodec {
            split: MessageCodec::new(),
        }
    }
}

impl Decoder for ReadyCodec {
    type Item = ReadyStateMessage;
    type Error = Error;

    fn decode(&mut self, buf: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let cmd = match self.split.decode(buf)? {
            Some(c) => c,
            None => return Ok(None),
        };
        // Safety: MessageCodec enforces ASCII, which is valid UTF-8
        let word = unsafe { std::str::from_utf8_unchecked(&cmd.word) };
        let payload = cmd
            .payload
            .as_ref()
            .map(|b| unsafe { std::str::from_utf8_unchecked(b) });
        let msg = <ReadyStateMessage as PartialParse>::parse_partial(word, payload)?
            .ok_or(Error::InvalidMessageWord)?;
        Ok(Some(msg))
    }
}

impl Encoder<ReadyStateMessage> for ReadyCodec {
    type Error = Error;

    fn encode(&mut self, msg: ReadyStateMessage, buf: &mut BytesMut) -> Result<(), Self::Error> {
        let line_str = msg.to_string();
        let line = line_str.as_bytes();
        trace!(?line, "encode");
        buf.extend_from_slice(line);
        buf.extend_from_slice(b"\r\n");
        Ok(())
    }
}
