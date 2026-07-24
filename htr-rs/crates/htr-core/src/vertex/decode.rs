// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::vertex::header::{FeeHeader, FeeHeaderEntry, NanoHeader, NanoHeaderAction};
use typed_floats::InvalidNumber;

type Result<T> = std::result::Result<T, DecodeError>;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum DecodeError {
    #[error("incomplete input: need {0}")]
    Incomplete(usize),
    #[error("invalid value encoding")]
    InvalidValueEncoding,
    #[error("invalid parents length")]
    InvalidParentsLen(usize),
    #[error("invalid id length")]
    IdLength,
    #[error("parse error")]
    Parse,
    #[error("unexpected trailing bytes")]
    Trailing,
    #[error("unexpected kind")]
    UnexpectedKind(Kind),
    #[error("invalid byte: {0}")]
    InvalidByte(u8),
    #[error("invalid float: {0}")]
    InvalidFloat(#[from] InvalidNumber),
    #[error("invalid value: {0}")]
    InvalidValue(#[from] std::num::TryFromIntError),
    #[error("invalid UTF-8: {0}")]
    InvalidUtf8(#[from] std::str::Utf8Error),
}

impl From<derive_more::TryFromReprError<u8>> for DecodeError {
    fn from(e: derive_more::TryFromReprError<u8>) -> Self {
        DecodeError::InvalidByte(e.input)
    }
}

impl From<bytes::TryGetError> for DecodeError {
    fn from(e: bytes::TryGetError) -> Self {
        let missing = e.requested.saturating_sub(e.available);
        DecodeError::Incomplete(missing.max(1))
    }
}

impl From<std::string::FromUtf8Error> for DecodeError {
    fn from(e: std::string::FromUtf8Error) -> Self {
        e.utf8_error().into()
    }
}

impl<const N: usize> From<smallstr::FromUtf8Error<[u8; N]>> for DecodeError {
    fn from(e: smallstr::FromUtf8Error<[u8; N]>) -> Self {
        e.utf8_error().into()
    }
}

// parents data as found in a transaction
type TxParentsData = [TransactionId; 2];

// parents data as found in a block
type BlockParentsData = (BlockId, [TransactionId; 2]);

#[derive(derive_more::From)]
enum RegularTransactionBody {
    Genesis(GenesisTransactionData),
    Regular(RegularTransactionData),
}

impl From<RegularTransactionBody> for AnyTransactionData {
    fn from(body: RegularTransactionBody) -> Self {
        match body {
            RegularTransactionBody::Genesis(data) => data.into(),
            RegularTransactionBody::Regular(data) => data.into(),
        }
    }
}

impl From<RegularTransactionBody> for AnyVertexData {
    fn from(body: RegularTransactionBody) -> Self {
        AnyVertexData::Transaction(body.into())
    }
}

#[derive(derive_more::From)]
enum RegularBlockBody {
    Genesis(GenesisBlockData),
    Regular(RegularBlockData),
}

impl From<RegularBlockBody> for AnyBlockData {
    fn from(body: RegularBlockBody) -> Self {
        match body {
            RegularBlockBody::Genesis(data) => data.into(),
            RegularBlockBody::Regular(data) => data.into(),
        }
    }
}

impl From<RegularBlockBody> for AnyVertexData {
    fn from(body: RegularBlockBody) -> Self {
        AnyVertexData::Block(body.into())
    }
}

trait VertexDecodeExt: Buf {
    fn finish(&self) -> Result<()> {
        if self.has_remaining() {
            Err(DecodeError::Trailing)
        } else {
            Ok(())
        }
    }

    fn try_get_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let mut array = [0u8; N];
        self.try_copy_to_slice(&mut array)?;
        Ok(array)
    }

    fn decode_len_u8(&mut self) -> Result<usize> {
        Ok(self.try_get_u8()? as usize)
    }

    fn decode_len_u16(&mut self) -> Result<usize> {
        Ok(self.try_get_u16()? as usize)
    }

    fn decode_signal_bits(&mut self) -> Result<SignalBits> {
        Ok(SignalBits(self.try_get_u8()?))
    }

    fn decode_kind(&mut self) -> Result<Kind> {
        Ok(self.try_get_u8()?.try_into()?)
    }

    fn decode_vertex_id(&mut self) -> Result<VertexId> {
        Ok(VertexId(self.decode_hash()?))
    }

    fn decode_hash(&mut self) -> Result<Hash32> {
        Ok(Hash32(self.try_get_array()?))
    }

    fn decode_token_uid(&mut self) -> Result<TokenUid> {
        Ok(TokenUid(self.decode_hash()?))
    }

    fn decode_token_uid_vec(&mut self, tokens_len: usize) -> Result<Vec<TokenUid>> {
        let mut tokens: Vec<TokenUid> = Vec::with_capacity(tokens_len);
        for _ in 0..tokens_len {
            tokens.push(self.decode_token_uid()?);
        }
        Ok(tokens)
    }

    fn decode_block_id(&mut self) -> Result<BlockId> {
        Ok(BlockId(self.decode_vertex_id()?))
    }

    fn decode_transaction_id(&mut self) -> Result<TransactionId> {
        Ok(TransactionId(self.decode_vertex_id()?))
    }

    fn decode_bytes_u8(&mut self) -> Result<Bytes> {
        let data_len = self.decode_len_u8()?;
        let mut data = BytesMut::zeroed(data_len);
        self.try_copy_to_slice(data.as_mut())?;
        Ok(data.freeze())
    }

    fn decode_smallstr_u8<const N: usize>(&mut self) -> Result<SmallString<[u8; N]>> {
        let data_len = self.decode_len_u8()?;
        if data_len > 4 * N {
            return Err(DecodeError::Parse);
        }
        Ok(if data_len == 0 {
            SmallString::new()
        } else if data_len <= N {
            // read exactly data_len bytes, then construct from &str
            let mut tmp = [0u8; N];
            let (head, _) = tmp.split_at_mut(data_len);
            self.try_copy_to_slice(head)?;
            SmallString::from_str(std::str::from_utf8(head)?)
        } else {
            // read into a heap buffer of the exact size
            let mut data = vec![0u8; data_len];
            self.try_copy_to_slice(&mut data)?;
            SmallString::from_string(String::from_utf8(data)?)
        })
    }

    fn decode_bytes_u16(&mut self) -> Result<Bytes> {
        let data_len = self.decode_len_u16()?;
        let mut data = BytesMut::zeroed(data_len);
        self.try_copy_to_slice(data.as_mut())?;
        Ok(data.freeze())
    }

    fn decode_bytes_u32(&mut self) -> Result<Bytes> {
        let data_len = self.try_get_u32()? as usize;
        let mut data = BytesMut::zeroed(data_len);
        if data_len > 0 {
            self.try_copy_to_slice(data.as_mut())?;
        }
        Ok(data.freeze())
    }

    // Unsigned LEB128 with a byte-limit to guard against malformed inputs.
    fn decode_uleb128_limited(&mut self, max_bytes: usize) -> Result<u64> {
        let mut result: u64 = 0;
        let mut shift = 0u32;
        for _i in 0..max_bytes {
            let byte = self.try_get_u8()?;
            let value = (byte & 0x7F) as u64;
            result |= value.checked_shl(shift).ok_or(DecodeError::Parse)?;
            if (byte & 0x80) == 0 {
                return Ok(result);
            }
            shift += 7;
            if shift >= 64 {
                return Err(DecodeError::Parse);
            }
            // continue loop if continuation bit set
            // ensure we don't exceed max_bytes; if i == max_bytes-1 we already consumed last allowed byte
        }
        Err(DecodeError::Parse)
    }

    fn decode_uleb128_u64(&mut self) -> Result<u64> {
        // seqnum allows up to 8 bytes
        self.decode_uleb128_limited(8)
    }

    fn decode_uleb128_u16(&mut self) -> Result<u16> {
        // script len is limited to 2 bytes LEB128
        let v = self.decode_uleb128_limited(2)?;
        Ok(v.try_into()?)
    }

    fn decode_tx_input(&mut self) -> Result<TxInput> {
        let tx_id = self.decode_transaction_id()?;
        let index = self.try_get_u8()?;
        let data = self.decode_bytes_u16()?;
        Ok(TxInput { tx_id, index, data })
    }

    fn decode_tx_input_vec(&mut self, inputs_len: usize) -> Result<Vec<TxInput>> {
        let mut inputs = Vec::with_capacity(inputs_len);
        for _ in 0..inputs_len {
            inputs.push(self.decode_tx_input()?);
        }
        Ok(inputs)
    }

    fn try_peek_u8(&mut self) -> Result<u8> {
        Ok(*self.chunk().first().ok_or(DecodeError::Incomplete(1))?)
    }

    fn decode_output_value(&mut self) -> Result<OutputValue> {
        let first = self.try_peek_u8()?;
        let value = if (first & 0x80) != 0 {
            -(self.try_get_i64()?) as u64
        } else {
            self.try_get_u32()? as u64
        };
        Ok(value.try_into()?)
    }

    fn decode_tx_output(&mut self) -> Result<TxOutput> {
        let value = self.decode_output_value()?;
        let token_data = self.try_get_u8()?;
        let script = self.decode_bytes_u16()?;
        Ok(TxOutput {
            value,
            token_data,
            script,
        })
    }

    fn decode_tx_output_vec(&mut self, outputs_len: usize) -> Result<Vec<TxOutput>> {
        let mut outputs = Vec::with_capacity(outputs_len);
        for _ in 0..outputs_len {
            outputs.push(self.decode_tx_output()?);
        }
        Ok(outputs)
    }
    fn decode_address(&mut self) -> Result<crate::common::Address> {
        let mut arr = [0u8; 25];
        self.try_copy_to_slice(&mut arr)?;
        Ok(crate::common::Address(arr))
    }

    fn decode_nano_header(&mut self) -> Result<AnyHeader> {
        // VertexId (32 bytes)
        let id = self.decode_vertex_id()?;
        // seqnum (ULEB128, up to 8 bytes)
        let seqnum = self.decode_uleb128_u64()?;
        // method (u8 len + bytes)
        let method_bytes = self.decode_bytes_u8()?;
        let method = std::str::from_utf8(&method_bytes)?.to_owned();
        // args (u16 len + bytes)
        let args = self.decode_bytes_u16()?;
        // actions
        let actions_len = self.decode_len_u8()?;
        let mut actions = Vec::with_capacity(actions_len);
        for _ in 0..actions_len {
            let action_type = self.try_get_u8()?;
            let index = self.try_get_u8()?;
            match action_type {
                1 => {
                    // Deposit: amount as output-value
                    let amount = self.decode_output_value()?;
                    actions.push(NanoHeaderAction::Deposit { index, amount });
                }
                2 => {
                    // Withdrawal: amount as output-value
                    let amount = self.decode_output_value()?;
                    actions.push(NanoHeaderAction::Withdrawal { index, amount });
                }
                3 | 4 => {
                    // Authorities: encoded in low bits of the value using same encoding
                    let flags = self.decode_output_value()?.get();
                    if flags == 0 || flags > 3 {
                        return Err(DecodeError::Parse);
                    }
                    let mint = (flags & 0x01) != 0;
                    let melt = (flags & 0x02) != 0;
                    if action_type == 3 {
                        actions.push(NanoHeaderAction::GrantAuthority { index, mint, melt });
                    } else {
                        actions.push(NanoHeaderAction::AcquireAuthority { index, mint, melt });
                    }
                }
                _ => return Err(DecodeError::Parse),
            }
        }
        // address (25 bytes)
        let address = self.decode_address()?;
        // script (ULEB128 up to 2 bytes)
        let script_len = self.decode_uleb128_u16()? as usize;
        let mut script = BytesMut::zeroed(script_len);
        if script_len > 0 {
            self.try_copy_to_slice(script.as_mut())?;
        }
        let script = script.freeze();
        Ok(AnyHeader::Nano(NanoHeader {
            seqnum,
            id,
            method,
            args,
            actions,
            address,
            script,
        }))
    }

    fn decode_fee_header(&mut self) -> Result<AnyHeader> {
        let count = self.decode_len_u8()?;
        let mut fees = Vec::with_capacity(count);
        for _ in 0..count {
            let token = self.decode_token_uid()?;
            let amount = self.decode_output_value()?;
            fees.push(FeeHeaderEntry { token, amount });
        }
        Ok(AnyHeader::Fee(FeeHeader { fees }))
    }

    fn decode_headers_vec(&mut self) -> Result<Vec<AnyHeader>> {
        let mut headers = Vec::new();
        while self.has_remaining() {
            if headers.len() >= 2 {
                return Err(DecodeError::Parse);
            }
            let kind: HeaderKind = self.try_get_u8()?.try_into()?;
            match kind {
                HeaderKind::Nano => headers.push(self.decode_nano_header()?),
                HeaderKind::Fee => headers.push(self.decode_fee_header()?),
            }
        }
        Ok(headers)
    }

    fn decode_weight(&mut self) -> Result<Weight> {
        Ok(self.try_get_f64()?.try_into()?)
    }

    fn decode_timestamp(&mut self) -> Result<Timestamp> {
        Ok(Timestamp(self.try_get_u32()?))
    }

    fn decode_tx_parents2(&mut self) -> Result<TxParentsData> {
        Ok([self.decode_transaction_id()?, self.decode_transaction_id()?])
    }

    fn decode_token_kind(&mut self) -> Result<TokenKind> {
        Ok(self.try_get_u8()?.try_into()?)
    }

    fn decode_ocb_kind(&mut self) -> Result<OcbKind> {
        Ok(self.try_get_u8()?.try_into()?)
    }

    fn decode_tx_parents_opt(&mut self) -> Result<Option<TxParentsData>> {
        let parents_len = self.decode_len_u8()?;
        Ok(match parents_len {
            0 => None,
            2 => Some(self.decode_tx_parents2()?),
            len => {
                return Err(DecodeError::InvalidParentsLen(len));
            }
        })
    }

    fn decode_tx_funds_data(&mut self) -> Result<(Vec<TokenUid>, Vec<TxInput>, Vec<TxOutput>)> {
        let tokens_len = self.decode_len_u8()?;
        let inputs_len = self.decode_len_u8()?;
        let outputs_len = self.decode_len_u8()?;
        let tokens = self.decode_token_uid_vec(tokens_len)?;
        let inputs = self.decode_tx_input_vec(inputs_len)?;
        let outputs = self.decode_tx_output_vec(outputs_len)?;
        Ok((tokens, inputs, outputs))
    }

    fn decode_tx_graph_data(&mut self) -> Result<(Weight, Timestamp, Option<TxParentsData>)> {
        let weight = self.decode_weight()?;
        let timestamp = self.decode_timestamp()?;
        let parents = self.decode_tx_parents_opt()?;
        Ok((weight, timestamp, parents))
    }

    fn decode_regular_transaction_body(
        &mut self,
        signal_bits: SignalBits,
    ) -> Result<RegularTransactionBody> {
        let (tokens, inputs, outputs) = self.decode_tx_funds_data()?;
        let (weight, timestamp, parents) = self.decode_tx_graph_data()?;
        let nonce = self.try_get_u32()?;
        let headers = self.decode_headers_vec()?;
        self.finish()?;

        Ok(if let Some(tx_parents) = parents {
            RegularTransactionData {
                signal_bits,
                tokens,
                inputs,
                outputs,
                weight,
                timestamp,
                tx_parents,
                nonce,
                headers,
            }
            .into()
        } else {
            if !inputs.is_empty() || signal_bits.0 != 0x00 {
                return Err(DecodeError::Parse);
            }
            GenesisTransactionData {
                outputs,
                weight,
                timestamp,
                nonce,
            }
            .into()
        })
    }

    fn decode_token_creation_transaction_body(
        &mut self,
        signal_bits: SignalBits,
    ) -> Result<TokenCreationTransactionData> {
        // Funds: inputs_len, outputs_len
        let inputs_len = self.decode_len_u8()?;
        let outputs_len = self.decode_len_u8()?;
        let inputs = self.decode_tx_input_vec(inputs_len)?;
        let outputs = self.decode_tx_output_vec(outputs_len)?;
        // token info
        let token_kind = self.decode_token_kind()?;
        let name = self.decode_smallstr_u8()?;
        let symbol = self.decode_smallstr_u8()?;
        // Graph
        let (weight, timestamp, parents) = self.decode_tx_graph_data()?;
        let Some(tx_parents) = parents else {
            return Err(DecodeError::InvalidParentsLen(0));
        };
        let nonce = self.try_get_u32()?;
        let headers = self.decode_headers_vec()?;
        self.finish()?;
        Ok(TokenCreationTransactionData {
            signal_bits,
            inputs,
            outputs,
            token_kind,
            name,
            symbol,
            weight,
            timestamp,
            tx_parents,
            nonce,
            headers,
        })
    }

    fn decode_on_chain_blueprint_body(
        &mut self,
        signal_bits: SignalBits,
    ) -> Result<OnChainBlueprintData> {
        // Funds: tokens_len, inputs_len, outputs_len
        let tokens_len = self.decode_len_u8()?;
        let inputs_len = self.decode_len_u8()?;
        let outputs_len = self.decode_len_u8()?;
        let tokens = self.decode_token_uid_vec(tokens_len)?;
        let inputs = self.decode_tx_input_vec(inputs_len)?;
        let outputs = self.decode_tx_output_vec(outputs_len)?;
        // OCB extras
        let ocb_kind = self.decode_ocb_kind()?;
        let code = self.decode_bytes_u32()?;
        let nc_pubkey = self.decode_bytes_u8()?;
        let nc_signature = self.decode_bytes_u8()?;
        // Graph
        let (weight, timestamp, parents) = self.decode_tx_graph_data()?;
        let Some(tx_parents) = parents else {
            return Err(DecodeError::InvalidParentsLen(0));
        };
        let nonce = self.try_get_u32()?;
        let headers = self.decode_headers_vec()?;
        self.finish()?;
        Ok(OnChainBlueprintData {
            signal_bits,
            tokens,
            inputs,
            outputs,
            ocb_kind,
            code,
            nc_pubkey,
            nc_signature,
            weight,
            timestamp,
            tx_parents,
            nonce,
            headers,
        })
    }

    fn decode_any_transaction_data(&mut self) -> Result<AnyTransactionData> {
        let signal_bits = self.decode_signal_bits()?;
        Ok(match self.decode_kind()? {
            Kind::RegularTransaction => self.decode_regular_transaction_body(signal_bits)?.into(),
            Kind::TokenCreationTransaction => self
                .decode_token_creation_transaction_body(signal_bits)?
                .into(),
            Kind::OnChainBlueprint => self.decode_on_chain_blueprint_body(signal_bits)?.into(),
            kind => {
                return Err(DecodeError::UnexpectedKind(kind));
            }
        })
    }

    fn decode_block_funds_data(&mut self) -> Result<Vec<TxOutput>> {
        let outputs_len = self.decode_len_u8()?;
        let outputs = self.decode_tx_output_vec(outputs_len)?;
        Ok(outputs)
    }

    fn decode_block_parents_opt(&mut self) -> Result<Option<BlockParentsData>> {
        let parents_len = self.decode_len_u8()?;
        Ok(match parents_len {
            0 => None,
            3 => Some((self.decode_block_id()?, self.decode_tx_parents2()?)),
            len => {
                return Err(DecodeError::InvalidParentsLen(len));
            }
        })
    }

    fn decode_block_graph_data(
        &mut self,
    ) -> Result<(Weight, Timestamp, Option<BlockParentsData>, Bytes)> {
        let weight = self.decode_weight()?;
        let timestamp = self.decode_timestamp()?;
        let parents = self.decode_block_parents_opt()?;
        let data = self.decode_bytes_u8()?;
        Ok((weight, timestamp, parents, data))
    }

    fn decode_varint(&mut self) -> Result<u64> {
        let tag = self.try_get_u8()?;
        Ok(match tag {
            t if t < 0xFD => t as u64,
            0xFD => {
                let mut b = [0u8; 2];
                self.try_copy_to_slice(&mut b)?;
                u16::from_le_bytes(b) as u64
            }
            0xFE => {
                let mut b = [0u8; 4];
                self.try_copy_to_slice(&mut b)?;
                u32::from_le_bytes(b) as u64
            }
            _ => {
                let mut b = [0u8; 8];
                self.try_copy_to_slice(&mut b)?;
                u64::from_le_bytes(b)
            }
        })
    }

    fn decode_varbytes(&mut self) -> Result<Bytes> {
        let len = self.decode_varint()? as usize;
        let mut data = BytesMut::zeroed(len);
        if len > 0 {
            self.try_copy_to_slice(data.as_mut())?;
        }
        Ok(data.freeze())
    }

    fn decode_merkle_path(&mut self) -> Result<Vec<Hash32>> {
        let len = self.decode_varint()? as usize;
        if len > MAX_MERKLE_PATH_LEN {
            return Err(DecodeError::Parse);
        }
        let mut merkle_path = Vec::with_capacity(len);
        for _ in 0..len {
            merkle_path.push(self.decode_hash()?);
        }
        Ok(merkle_path)
    }

    fn decode_auxpow(&mut self) -> Result<AuxPow> {
        let header_head = self.try_get_array::<36>()?;
        let coinbase_head = self.decode_varbytes()?;
        let coinbase_tail = self.decode_varbytes()?;
        let merkle_path = self.decode_merkle_path()?;
        let header_tail = self.try_get_array::<12>()?;
        Ok(AuxPow {
            header_head,
            coinbase_head,
            coinbase_tail,
            merkle_path,
            header_tail,
        })
    }

    fn decode_regular_block_body(&mut self, signal_bits: SignalBits) -> Result<RegularBlockBody> {
        let outputs = self.decode_block_funds_data()?;
        let (weight, timestamp, parents, data) = self.decode_block_graph_data()?;
        let nonce = self.try_get_u128()?;
        self.finish()?;

        Ok(if let Some((block_parent, tx_parents)) = parents {
            RegularBlockData {
                signal_bits,
                outputs,
                weight,
                timestamp,
                block_parent,
                tx_parents,
                data,
                nonce,
            }
            .into()
        } else {
            if !data.is_empty() || signal_bits.0 != 0x00 {
                return Err(DecodeError::Parse);
            }
            GenesisBlockData {
                outputs,
                weight,
                timestamp,
                nonce,
            }
            .into()
        })
    }

    fn decode_merge_mined_block_body(
        &mut self,
        signal_bits: SignalBits,
    ) -> Result<MergeMinedBlockData> {
        let outputs = self.decode_block_funds_data()?;
        let (weight, timestamp, parents, data) = self.decode_block_graph_data()?;
        let Some((block_parent, tx_parents)) = parents else {
            return Err(DecodeError::InvalidParentsLen(0));
        };
        let aux_pow = self.decode_auxpow()?;
        self.finish()?;
        Ok(MergeMinedBlockData {
            signal_bits,
            outputs,
            weight,
            timestamp,
            block_parent,
            tx_parents,
            data,
            aux_pow,
        })
    }

    fn decode_poa_block_body(&mut self, _signal_bits: SignalBits) -> Result<PoaBlockData> {
        let signal_bits = _signal_bits;
        let outputs = self.decode_block_funds_data()?;
        if !outputs.is_empty() {
            return Err(DecodeError::Parse);
        }
        let (weight, timestamp, parents, data) = self.decode_block_graph_data()?;
        let Some((block_parent, tx_parents)) = parents else {
            return Err(DecodeError::InvalidParentsLen(0));
        };
        // signer_id (2 bytes)
        let signer_id = self.try_get_array::<2>()?;
        // signature (u8 len + bytes, capped to 100)
        let sig_len = self.decode_len_u8()?;
        if sig_len > 100 {
            return Err(DecodeError::Parse);
        }
        let mut sig = BytesMut::zeroed(sig_len);
        if sig_len > 0 {
            self.try_copy_to_slice(sig.as_mut())?;
        }
        let signature = sig.freeze();
        let nonce = self.try_get_u128()?;
        self.finish()?;
        Ok(PoaBlockData {
            signal_bits,
            weight,
            timestamp,
            block_parent,
            tx_parents,
            data,
            signer_id,
            signature,
            nonce,
        })
    }

    fn decode_any_block_data(&mut self) -> Result<AnyBlockData> {
        let signal_bits = self.decode_signal_bits()?;
        Ok(match self.decode_kind()? {
            Kind::RegularBlock => self.decode_regular_block_body(signal_bits)?.into(),
            Kind::MergeMinedBlock => self.decode_merge_mined_block_body(signal_bits)?.into(),
            Kind::PoaBlock => self.decode_poa_block_body(signal_bits)?.into(),
            kind => {
                return Err(DecodeError::UnexpectedKind(kind));
            }
        })
    }

    fn decode_any_vertex_data(&mut self) -> Result<AnyVertexData> {
        let signal_bits = self.decode_signal_bits()?;
        Ok(match self.decode_kind()? {
            Kind::RegularBlock => self.decode_regular_block_body(signal_bits)?.into(),
            Kind::RegularTransaction => self.decode_regular_transaction_body(signal_bits)?.into(),
            Kind::TokenCreationTransaction => self
                .decode_token_creation_transaction_body(signal_bits)?
                .into(),
            Kind::MergeMinedBlock => self.decode_merge_mined_block_body(signal_bits)?.into(),
            Kind::PoaBlock => self.decode_poa_block_body(signal_bits)?.into(),
            Kind::OnChainBlueprint => self.decode_on_chain_blueprint_body(signal_bits)?.into(),
        })
    }
}

impl<B: Buf> VertexDecodeExt for B {}

pub fn decode_any_vertex_data(mut buf: impl Buf) -> Result<AnyVertexData> {
    buf.decode_any_vertex_data()
}

pub fn decode_any_block_data(mut buf: impl Buf) -> Result<AnyBlockData> {
    buf.decode_any_block_data()
}

pub fn decode_any_transaction_data(mut buf: impl Buf) -> Result<AnyTransactionData> {
    buf.decode_any_transaction_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_output_value_short_and_long() {
        // Short (4-byte) positive value
        let mut buf = BytesMut::new();
        buf.put_u32(1_234_567);
        buf.put(&b"foo"[..]);
        let v = buf.decode_output_value().expect("parse short");
        assert_eq!(buf.len(), 3);
        assert_eq!(v.get(), 1_234_567);

        // Long (8-byte) negative encoding of a large positive value
        let mut buf = BytesMut::new();
        buf.put_i64(-5_000_000_000);
        buf.put(&b"foo"[..]);
        let v = buf.decode_output_value().expect("parse long");
        assert_eq!(buf.len(), 3);
        assert_eq!(v.get(), 5_000_000_000);
    }

    #[test]
    fn decode_genesis_block_from_bytes() {
        let hex = "000001ffffffe8b789180000001976a914a584cf48b161e4a49223ed220df30037ab740e0088ac40350000000000005e0be1000000000000000000000000000000000c9ba0";
        let bytes = Bytes::from(const_hex::decode(hex).expect("valid hex"));
        let AnyBlockData::Genesis(g) = decode_any_block_data(bytes).expect("parse") else {
            panic!("expected genesis")
        };
        assert_eq!(g.outputs.len(), 1);
        assert!((g.weight.get() - 21.0).abs() < f64::EPSILON);
    }

    #[test]
    fn decode_minimal_regular_block() {
        // Build a minimal Regular Block with:
        // signal=0x00, kind=0x00, outputs_len=0
        // weight=1.0, timestamp=0x00000001, parents_len=0, data_len=0
        // nonce=16 zero bytes
        let mut buf = Vec::new();
        buf.push(0x00); // signal_bits
        buf.push(0x00); // kind
        buf.push(0x00); // outputs_len
        buf.extend_from_slice(&1.0f64.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(0x00); // parents_len
        buf.push(0x00); // data_len
        buf.extend_from_slice(&0u128.to_be_bytes()); // nonce

        let AnyBlockData::Genesis(g) = decode_any_block_data(buf.as_slice()).expect("parse") else {
            panic!("expected genesis block")
        };
        assert_eq!(g.outputs.len(), 0);
        assert_eq!(g.weight, 1.0);
        assert_eq!(g.timestamp, Timestamp(1));
        assert_eq!(g.nonce, 0);
    }

    #[test]
    fn decode_regular_block_with_outputs() {
        // One output (short), one output (long), no parents, empty data
        let mut buf = Vec::new();
        buf.push(0x00); // signal_bits
        buf.push(0x00); // kind
        buf.push(0x02); // outputs_len
        // Output 1: short value 1000, token_data=1, script="ab"
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.push(1u8);
        buf.extend_from_slice(&2u16.to_be_bytes());
        buf.extend_from_slice(b"ab");
        // Output 2: long value 5_000_000_000 encoded as negative i64
        buf.extend_from_slice(&(-(5_000_000_000_i64)).to_be_bytes());
        buf.push(0x80);
        buf.extend_from_slice(&3u16.to_be_bytes());
        buf.extend_from_slice(b"xyz");
        // Graph
        buf.extend_from_slice(&2.5f64.to_be_bytes());
        buf.extend_from_slice(&42u32.to_be_bytes());
        buf.push(0x00); // parents_len
        buf.push(0x00); // data_len
        buf.extend_from_slice(&6969u128.to_be_bytes());

        let AnyBlockData::Genesis(g) = decode_any_block_data(buf.as_slice()).expect("parse") else {
            panic!("expected genesis")
        };
        assert_eq!(g.outputs.len(), 2);
        assert_eq!(g.outputs[0].value.get(), 1000);
        assert_eq!(g.outputs[0].token_data, 1);
        assert_eq!(g.outputs[0].script, Bytes::from_static(b"ab"));
        assert_eq!(g.outputs[1].value.get(), 5_000_000_000);
        assert_eq!(g.outputs[1].token_data, 0x80);
        assert_eq!(g.outputs[1].script, Bytes::from_static(b"xyz"));
        assert_eq!(g.weight, 2.5);
        assert_eq!(g.timestamp, Timestamp(42));
        assert_eq!(g.nonce, 6969);
    }

    #[test]
    fn decode_exmaple_genesis_block() {
        // Hex-encoded regular block with 1 P2PKH output, empty parents/data, 16-byte nonce.
        let hex = "000001ffffffe8b789180000001976a914a584cf48b161e4a49223ed220df30037ab740e0088ac40350000000000005e0be1000000000000000000000000000000000c9ba0";
        let bytes = const_hex::decode(hex).expect("valid hex");
        let AnyBlockData::Genesis(g) = decode_any_block_data(bytes.as_slice()).expect("parse")
        else {
            panic!("expected genesis")
        };

        assert_eq!(g.outputs.len(), 1);
        let o = &g.outputs[0];
        assert!(o.value.get() > (1u64 << 31)); // encoded with 8-byte negative form
        assert_eq!(o.token_data, 0);
        assert_eq!(o.script.len(), 25);
        assert_eq!(o.script[0], 0x76);
        assert_eq!(o.script[1], 0xA9);
        assert_eq!(o.script[2], 0x14);
        assert_eq!(o.script[o.script.len() - 2], 0x88);
        assert_eq!(o.script[o.script.len() - 1], 0xAC);

        assert!((g.weight.get() - 21.0).abs() < f64::EPSILON);
        assert_eq!(
            g.timestamp.0,
            u32::from_be_bytes(const_hex::decode_to_array::<_, 4>("5e0be100").unwrap())
        );
        assert_eq!(g.nonce, 826272);
    }

    #[test]
    fn decode_exmaple_regular_block() {
        // Hex-encoded regular block with 1 output, 3 parents, non-empty ASCII data, 16-byte nonce.
        let hex = "0000010000190000001976a914b677a202c8ccc20ff765a789ffe8b7930d33642588ac40350000000000005f2a45f9030000033139d08176d1051fb3a272c3610457f0c7f686afbe0afe3d37f966db8500e161a6b0bee1781ea9300680913fb76fd0fac4acab527cd9626cc1514abdc900975897028ceb037307327c953f5e7ad4d3f42402d71bd3d11ecb63ac39f01a6235393839383938633636663764663465623938616138363536303834613364372d64653332623364303839326434656366616534306165343335396231323536632d616661663032303735626231343731323831656636313130643333333061326100000000000000000000000200217e76";
        let bytes = const_hex::decode(hex).expect("valid hex");
        let AnyBlockData::Regular(rb) = decode_any_block_data(bytes.as_slice()).expect("parse")
        else {
            panic!("expected regular")
        };

        assert_eq!(rb.outputs.len(), 1);
        assert_eq!(rb.outputs[0].script.len(), 25);
        assert!((rb.weight.get() - 21.0).abs() < f64::EPSILON);
        assert_eq!(
            rb.timestamp.0,
            u32::from_be_bytes(const_hex::decode_to_array::<_, 4>("5f2a45f9").unwrap())
        );

        // Parents split into block and 2 tx parents
        let _bp = rb.block_parent;
        let [_t0, _t1] = rb.tx_parents;

        // Data: should be non-empty and ASCII-like
        assert!(!rb.data.is_empty());
        assert!(rb.data.is_ascii());
        // Nonce is present (16 bytes)
        assert_eq!(rb.nonce, 8592129654);
    }

    // example genesis transaction: 000100000040200000000000005e0be10100000000be with hash 00e161a6b0bee1781ea9300680913fb76fd0fac4acab527cd9626cc1514abdc9
    // example regular transaction: 000100010100006e50f6a33f83d510c8fbc5901b8ac760763e7b0e5ed699086478e121b8a200006a473045022100cc747b3d57dfd3f0438d40a4a5d861dbc834d824cd5a43742038fe6a8acc7d3f02206eac32a674b9fc76fce41b8612d498d9e638fc7bef1bc9fac1093b2d723a56b2210349023d26003521e4309e5769f229aa3cccdd423c6e5dc44e97f363612f5db6da0000000300001976a91403bfa6df9588359280bcb0f884d105ee0d27b77088ac4030d3fdf63c434868e84f7a0200007e79c3db6964bbe805fe6903927b64a88ddd9ffdd81276473fd286f336770000000076555eb00732d0f49becec3fc32fbb0f74eaf99daa78a3f81470e26300004af1 with hash 000079f2c9ad6b5c390bb6ec2694b16dbc071d303a73224209654a6b41ba9f3f
    #[test]
    fn decode_example_genesis_transaction() {
        let hex = "000100000040200000000000005e0be10100000000be";
        let raw = const_hex::decode(hex).expect("hex");
        match decode_any_transaction_data(raw.as_slice()).expect("parse") {
            AnyTransactionData::Genesis(g) => {
                assert!(g.weight.get() > 0.0);
            }
            _ => panic!("expected genesis transaction"),
        }
    }

    #[test]
    fn decode_example_regular_transaction() {
        let hex = "000100010100006e50f6a33f83d510c8fbc5901b8ac760763e7b0e5ed699086478e121b8a200006a473045022100cc747b3d57dfd3f0438d40a4a5d861dbc834d824cd5a43742038fe6a8acc7d3f02206eac32a674b9fc76fce41b8612d498d9e638fc7bef1bc9fac1093b2d723a56b2210349023d26003521e4309e5769f229aa3cccdd423c6e5dc44e97f363612f5db6da0000000300001976a91403bfa6df9588359280bcb0f884d105ee0d27b77088ac4030d3fdf63c434868e84f7a0200007e79c3db6964bbe805fe6903927b64a88ddd9ffdd81276473fd286f336770000000076555eb00732d0f49becec3fc32fbb0f74eaf99daa78a3f81470e26300004af1";
        let raw = const_hex::decode(hex).expect("hex");
        match decode_any_transaction_data(raw.as_slice()).expect("parse") {
            AnyTransactionData::Regular(r) => {
                assert_eq!(r.tx_parents.len(), 2);
                assert!(!r.outputs.is_empty());
            }
            _ => panic!("expected regular transaction"),
        }
    }

    #[test]
    fn decode_example_token_creation_transaction() {
        let hex = "00020104000005551d7740fd7d3c0acc50b5677fdd844f1225985aa431e1712af2a2fd8900006a473045022100a445edb5cd6c79a0a7b5ed837582fd65b8d511ee60b64fd076e07bd8f63f75a202202dca24320bffc4c3ca2a07cdfff38f7c839bde70ed49ef634ac6588972836cab2103bfa995d676e3c0ed7b863c74cfef9683fab3163b42b6f21442326a023fc57fba0000264800001976a9146876f9578221fdb678d4e8376503098a9228b13288ac00004e2001001976a914031761ef85a24603203c97e75af355b83209f08f88ac0000000181001976a9149f091256cb98649c7c35df0aad44d7805710691e88ac0000000281001976a914b1d7a5ee505ad4d3b93ea1a5162ba83d5049ec4e88ac0109546f5468654d6f6f6e04f09f9a804034a52aec6cece75e0fc0e30200001a72272f48339fcc5d5ec5deaf197855964b0eb912e8c6eefe00928b6cf600001055641c20b71871ed2c5c7d4096a34f40888d79c25bce74421646e732dc01ff7369";
        let raw = const_hex::decode(hex).expect("hex");
        match decode_any_transaction_data(raw.as_slice()).expect("parse") {
            AnyTransactionData::TokenCreation(c) => {
                assert_eq!(c.tx_parents.len(), 2);
                assert_eq!(c.name.as_str(), "ToTheMoon");
                assert_eq!(c.symbol.as_str(), "🚀");
                assert!(!c.outputs.is_empty());
            }
            _ => panic!("expected regular transaction"),
        }
    }

    #[test]
    fn decode_minimal_genesis_transaction() {
        // signal_bits=0x00, kind=1, no tokens/inputs/outputs, parents_len=0, 4-byte nonce
        let mut buf = vec![0x00, 0x01, 0, 0, 0];
        // graph
        buf.extend_from_slice(&2.5f64.to_be_bytes());
        buf.extend_from_slice(&42u32.to_be_bytes());
        buf.push(0); // parents_len
        // nonce (u32)
        buf.extend_from_slice(&123u32.to_be_bytes());

        let tx = decode_any_transaction_data(buf.as_slice()).expect("parse");
        let AnyTransactionData::Genesis(g) = tx else {
            panic!("expected genesis")
        };
        assert_eq!(g.outputs.len(), 0);
        assert!((g.weight.get() - 2.5).abs() < f64::EPSILON);
        assert_eq!(g.timestamp, Timestamp(42));
        assert_eq!(g.nonce, 123);
    }

    #[test]
    fn decode_minimal_regular_transaction() {
        // signal_bits=0x00, kind=1, no tokens/inputs/outputs, parents_len=2, 4-byte nonce
        let mut buf = vec![0x00, 0x01, 0, 0, 0];
        // graph
        buf.extend_from_slice(&1.0f64.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(2); // parents_len
        // parents: 2 x 32 bytes
        buf.extend_from_slice(&[0x11u8; 32]);
        buf.extend_from_slice(&[0x22u8; 32]);
        // nonce (u32)
        buf.extend_from_slice(&0xAABBCCDDu32.to_be_bytes());

        let tx = decode_any_transaction_data(buf.as_slice()).expect("parse");
        let AnyTransactionData::Regular(r) = tx else {
            panic!("expected regular")
        };
        assert_eq!(r.tx_parents.len(), 2);
        assert_eq!(r.outputs.len(), 0);
        assert_eq!(r.nonce, 0xAABBCCDD);
    }

    #[test]
    fn decode_poa_with_nonzero_outputs_rejected() {
        // PoA with one output (should be rejected), minimal otherwise
        let mut buf = Vec::new();
        buf.push(0x00); // signal_bits
        buf.push(Kind::PoaBlock as u8);
        buf.push(0x01); // outputs_len = 1
        // output: value=1000 (u32), token_data=0, script_len=0
        buf.extend_from_slice(&1000u32.to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(&0u16.to_be_bytes());
        // graph
        buf.extend_from_slice(&1.0f64.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(3); // parents_len
        buf.extend_from_slice(&[0u8; 32]); // block parent
        buf.extend_from_slice(&[0u8; 32]); // tx parent 0
        buf.extend_from_slice(&[0u8; 32]); // tx parent 1
        buf.push(0); // data_len
        // PoA extras
        buf.extend_from_slice(&[0x12, 0x34]); // signer_id
        buf.push(0); // signature_len
        // nonce
        buf.extend_from_slice(&0u128.to_be_bytes());

        let res = decode_any_block_data(buf.as_slice());
        assert!(matches!(res, Err(DecodeError::Parse)));
    }

    #[test]
    fn decode_poa_with_long_signature_rejected() {
        let mut buf = Vec::new();
        buf.push(0x00); // signal_bits
        buf.push(Kind::PoaBlock as u8);
        buf.push(0x00); // outputs_len = 0
        // graph
        buf.extend_from_slice(&1.0f64.to_be_bytes());
        buf.extend_from_slice(&1u32.to_be_bytes());
        buf.push(3); // parents_len
        buf.extend_from_slice(&[0u8; 32]); // block parent
        buf.extend_from_slice(&[0u8; 32]); // tx parent 0
        buf.extend_from_slice(&[0u8; 32]); // tx parent 1
        buf.push(0); // data_len
        // PoA extras
        buf.extend_from_slice(&[0x12, 0x34]); // signer_id
        buf.push(101); // signature_len (too long)
        buf.extend_from_slice(&[0u8; 101]);
        // nonce
        buf.extend_from_slice(&0u128.to_be_bytes());

        let res = decode_any_block_data(buf.as_slice());
        assert!(matches!(res, Err(DecodeError::Parse)));
    }
}
