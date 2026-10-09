// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::crypto::{sha256, sha256d_concat_rev, sha256d_rev, sha256d_simple_merkle_root};
use crate::vertex::header::NanoHeaderAction;

type Result<T> = std::result::Result<T, EncodeError>;

#[derive(Debug, PartialEq, Eq, Error)]
pub enum EncodeError {
    #[error("invalid data")]
    Invalid,
}

// parents data as found in a transaction
type TxParentsData = [TransactionId; 2];

// parents data as found in a block
type BlockParentsData = (BlockId, [TransactionId; 2]);

trait VertexEncodeExt: BufMut {
    fn encode_u8_len(&mut self, len: usize) -> Result<()> {
        if len > u8::MAX as usize {
            return Err(EncodeError::Invalid);
        }
        self.put_u8(len as u8);
        Ok(())
    }

    fn encode_u16_len(&mut self, len: usize) -> Result<()> {
        if len > u16::MAX as usize {
            return Err(EncodeError::Invalid);
        }
        self.put_u16(len as u16);
        Ok(())
    }

    fn encode_slice_u8(&mut self, slice: impl AsRef<[u8]>) -> Result<()> {
        let slice = slice.as_ref();
        self.encode_u8_len(slice.len())?;
        self.put_slice(slice);
        Ok(())
    }

    fn encode_slice_u16(&mut self, slice: impl AsRef<[u8]>) -> Result<()> {
        let slice = slice.as_ref();
        self.encode_u16_len(slice.len())?;
        self.put_slice(slice);
        Ok(())
    }

    fn encode_slice_u32(&mut self, slice: impl AsRef<[u8]>) -> Result<()> {
        let slice = slice.as_ref();
        self.put_u32(slice.len() as u32);
        self.put_slice(slice);
        Ok(())
    }

    fn encode_str_u8(&mut self, string: impl AsRef<str>) -> Result<()> {
        let slice = string.as_ref().as_bytes();
        self.encode_slice_u8(slice)
    }

    fn encode_output_value(&mut self, value: OutputValue) -> Result<()> {
        let value: u64 = value.get();
        if value <= i32::MAX as u64 {
            self.put_u32(value as u32);
        } else {
            if value > (i64::MAX as u64) {
                return Err(EncodeError::Invalid);
            }
            self.put_i64(-(value as i64));
        }
        Ok(())
    }

    fn encode_tx_input(&mut self, input: &TxInput) -> Result<()> {
        self.put_slice(&input.tx_id);
        self.put_u8(input.index);
        self.encode_slice_u16(&input.data)?;
        Ok(())
    }

    fn encode_tx_output(&mut self, output: &TxOutput) -> Result<()> {
        self.encode_output_value(output.value)?;
        self.put_u8(output.token_data);
        self.encode_slice_u16(&output.script)?;
        Ok(())
    }

    fn encode_iter_tokens<'i>(&mut self, tokens: impl Iterator<Item = &'i TokenUid>) {
        for token in tokens {
            self.put_slice(token);
        }
    }

    fn encode_iter_inputs<'i>(&mut self, inputs: impl Iterator<Item = &'i TxInput>) -> Result<()> {
        for input in inputs {
            self.encode_tx_input(input)?;
        }
        Ok(())
    }

    fn encode_iter_outputs<'i>(
        &mut self,
        outputs: impl Iterator<Item = &'i TxOutput>,
    ) -> Result<()> {
        for output in outputs {
            self.encode_tx_output(output)?;
        }
        Ok(())
    }

    fn encode_signal_bits(&mut self, s: SignalBits) {
        self.put_u8(s.0);
    }

    fn encode_kind(&mut self, k: Kind) {
        self.put_u8(k as u8);
    }

    fn encode_weight(&mut self, w: Weight) {
        self.put_f64(w.get())
    }

    fn encode_timestamp(&mut self, t: Timestamp) {
        self.put_u32(t.0)
    }

    fn encode_tx_parents(&mut self, p: Option<TxParentsData>) {
        if let Some(parents) = p {
            self.put_u8(2);
            self.put_slice(&parents[0]);
            self.put_slice(&parents[1]);
        } else {
            self.put_u8(0);
        }
    }

    fn encode_block_parents(&mut self, p: Option<BlockParentsData>) {
        if let Some((block, parents)) = p {
            self.put_u8(3);
            self.put_slice(&block);
            self.put_slice(&parents[0]);
            self.put_slice(&parents[1]);
        } else {
            self.put_u8(0);
        }
    }

    fn encode_uleb128(&mut self, mut v: u64) {
        loop {
            let mut byte = (v & 0x7F) as u8;
            v >>= 7;
            if v != 0 {
                byte |= 0x80;
            }
            self.put_u8(byte);
            if v == 0 {
                break;
            }
        }
    }

    fn encode_address(&mut self, addr: &crate::common::Address) {
        self.put_slice(addr.as_ref());
    }

    fn encode_nano_header(&mut self, n: &NanoHeader) -> Result<()> {
        self.put_u8(HeaderKind::Nano as u8);
        // id (VertexId)
        self.put_slice(&n.id);
        // seqnum (ULEB128)
        self.encode_uleb128(n.seqnum);
        // method (u8 len + bytes)
        self.encode_str_u8(&n.method)?;
        // args (u16 len + bytes)
        self.encode_slice_u16(&n.args)?;
        // actions
        self.encode_u8_len(n.actions.len())?;
        for a in &n.actions {
            match a {
                NanoHeaderAction::Deposit { index, amount } => {
                    self.put_u8(1);
                    self.put_u8(*index);
                    self.encode_output_value(*amount)?;
                }
                NanoHeaderAction::Withdrawal { index, amount } => {
                    self.put_u8(2);
                    self.put_u8(*index);
                    self.encode_output_value(*amount)?;
                }
                NanoHeaderAction::GrantAuthority { index, mint, melt }
                | NanoHeaderAction::AcquireAuthority { index, mint, melt } => {
                    let kind = match a {
                        NanoHeaderAction::GrantAuthority { .. } => 3,
                        _ => 4,
                    };
                    self.put_u8(kind);
                    self.put_u8(*index);
                    let mut flags: u64 = 0;
                    if *mint {
                        flags |= 0x01;
                    }
                    if *melt {
                        flags |= 0x02;
                    }
                    if flags == 0 || flags > 3 {
                        return Err(EncodeError::Invalid);
                    }
                    self.encode_output_value(OutputValue::new(flags).ok_or(EncodeError::Invalid)?)?;
                }
            }
        }
        // address (25 bytes fixed)
        self.encode_address(&n.address);
        // script (ULEB128 + bytes)
        self.encode_uleb128(n.script.len() as u64);
        self.put_slice(&n.script);
        Ok(())
    }

    fn encode_headers<'i>(&mut self, headers: impl Iterator<Item = &'i AnyHeader>) -> Result<()> {
        let mut count = 0usize;
        for h in headers {
            count += 1;
            if count > 2 {
                return Err(EncodeError::Invalid);
            }
            match h {
                AnyHeader::Nano(n) => self.encode_nano_header(n)?,
                AnyHeader::Fee(f) => self.encode_fee_header(f)?,
            }
        }
        Ok(())
    }

    fn encode_fee_header(&mut self, f: &FeeHeader) -> Result<()> {
        self.put_u8(HeaderKind::Fee as u8);
        self.encode_u8_len(f.fees.len())?;
        for e in &f.fees {
            self.put_slice(&e.token);
            self.encode_output_value(e.amount)?;
        }
        Ok(())
    }

    fn encode_prefix(&mut self, s: SignalBits, k: Kind) {
        self.encode_signal_bits(s);
        self.encode_kind(k);
    }

    fn encode_tx_funds(
        &mut self,
        tokens: &'_ [TokenUid],
        inputs: &'_ [TxInput],
        outputs: &'_ [TxOutput],
    ) -> Result<()> {
        self.encode_u8_len(tokens.len())?;
        self.encode_u8_len(inputs.len())?;
        self.encode_u8_len(outputs.len())?;
        self.encode_iter_tokens(tokens.iter());
        self.encode_iter_inputs(inputs.iter())?;
        self.encode_iter_outputs(outputs.iter())?;
        Ok(())
    }

    fn encode_tx_graph(&mut self, w: Weight, t: Timestamp, p: Option<TxParentsData>) -> Result<()> {
        self.encode_weight(w);
        self.encode_timestamp(t);
        self.encode_tx_parents(p);
        Ok(())
    }

    fn encode_genesis_tx_funds(&mut self, data: &GenesisTransactionData) -> Result<()> {
        self.encode_prefix(Default::default(), data.kind());
        self.encode_tx_funds(&[], &[], data.outputs.as_slice())?;
        Ok(())
    }

    fn encode_genesis_tx_graph(&mut self, data: &GenesisTransactionData) -> Result<()> {
        self.encode_tx_graph(data.weight, data.timestamp, None)?;
        Ok(())
    }

    fn encode_genesis_tx(&mut self, data: &GenesisTransactionData) -> Result<()> {
        self.encode_genesis_tx_funds(data)?;
        self.encode_genesis_tx_graph(data)?;
        self.put_u32(data.nonce);
        Ok(())
    }

    fn encode_regular_tx_funds(&mut self, data: &RegularTransactionData) -> Result<()> {
        self.encode_prefix(data.signal_bits, data.kind());
        self.encode_tx_funds(
            data.tokens.as_slice(),
            data.inputs.as_slice(),
            data.outputs.as_slice(),
        )?;
        Ok(())
    }

    fn encode_regular_tx_graph(&mut self, data: &RegularTransactionData) -> Result<()> {
        self.encode_tx_graph(data.weight, data.timestamp, Some(data.tx_parents))?;
        Ok(())
    }

    fn encode_regular_tx(&mut self, data: &RegularTransactionData) -> Result<()> {
        self.encode_regular_tx_funds(data)?;
        self.encode_regular_tx_graph(data)?;
        self.put_u32(data.nonce);
        self.encode_headers(data.headers.iter())?;
        Ok(())
    }

    fn encode_block_funds(&mut self, outputs: &'_ [TxOutput]) -> Result<()> {
        self.encode_u8_len(outputs.len())?;
        self.encode_iter_outputs(outputs.iter())?;
        Ok(())
    }

    fn encode_block_graph(
        &mut self,
        w: Weight,
        t: Timestamp,
        p: Option<BlockParentsData>,
        d: impl AsRef<[u8]>,
    ) -> Result<()> {
        self.encode_weight(w);
        self.encode_timestamp(t);
        self.encode_block_parents(p);
        self.encode_slice_u8(d)?;
        Ok(())
    }

    fn encode_varint(&mut self, v: u64) {
        if v < 0xFD {
            self.put_u8(v as u8);
        } else if v <= 0xFFFF {
            self.put_u8(0xFD);
            self.put_u16_le(v as u16);
        } else if v <= 0xFFFF_FFFF {
            self.put_u8(0xFE);
            self.put_u32_le(v as u32);
        } else {
            self.put_u8(0xFF);
            self.put_u64_le(v);
        }
    }

    fn encode_varbytes(&mut self, bytes: impl AsRef<[u8]>) {
        let bytes = bytes.as_ref();
        self.encode_varint(bytes.len() as u64);
        self.put_slice(bytes);
    }

    fn encode_merkle_path(&mut self, merkle_path: &'_ [Hash32]) {
        self.encode_varint(merkle_path.len() as u64);
        for h in merkle_path {
            self.put_slice(h);
        }
    }

    fn encode_auxpow(&mut self, aux: &AuxPow) -> Result<()> {
        self.put_slice(&aux.header_head);
        self.encode_varbytes(&aux.coinbase_head);
        self.encode_varbytes(&aux.coinbase_tail);
        self.encode_merkle_path(&aux.merkle_path);
        self.put_slice(&aux.header_tail);
        Ok(())
    }

    fn encode_genesis_block_funds(&mut self, data: &GenesisBlockData) -> Result<()> {
        self.encode_prefix(Default::default(), data.kind());
        self.encode_block_funds(data.outputs.as_slice())
    }

    fn encode_genesis_block_graph(&mut self, data: &GenesisBlockData) -> Result<()> {
        self.encode_block_graph(data.weight, data.timestamp, None, [])
    }

    fn encode_genesis_block(&mut self, data: &GenesisBlockData) -> Result<()> {
        self.encode_genesis_block_funds(data)?;
        self.encode_genesis_block_graph(data)?;
        self.put_u128(data.nonce);
        Ok(())
    }

    fn encode_regular_block_funds(&mut self, data: &RegularBlockData) -> Result<()> {
        self.encode_prefix(data.signal_bits, data.kind());
        self.encode_block_funds(data.outputs.as_slice())
    }

    fn encode_regular_block_graph(&mut self, data: &RegularBlockData) -> Result<()> {
        self.encode_block_graph(
            data.weight,
            data.timestamp,
            Some((data.block_parent, data.tx_parents)),
            &data.data,
        )
    }

    fn encode_regular_block(&mut self, data: &RegularBlockData) -> Result<()> {
        self.encode_regular_block_funds(data)?;
        self.encode_regular_block_graph(data)?;
        self.put_u128(data.nonce);
        Ok(())
    }

    fn encode_merge_mined_block(&mut self, data: &MergeMinedBlockData) -> Result<()> {
        self.encode_prefix(data.signal_bits, data.kind());
        self.encode_block_funds(data.outputs.as_slice())?;
        self.encode_block_graph(
            data.weight,
            data.timestamp,
            Some((data.block_parent, data.tx_parents)),
            &data.data,
        )?;
        self.encode_auxpow(&data.aux_pow)?;
        Ok(())
    }

    fn encode_poa_block(&mut self, data: &PoaBlockData) -> Result<()> {
        if data.signature.len() > 100 {
            return Err(EncodeError::Invalid);
        }
        self.encode_prefix(data.signal_bits, data.kind());
        self.put_u8(0);
        self.encode_block_graph(
            data.weight,
            data.timestamp,
            Some((data.block_parent, data.tx_parents)),
            &data.data,
        )?;
        self.put_slice(&data.signer_id);
        self.encode_slice_u8(&data.signature)?;
        self.put_u128(data.nonce);
        Ok(())
    }

    fn encode_token_creation_funds(&mut self, data: &TokenCreationTransactionData) -> Result<()> {
        self.encode_prefix(data.signal_bits, data.kind());
        self.encode_u8_len(data.inputs.len())?;
        self.encode_u8_len(data.outputs.len())?;
        self.encode_iter_inputs(data.inputs.iter())?;
        self.encode_iter_outputs(data.outputs.iter())?;
        self.put_u8(data.token_kind as u8);
        self.encode_str_u8(&data.name)?;
        self.encode_str_u8(&data.symbol)?;
        Ok(())
    }

    fn encode_token_creation_tx(&mut self, data: &TokenCreationTransactionData) -> Result<()> {
        self.encode_token_creation_funds(data)?;
        self.encode_tx_graph(data.weight, data.timestamp, Some(data.tx_parents))?;
        self.put_u32(data.nonce);
        self.encode_headers(data.headers.iter())?;
        Ok(())
    }

    fn encode_on_chain_blueprint_funds(&mut self, data: &OnChainBlueprintData) -> Result<()> {
        self.encode_prefix(data.signal_bits, data.kind());
        self.encode_u8_len(data.tokens.len())?;
        self.encode_u8_len(data.inputs.len())?;
        self.encode_u8_len(data.outputs.len())?;
        self.encode_iter_tokens(data.tokens.iter());
        self.encode_iter_inputs(data.inputs.iter())?;
        self.encode_iter_outputs(data.outputs.iter())?;
        self.put_u8(data.ocb_kind as u8);
        self.encode_slice_u32(&data.code)?;
        self.encode_slice_u8(&data.nc_pubkey)?;
        self.encode_slice_u8(&data.nc_signature)?;
        Ok(())
    }

    fn encode_on_chain_blueprint(&mut self, data: &OnChainBlueprintData) -> Result<()> {
        self.encode_on_chain_blueprint_funds(data)?;
        self.encode_tx_graph(data.weight, data.timestamp, Some(data.tx_parents))?;
        self.put_u32(data.nonce);
        self.encode_headers(data.headers.iter())?;
        Ok(())
    }

    fn encode_any_block(&mut self, data: &AnyBlockData) -> Result<()> {
        match data {
            AnyBlockData::Genesis(data) => self.encode_genesis_block(data),
            AnyBlockData::Regular(data) => self.encode_regular_block(data),
            AnyBlockData::MergeMined(data) => self.encode_merge_mined_block(data),
            AnyBlockData::Poa(data) => self.encode_poa_block(data),
        }
    }

    fn encode_any_transaction(&mut self, data: &AnyTransactionData) -> Result<()> {
        match data {
            AnyTransactionData::Genesis(data) => self.encode_genesis_tx(data),
            AnyTransactionData::Regular(data) => self.encode_regular_tx(data),
            AnyTransactionData::TokenCreation(data) => self.encode_token_creation_tx(data),
            AnyTransactionData::OnChainBlueprint(data) => self.encode_on_chain_blueprint(data),
        }
    }

    fn encode_any_vertex(&mut self, data: &AnyVertexData) -> Result<()> {
        match data {
            AnyVertexData::Block(data) => self.encode_any_block(data),
            AnyVertexData::Transaction(data) => self.encode_any_transaction(data),
        }
    }
}

impl<B: BufMut> VertexEncodeExt for B {}

pub fn encode_any_vertex_data(mut buf: impl BufMut, data: &AnyVertexData) -> Result<()> {
    buf.encode_any_vertex(data)
}

pub fn encode_any_block_data(mut buf: impl BufMut, data: &AnyBlockData) -> Result<()> {
    buf.encode_any_block(data)
}

pub fn encode_any_transaction_data(mut buf: impl BufMut, data: &AnyTransactionData) -> Result<()> {
    buf.encode_any_transaction(data)
}

impl HashableData for GenesisBlockData {
    fn write_funds<B: BufMut>(&self, buf: &mut B) {
        buf.encode_genesis_block_funds(self).unwrap();
    }
    fn write_graph<B: BufMut>(&self, buf: &mut B) {
        buf.encode_genesis_block_graph(self).unwrap();
    }
    fn write_nonce<B: BufMut>(&self, buf: &mut B) {
        buf.put_u128(self.nonce);
    }
}

impl HashableData for RegularBlockData {
    fn write_funds<B: BufMut>(&self, buf: &mut B) {
        buf.encode_regular_block_funds(self).unwrap();
    }
    fn write_graph<B: BufMut>(&self, buf: &mut B) {
        buf.encode_regular_block_graph(self).unwrap();
    }
    fn write_nonce<B: BufMut>(&self, buf: &mut B) {
        buf.put_u128(self.nonce);
    }
}

impl HashableData for MergeMinedBlockData {
    fn write_funds<B: BufMut>(&self, buf: &mut B) {
        buf.encode_prefix(self.signal_bits, self.kind());
        buf.encode_block_funds(self.outputs.as_slice()).unwrap();
    }
    fn write_graph<B: BufMut>(&self, buf: &mut B) {
        buf.encode_block_graph(
            self.weight,
            self.timestamp,
            Some((self.block_parent, self.tx_parents)),
            &self.data,
        )
        .unwrap();
    }
    fn write_nonce<B: BufMut>(&self, buf: &mut B) {
        // Not used for merge-mined hashing; keep 16 zero bytes for uniformity.
        buf.put_slice(&[0u8; 16]);
    }
    fn compute_hash(&self) -> Hash32 {
        // Compute H_funds and H_graph
        let mut funds_buf = BytesMut::new();
        self.write_funds(&mut funds_buf);
        let h_funds = sha256(funds_buf.freeze());

        let mut graph_buf = BytesMut::new();
        self.write_graph(&mut graph_buf);
        let h_graph = sha256(graph_buf.freeze());

        // Mining base hash as embedded in coinbase (LE)
        let base_le = sha256d_concat_rev([h_funds.as_ref(), h_graph.as_ref()]);

        // Coinbase transaction hash (LE)
        let mut coinbase = BytesMut::new();
        coinbase.extend_from_slice(&self.aux_pow.coinbase_head);
        coinbase.extend_from_slice(base_le.as_ref());
        coinbase.extend_from_slice(&self.aux_pow.coinbase_tail);
        let cb_le = sha256d_rev(coinbase.freeze());

        // Merkle root (LE) from [coinbase_hash] + merkle_path
        let root_le = sha256d_simple_merkle_root(
            std::iter::once(cb_le).chain(self.aux_pow.merkle_path.iter().copied()),
        );

        // Build Bitcoin header with merkle_root in BE (reverse of LE bytes)
        let mut header = BytesMut::new();
        header.extend_from_slice(&self.aux_pow.header_head);
        header.extend_from_slice(root_le.reversed().as_ref());
        header.extend_from_slice(&self.aux_pow.header_tail);
        sha256d_rev(header.freeze())
    }
}

impl HashableData for PoaBlockData {
    fn write_funds<B: BufMut>(&self, buf: &mut B) {
        buf.encode_prefix(self.signal_bits, self.kind());
        buf.put_u8(0);
    }
    fn write_graph<B: BufMut>(&self, buf: &mut B) {
        buf.encode_block_graph(
            self.weight,
            self.timestamp,
            Some((self.block_parent, self.tx_parents)),
            &self.data,
        )
        .unwrap();
        buf.put_slice(&self.signer_id);
        buf.encode_slice_u8(&self.signature).unwrap();
    }
    fn write_nonce<B: BufMut>(&self, buf: &mut B) {
        buf.put_u128(self.nonce);
    }
}

impl HashableData for GenesisTransactionData {
    fn write_funds<B: BufMut>(&self, buf: &mut B) {
        buf.encode_genesis_tx_funds(self).unwrap();
    }
    fn write_graph<B: BufMut>(&self, buf: &mut B) {
        buf.encode_genesis_tx_graph(self).unwrap();
    }
    fn write_nonce<B: BufMut>(&self, buf: &mut B) {
        buf.put_u128(self.nonce as u128);
    }
}

impl HashableData for RegularTransactionData {
    fn write_funds<B: BufMut>(&self, buf: &mut B) {
        buf.encode_regular_tx_funds(self).unwrap();
    }
    fn write_graph<B: BufMut>(&self, buf: &mut B) {
        buf.encode_regular_tx_graph(self).unwrap();
        // Include headers in graph hash per spec
        buf.encode_headers(self.headers.iter()).unwrap();
    }
    fn write_nonce<B: BufMut>(&self, buf: &mut B) {
        buf.put_u128(self.nonce as u128);
    }
}

impl HashableData for TokenCreationTransactionData {
    fn write_funds<B: BufMut>(&self, buf: &mut B) {
        buf.encode_token_creation_funds(self).unwrap();
    }
    fn write_graph<B: BufMut>(&self, buf: &mut B) {
        buf.encode_tx_graph(self.weight, self.timestamp, Some(self.tx_parents))
            .unwrap();
        buf.encode_headers(self.headers.iter()).unwrap();
    }
    fn write_nonce<B: BufMut>(&self, buf: &mut B) {
        buf.put_u128(self.nonce as u128);
    }
}

impl HashableData for OnChainBlueprintData {
    fn write_funds<B: BufMut>(&self, buf: &mut B) {
        buf.encode_on_chain_blueprint_funds(self).unwrap();
    }
    fn write_graph<B: BufMut>(&self, buf: &mut B) {
        buf.encode_tx_graph(self.weight, self.timestamp, Some(self.tx_parents))
            .unwrap();
        buf.encode_headers(self.headers.iter()).unwrap();
    }
    fn write_nonce<B: BufMut>(&self, buf: &mut B) {
        buf.put_u128(self.nonce as u128);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Address;
    use crate::vertex::header::{FeeHeader, FeeHeaderEntry, NanoHeader, NanoHeaderAction};
    use bytes::Bytes;
    use std::num::NonZero;

    #[test]
    fn render_minimal_regular_block_matches_manual() {
        // Manual buffer constructed in parse tests
        let mut manual = Vec::new();
        manual.push(0x00); // signal_bits
        manual.push(Kind::RegularBlock as u8);
        manual.push(0x00); // outputs_len
        manual.extend_from_slice(&1.0f64.to_be_bytes());
        manual.extend_from_slice(&1u32.to_be_bytes());
        manual.push(0x00); // parents_len
        manual.push(0x00); // data_len
        manual.extend_from_slice(&0u128.to_be_bytes());

        let gb = GenesisBlockData {
            outputs: vec![],
            weight: Weight::new(1.0).unwrap(),
            timestamp: Timestamp(1),
            nonce: 0,
        };
        let mut buf = BytesMut::new();
        buf.encode_genesis_block(&gb).expect("encode");
        let rendered = buf.freeze();
        assert_eq!(&rendered[..], manual.as_slice());
    }

    fn sample_hash(fill: u8) -> Hash32 {
        Hash32([fill; 32])
    }

    #[test]
    fn roundtrip_genesis_block() {
        let outputs = vec![
            TxOutput {
                value: NonZero::new(100u64).unwrap(),
                token_data: 0,
                script: Bytes::from_static(b"abc"),
            },
            TxOutput {
                value: NonZero::new(5_000_000_000u64).unwrap(),
                token_data: 1,
                script: Bytes::from_static(b"defgh"),
            },
        ];
        let gb = GenesisBlockData {
            outputs,
            weight: Weight::new(2.0).unwrap(),
            timestamp: Timestamp(12345),
            nonce: 999_555_333_111u128,
        };

        let mut buf = BytesMut::new();
        let any = AnyBlockData::from(gb.clone());
        encode_any_block_data(&mut buf, &any).expect("encode");

        let decoded = decode_any_block_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyBlockData::from(gb));
    }

    #[test]
    fn roundtrip_regular_block() {
        let outputs = vec![TxOutput {
            value: NonZero::new(1234u64).unwrap(),
            token_data: 0,
            script: Bytes::from_static(b"script"),
        }];
        let rb = RegularBlockData {
            signal_bits: SignalBits(0x00),
            outputs,
            weight: Weight::new(3.5).unwrap(),
            timestamp: Timestamp(0x0102_0304),
            block_parent: BlockId(VertexId(sample_hash(0xAA))),
            tx_parents: [
                TransactionId(VertexId(sample_hash(0x11))),
                TransactionId(VertexId(sample_hash(0x22))),
            ],
            data: Bytes::from_static(b"hello world"),
            nonce: 42u128,
        };

        let mut buf = BytesMut::new();
        let any = AnyBlockData::from(rb.clone());
        encode_any_block_data(&mut buf, &any).expect("encode");

        let decoded = decode_any_block_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyBlockData::from(rb));
    }

    #[test]
    fn roundtrip_merge_mined_block() {
        fn h(fill: u8) -> Hash32 {
            Hash32([fill; 32])
        }

        let mmb = MergeMinedBlockData {
            signal_bits: SignalBits(0x00),
            outputs: vec![],
            weight: Weight::new(3.0).unwrap(),
            timestamp: Timestamp(0x0A0B0C0D),
            block_parent: BlockId(VertexId(h(0xAB))),
            tx_parents: [
                TransactionId(VertexId(h(0xCD))),
                TransactionId(VertexId(h(0xEF))),
            ],
            data: Bytes::from_static(b"demo"),
            aux_pow: AuxPow {
                header_head: [0u8; 36],
                coinbase_head: Bytes::from_static(b""),
                coinbase_tail: Bytes::from_static(b""),
                merkle_path: vec![],
                header_tail: [0u8; 12],
            },
        };

        let mut buf = BytesMut::new();
        let any = AnyBlockData::from(mmb.clone());
        encode_any_block_data(&mut buf, &any).expect("encode");
        let decoded = decode_any_block_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyBlockData::from(mmb));
    }

    #[test]
    fn roundtrip_genesis_transaction() {
        let outputs = vec![TxOutput {
            value: NonZero::new(10_000u64).unwrap(),
            token_data: 0,
            script: Bytes::from_static(b"pay to pubkey hash"),
        }];
        let gt = GenesisTransactionData {
            outputs,
            weight: Weight::new(0.5).unwrap(),
            timestamp: Timestamp(7),
            nonce: 0xDEAD_BEEFu32,
        };

        let mut buf = BytesMut::new();
        let any = AnyTransactionData::from(gt.clone());
        encode_any_transaction_data(&mut buf, &any).expect("encode");
        let decoded = decode_any_transaction_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyTransactionData::from(gt));
    }

    #[test]
    fn roundtrip_regular_transaction() {
        let tokens = vec![TokenUid(sample_hash(0x55)), TokenUid(sample_hash(0x66))];
        let inputs = vec![
            TxInput {
                tx_id: TransactionId(VertexId(sample_hash(0xA1))),
                index: 0,
                data: Bytes::from_static(b"sigdata1"),
            },
            TxInput {
                tx_id: TransactionId(VertexId(sample_hash(0xA2))),
                index: 1,
                data: Bytes::from_static(b"sigdata2"),
            },
        ];
        let outputs = vec![
            TxOutput {
                value: NonZero::new(1_000_000u64).unwrap(),
                token_data: 0, // HTR
                script: Bytes::from_static(b"p2pkh1"),
            },
            TxOutput {
                value: NonZero::new(3_000_000_000u64).unwrap(),
                token_data: 1, // token index 1 (first in tokens list)
                script: Bytes::from_static(b"p2pkh2"),
            },
        ];
        let rt = RegularTransactionData {
            signal_bits: SignalBits(0x01),
            tokens,
            inputs,
            outputs,
            weight: Weight::new(1.25).unwrap(),
            timestamp: Timestamp(1_700_000_000),
            tx_parents: [
                TransactionId(VertexId(sample_hash(0xC1))),
                TransactionId(VertexId(sample_hash(0xC2))),
            ],
            nonce: 0xAABB_CCDD,
            headers: vec![],
        };

        let mut buf = BytesMut::new();
        let any = AnyTransactionData::from(rt.clone());
        encode_any_transaction_data(&mut buf, &any).expect("encode");
        let decoded = decode_any_transaction_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyTransactionData::from(rt));
    }

    #[test]
    fn roundtrip_token_creation_transaction() {
        let inputs = vec![TxInput {
            tx_id: TransactionId(VertexId(Hash32([0xAB; 32]))),
            index: 2,
            data: Bytes::from_static(b"sigdata-tokcreate"),
        }];
        let outputs = vec![
            TxOutput {
                value: OutputValue::new(5_000u64).unwrap(),
                token_data: 0, // HTR output for deposit
                script: Bytes::from_static(b"out1"),
            },
            TxOutput {
                value: OutputValue::new(1_000u64).unwrap(),
                token_data: 1, // created token index 1
                script: Bytes::from_static(b"out2"),
            },
        ];
        let tct = TokenCreationTransactionData {
            signal_bits: SignalBits(0x02),
            inputs,
            outputs,
            token_kind: TokenKind::Deposit,
            name: "MyToken".into(),
            symbol: "MTK".into(),
            weight: Weight::new(2.0).unwrap(),
            timestamp: Timestamp(1_700_123_456),
            tx_parents: [
                TransactionId(VertexId(Hash32([0x11; 32]))),
                TransactionId(VertexId(Hash32([0x22; 32]))),
            ],
            nonce: 0x01020304,
            headers: vec![],
        };

        let mut buf = BytesMut::new();
        let any = AnyTransactionData::from(tct.clone());
        encode_any_transaction_data(&mut buf, &any).expect("encode");
        let decoded = decode_any_transaction_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyTransactionData::from(tct));
    }

    #[test]
    fn roundtrip_on_chain_blueprint() {
        let tokens = vec![TokenUid(Hash32([0xAA; 32]))];
        let inputs = vec![TxInput {
            tx_id: TransactionId(VertexId(Hash32([0xCD; 32]))),
            index: 0,
            data: Bytes::from_static(b"sig"),
        }];
        let outputs = vec![TxOutput {
            value: NonZero::new(42u64).unwrap(),
            token_data: 0,
            script: Bytes::from_static(b"p2pkh"),
        }];
        let ocb = OnChainBlueprintData {
            signal_bits: SignalBits(0x00),
            tokens,
            inputs,
            outputs,
            ocb_kind: OcbKind::PythonZlib,
            code: Bytes::from_static(b"\x01\x78\x9c..."), // code_kind=1, rest zlib stub
            nc_pubkey: Bytes::from_static(b"0333deadbeef"),
            nc_signature: Bytes::from_static(b"3045..."),
            weight: Weight::new(3.0).unwrap(),
            timestamp: Timestamp(1234567890),
            tx_parents: [
                TransactionId(VertexId(Hash32([0x11; 32]))),
                TransactionId(VertexId(Hash32([0x22; 32]))),
            ],
            nonce: 0xDEAD_BEEF,
            headers: vec![],
        };

        let mut buf = BytesMut::new();
        let any = AnyTransactionData::from(ocb.clone());
        encode_any_transaction_data(&mut buf, &any).expect("encode");
        let decoded = decode_any_transaction_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyTransactionData::from(ocb));
    }

    #[test]
    fn roundtrip_poa_block() {
        let pb = PoaBlockData {
            signal_bits: SignalBits(0x00),
            weight: Weight::new(10.0).unwrap(),
            timestamp: Timestamp(0x01020304),
            block_parent: BlockId(VertexId(Hash32([0xAA; 32]))),
            tx_parents: [
                TransactionId(VertexId(Hash32([0x11; 32]))),
                TransactionId(VertexId(Hash32([0x22; 32]))),
            ],
            data: Bytes::from_static(b"hello"),
            signer_id: [0x12, 0x34],
            signature: Bytes::from_static(b"sigbytes"),
            nonce: 0x0102030405060708090A0B0C0D0E0F00u128,
        };

        let mut buf = BytesMut::new();
        let any = AnyBlockData::from(pb.clone());
        encode_any_block_data(&mut buf, &any).expect("encode");
        let decoded = decode_any_block_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyBlockData::from(pb));
    }

    #[test]
    fn roundtrip_regular_tx_with_nano_header() {
        let outputs = vec![TxOutput {
            value: NonZero::new(123u64).unwrap(),
            token_data: 0,
            script: Bytes::from_static(b"payto"),
        }];
        let headers = vec![AnyHeader::Nano(NanoHeader {
            seqnum: 300, // forces multi-byte ULEB128
            id: VertexId(Hash32([0xAB; 32])),
            method: "transfer".to_string(),
            args: Bytes::from_static(b"{}"),
            actions: vec![
                NanoHeaderAction::Deposit {
                    index: 1,
                    amount: 1500.try_into().unwrap(),
                },
                NanoHeaderAction::GrantAuthority {
                    index: 2,
                    mint: true,
                    melt: false,
                },
            ],
            address: Address([0x11; 25]),
            script: Bytes::from_static(b"\x01\x02"),
        })];

        let rt = RegularTransactionData {
            signal_bits: SignalBits(0x00),
            tokens: vec![],
            inputs: vec![],
            outputs,
            weight: Weight::new(1.0).unwrap(),
            timestamp: Timestamp(123456),
            tx_parents: [
                TransactionId(VertexId(Hash32([0x10; 32]))),
                TransactionId(VertexId(Hash32([0x20; 32]))),
            ],
            nonce: 0xAABBCCDD,
            headers,
        };

        let mut buf = BytesMut::new();
        let any = AnyTransactionData::from(rt.clone());
        encode_any_transaction_data(&mut buf, &any).expect("encode");
        let decoded = decode_any_transaction_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyTransactionData::from(rt));
    }

    #[test]
    fn compute_hash_merge_mined_block_example() {
        let expected = "00000000000000000e8ba92bc1968fc48ee8716404f5011039bbaf073a539c21";
        let hex = "0003010000032000001976a91473c0a326af979a12be89ee8a00e8871c8e27650288ac4050f05011955f4b68e5cf3b0300000000000000000534663d460969e50a23f1e3f2a747c2e8b5dd6988d2d48a00004f77b062015661d06c5dc7a68ee5a7e141ce8826589c6bf7b0d096e3738800000000e20584f545bf980327c1716eb1f5d7015834abac9b0146e1af1b941a0000000036170068dfce4287aedf5ad156f0be6c5c5e63e0581fc200000000000000000000fd680101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff640362020e2cfabe6d6d199589fae8469c6d0656963cda114952504ec571dc2e0983eac995c1720c765410000000f09f909f092f4632506f6f6c2f670000000000000000000000000000000000000000000000000000000000000000000000050056a73300000000000822020000000000001976a914c6740a12d0a7d556f89782bf5faf0e12cf25a63988acb5e9cd12000000001976a91469f2a01f4ff9e6ac24df9062e9828753474b348088ac0000000000000000266a24aa21a9ed7c7a323d71cc9304ba1ade1539710f5e129145504f9c364b3f83533da9247ee400000000000000002f6a2d434f52450142fdeae88682a965939fee9b7b2bd5b99694ff64e7ec323813c943336c579e238228a8ebd096a7e50000000000000000126a10455853415401051b0f0e0e0b1f1200130000000000000000266a24486174686b00000000000000002c6a4c2952534b424c4f434b3ada7b81661ae9e67dbaf1521ca00125a117efb5d3d383614558c7ab10007b3f270000000000000000296a27737973baef5a3ebf6b9d0c04fd41554b4513f1efc89e3b70b376382f01cee701cbe9d356432000ee7bd43e0cdf07d51ffaaef72391b85a6740a873a8e5dee875c242c3f1059b75ea35acf197afb9cbf2b0ddd06e4382fd1e0faf0bd4ff3dc677592fd4f8f58faea0e3fd4be1a7c28a3d5b6b962ae23246960ff1e2e4e6bfd0ff231ae068790a62815485767b22b456b3b5fa2d51d1a89deb035f7fb85cfc69239a060869ab28636bc91630c6f10752757ac8b738e78e8528edb6f8caa535cdbd4a51a2bbe818bc6c7ed35b8b5b47a123f7ad5a5651c5b630a60a3d4e46ce5f83a3adc48aaa5f12323e9c641ddf75c762c7c9197fcc0c03bd9789b59c1a046a2e4e7428dc9fb21f5967af30b0e0d533dfb51459302099e89a75b25922b39595d3d86efa2be670c328354ed866f80bdb680936594242ddd491ea237c49de5a44678b98a97356c4d39bff75604df532ba4324eb02ca520979ffd09481ba50da3111e12b02fbed9f336d6abde4df792495356e3548a6c1a4c740ae82b220e8d2b81de1bf97a82ed542f25ba6ae4e55392cefad6d9ec9b18ae0cd354c296b4c36b673624e160ac684e643cb6f1bf73fcfe568b4dd01179889dfb4";
        let raw = const_hex::decode(hex).expect("hex");
        let AnyBlockData::MergeMined(m) = decode_any_block_data(raw.as_slice()).expect("decode")
        else {
            panic!("expected merge-mined block");
        };
        assert_eq!(m.compute_hash().to_string(), expected);
    }

    #[test]
    fn roundtrip_regular_tx_with_fee_header() {
        let outputs = vec![TxOutput {
            value: NonZero::new(500u64).unwrap(),
            token_data: 0,
            script: Bytes::from_static(b"s"),
        }];
        let fee = FeeHeader {
            fees: vec![
                FeeHeaderEntry {
                    token: TokenUid(Hash32([0xAA; 32])),
                    amount: 100.try_into().unwrap(),
                },
                FeeHeaderEntry {
                    token: TokenUid(Hash32([0xBB; 32])),
                    amount: 200.try_into().unwrap(),
                },
            ],
        };
        let headers = vec![AnyHeader::Fee(fee)];

        let rt = RegularTransactionData {
            signal_bits: SignalBits(0x00),
            tokens: vec![],
            inputs: vec![],
            outputs,
            weight: Weight::new(1.0).unwrap(),
            timestamp: Timestamp(999),
            tx_parents: [
                TransactionId(VertexId(Hash32([0x55; 32]))),
                TransactionId(VertexId(Hash32([0x66; 32]))),
            ],
            nonce: 0x01020304,
            headers,
        };

        let mut buf = BytesMut::new();
        let any = AnyTransactionData::from(rt.clone());
        encode_any_transaction_data(&mut buf, &any).expect("encode");
        let decoded = decode_any_transaction_data(buf.freeze()).expect("decode");
        assert_eq!(decoded, AnyTransactionData::from(rt));
    }

    #[test]
    fn regular_tx_fee_header_impacts_hash() {
        let outputs = vec![TxOutput {
            value: NonZero::new(1u64).unwrap(),
            token_data: 0,
            script: Bytes::new(),
        }];
        let base = RegularTransactionData {
            signal_bits: SignalBits(0x00),
            tokens: vec![],
            inputs: vec![],
            outputs,
            weight: Weight::new(1.0).unwrap(),
            timestamp: Timestamp(1),
            tx_parents: [
                TransactionId(VertexId(Hash32([0x01; 32]))),
                TransactionId(VertexId(Hash32([0x02; 32]))),
            ],
            nonce: 1,
            headers: vec![],
        };
        let h1 = AnyHeader::Fee(FeeHeader {
            fees: vec![FeeHeaderEntry {
                token: TokenUid(Hash32([0x77; 32])),
                amount: 10.try_into().unwrap(),
            }],
        });
        let h2 = AnyHeader::Fee(FeeHeader {
            fees: vec![FeeHeaderEntry {
                token: TokenUid(Hash32([0x77; 32])),
                amount: 11.try_into().unwrap(),
            }],
        });
        let mut a = base.clone();
        a.headers = vec![h1];
        let mut b = base.clone();
        b.headers = vec![h2];
        assert_ne!(a.compute_hash(), b.compute_hash());
    }

    #[test]
    fn token_creation_headers_impact_hash() {
        let outputs = vec![TxOutput {
            value: NonZero::new(1000u64).unwrap(),
            token_data: 0,
            script: Bytes::from_static(b"s"),
        }];
        let base = TokenCreationTransactionData {
            signal_bits: SignalBits(0x00),
            inputs: vec![],
            outputs,
            token_kind: TokenKind::Deposit,
            name: "X".into(),
            symbol: "X".into(),
            weight: Weight::new(1.0).unwrap(),
            timestamp: Timestamp(1),
            tx_parents: [
                TransactionId(VertexId(Hash32([0x11; 32]))),
                TransactionId(VertexId(Hash32([0x22; 32]))),
            ],
            nonce: 1,
            headers: vec![],
        };
        let header1 = AnyHeader::Nano(NanoHeader {
            seqnum: 1,
            id: VertexId(Hash32([0xAB; 32])),
            method: "".into(),
            args: Bytes::new(),
            actions: vec![],
            address: Address([0u8; 25]),
            script: Bytes::new(),
        });
        let header2 = AnyHeader::Nano(NanoHeader {
            seqnum: 2,
            ..match &header1 {
                AnyHeader::Nano(n) => n.clone(),
                _ => unreachable!(),
            }
        });

        let mut a = base.clone();
        a.headers = vec![header1];
        let mut b = base.clone();
        b.headers = vec![header2];

        let ha = a.compute_hash();
        let hb = b.compute_hash();
        assert_ne!(ha, hb);
    }

    #[test]
    fn on_chain_blueprint_headers_impact_hash() {
        let outputs = vec![TxOutput {
            value: NonZero::new(42u64).unwrap(),
            token_data: 0,
            script: Bytes::from_static(b"p2pkh"),
        }];
        let base = OnChainBlueprintData {
            signal_bits: SignalBits(0x00),
            tokens: vec![],
            inputs: vec![],
            outputs,
            ocb_kind: OcbKind::PythonZlib,
            code: Bytes::from_static(b"\x01\x78\x9c"),
            nc_pubkey: Bytes::from_static(b"02dead"),
            nc_signature: Bytes::from_static(b"30"),
            weight: Weight::new(2.0).unwrap(),
            timestamp: Timestamp(2),
            tx_parents: [
                TransactionId(VertexId(Hash32([0x33; 32]))),
                TransactionId(VertexId(Hash32([0x44; 32]))),
            ],
            nonce: 2,
            headers: vec![],
        };
        let header1 = AnyHeader::Nano(NanoHeader {
            seqnum: 10,
            id: VertexId(Hash32([0xCD; 32])),
            method: "m".into(),
            args: Bytes::from_static(b"{}"),
            actions: vec![],
            address: Address([0xFFu8; 25]),
            script: Bytes::new(),
        });
        let header2 = AnyHeader::Nano(NanoHeader {
            seqnum: 11,
            ..match &header1 {
                AnyHeader::Nano(n) => n.clone(),
                _ => unreachable!(),
            }
        });

        let mut a = base.clone();
        a.headers = vec![header1];
        let mut b = base.clone();
        b.headers = vec![header2];

        let ha = a.compute_hash();
        let hb = b.compute_hash();
        assert_ne!(ha, hb);
    }
}
