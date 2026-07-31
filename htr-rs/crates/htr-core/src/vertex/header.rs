// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AnyHeader {
    Nano(NanoHeader),
    Fee(FeeHeader),
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, derive_more::TryFrom)]
#[try_from(repr)]
#[repr(u8)]
pub enum HeaderKind {
    Nano = 0x10,
    Fee = 0x11,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NanoHeaderAction {
    Deposit { index: u8, amount: OutputValue },
    Withdrawal { index: u8, amount: OutputValue },
    GrantAuthority { index: u8, mint: bool, melt: bool },
    AcquireAuthority { index: u8, mint: bool, melt: bool },
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NanoHeader {
    pub seqnum: u64,
    pub id: VertexId,
    pub method: String,
    pub args: Bytes,
    pub actions: Vec<NanoHeaderAction>,
    pub address: Address,
    pub script: Bytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FeeHeaderEntry {
    pub token: TokenUid,
    pub amount: OutputValue,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FeeHeader {
    pub fees: Vec<FeeHeaderEntry>,
}
