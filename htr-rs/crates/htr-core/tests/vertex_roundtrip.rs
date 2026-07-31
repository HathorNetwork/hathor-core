// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

//! Round-trip tests for the vertex codec against reference-serialized vectors.
//!
//! The hex vectors are real on-wire bytes produced by the Python reference implementation
//! (mirrored from `hathor_tests/tx/test_tx_deserialization.py`). Decoding then re-encoding must
//! reproduce them byte-for-byte, which proves the Rust codec round-trips the reference wire format
//! — and, unlike the unit tests in `vertex/`, exercises full real vertices (inputs, outputs,
//! scripts, AuxPoW, token info) rather than minimal hand-built ones. This fails fast in CI without
//! the Python toolchain.

use htr_core::vertex::{decode_any_vertex_data, encode_any_vertex_data};

/// Decode a hex string of full bytes. Panics on odd length or non-hex input — test-only.
fn hex_to_bytes(s: &str) -> Vec<u8> {
    assert!(
        s.len().is_multiple_of(2),
        "hex string must have even length"
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("valid hex"))
        .collect()
}

fn assert_vertex_roundtrip(name: &str, hex: &str) {
    let bytes = hex_to_bytes(hex);
    let vertex = decode_any_vertex_data(bytes.as_slice())
        .unwrap_or_else(|e| panic!("decode {name} failed: {e}"));
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    encode_any_vertex_data(&mut out, &vertex)
        .unwrap_or_else(|e| panic!("encode {name} failed: {e}"));
    assert_eq!(
        out, bytes,
        "re-encoded {name} diverged from reference bytes"
    );
}

const REGULAR_BLOCK: &str = concat!(
    "0000010000190000001976a9143d6dbcbf6e67b2cbcc3225994756a56a5e2d3a2788ac40350000000000005",
    "e0f84de03000006cb93385b8b87a545a1cbb6197e6caff600c12cc12fc54250d39c8088fc0002d4d2a15def",
    "7604688e1878ab681142a7b155cbe52a6b4e031250ae96db0a0002ad8d1519daaddc8e1a37b14aac0b04512",
    "9c01832281fb1c02d873c7abbf9623731383164323332613136626139353030316465323264333135316230",
    "3237652d38336231356462333436393734386262623962623933303638613836333634362d6365326637376",
    "23939313037343461316231366565666630663032316130663200000002000000000000000080326758",
);

const MERGE_MINED_BLOCK: &str = concat!(
    "00030100000c8000001976a914980f1b0f1c7a7a6c42be02df5ede0bf2785adaba88ac4050357517a827ea",
    "608334c303000000000000000021d76c80fbd19f2ddbb9d6ac15dcc76d3555585984f1d93600000000939f",
    "2222fcbc4128f4a16b56a7b971f4e7a334d866d636c4356c6be300000000b7f4fb8573e2110989fd48968e",
    "729a8a3f3004a37bc57227ce944b5b0000a07b248cca37a8e6144fa66bbcc7feafbf06d412556b946d4ccc",
    "03000000000000000032010000000100000000000000000000000000000000000000000000000000000000",
    "00000000ffffffff3d038b720a48617468405a554c55506f6f4c2d4243484e0007178052000000ffffffff",
    "01abba5d25000000001976a9141fd680935cd42f95702493d44c8de964a42656b588ac000000000c0007f3",
    "2f902f6a69cf0ce343e653da8ff02491a438ef23c8980f426d8856bfbe5ae313742fb14b4aaafc408e42d5",
    "535fdf0277f6f6bf6365cabb4630f5dfac7495905b267569f02af2aea67f7251b8e2be11c3e0bcd64138d3",
    "5061c94cb6dcdce57983a8ca6b45f9bba4b30fd676b5aa6f3ab165c04acf134c5c6f0ae29b71c50d85a561",
    "d31f9f1aabf06a92e2afc3bb7e1890577b99327057f05a2c7dc4e60c537996c7a1281001e7a35f3942f78d",
    "503e6d664324ad551f57e14d9cf3cba3d323529f5a40ee4a1b921eaadeade3a065e6d909179bddc59e26d5",
    "bf6d5f62b52f57587a1999ce1d873b2c78a35f831edc399f1b34cdec33bc524ecb18a737b0da285443ddd5",
    "fc72d506d71202b64c4dc9c14f224ec7496313b41bf7813ded6ff99ac61d3cd0bcb5b538ab8a7a2a7f4cd0",
    "a0425e2c1da057367a56c69c37d2d039b30ae82992eb80fe6058cf2d2c23e2f5dfaa4a16208b7672ed6afe",
    "34054d41a52aba7b8fd5483b83bc8c361b667eda73286be0fcba763583a65853a06e1b8f14ad3483608ad4",
    "03180a130afe",
);

const REGULAR_TRANSACTION: &str = concat!(
    "000100010200000000b7f4fb8573e2110989fd48968e729a8a3f3004a37bc57227ce944b5b0000694630440",
    "220139d8549e6e9be0dbf8f239f0a76a410c79861f62d66e58579fc34982e9c26be022041100a9a32da836f",
    "524b28c6a9397e44ed94979e106decdafeec7df735b172dd21030d8a0db18eed94e16d58651b6446a47dc12",
    "1088321e36d8c2da1069fad13bd850000923900001976a91430e129a98a497cdc3c46a6a8390ad606bb62b0",
    "3088ac007276a300001976a914b3c38f156655a508ea1157da7336d3f63d8e6ebb88ac4035152270ab19ca6",
    "08334890200000000b7f4fb8573e2110989fd48968e729a8a3f3004a37bc57227ce944b5b000000009332ed",
    "6f9347dad83dff1ea73fc49c34765c24ba100bfd12bef86aed33d7d5ce",
);

const TOKEN_CREATION_TRANSACTION: &str = concat!(
    "00020104000005551d7740fd7d3c0acc50b5677fdd844f1225985aa431e1712af2a2fd8900006a473045022",
    "100a445edb5cd6c79a0a7b5ed837582fd65b8d511ee60b64fd076e07bd8f63f75a202202dca24320bffc4c3",
    "ca2a07cdfff38f7c839bde70ed49ef634ac6588972836cab2103bfa995d676e3c0ed7b863c74cfef9683fab",
    "3163b42b6f21442326a023fc57fba0000264800001976a9146876f9578221fdb678d4e8376503098a9228b1",
    "3288ac00004e2001001976a914031761ef85a24603203c97e75af355b83209f08f88ac0000000181001976a",
    "9149f091256cb98649c7c35df0aad44d7805710691e88ac0000000281001976a914b1d7a5ee505ad4d3b93e",
    "a1a5162ba83d5049ec4e88ac0109546f5468654d6f6f6e04f09f9a804034a52aec6cece75e0fc0e30200001",
    "a72272f48339fcc5d5ec5deaf197855964b0eb912e8c6eefe00928b6cf600001055641c20b71871ed2c5c7d",
    "4096a34f40888d79c25bce74421646e732dc01ff7369",
);

#[test]
fn regular_block_roundtrip() {
    assert_vertex_roundtrip("regular_block", REGULAR_BLOCK);
}

#[test]
fn merge_mined_block_roundtrip() {
    assert_vertex_roundtrip("merge_mined_block", MERGE_MINED_BLOCK);
}

#[test]
fn regular_transaction_roundtrip() {
    assert_vertex_roundtrip("regular_transaction", REGULAR_TRANSACTION);
}

#[test]
fn token_creation_transaction_roundtrip() {
    assert_vertex_roundtrip("token_creation_transaction", TOKEN_CREATION_TRANSACTION);
}

#[test]
fn empty_input_is_rejected() {
    assert!(decode_any_vertex_data([].as_slice()).is_err());
}

#[test]
fn truncated_input_reports_incomplete() {
    // signal_bits + kind=RegularBlock parse, then the outputs-length byte is missing.
    let err = decode_any_vertex_data([0u8, 0u8].as_slice()).expect_err("must be incomplete");
    assert_eq!(err.to_string(), "incomplete input: need 1");
}
