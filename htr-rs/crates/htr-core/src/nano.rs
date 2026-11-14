// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use crate::crypto::{DigestAlgorithm, DigestContext};
use bytes::{Bytes, BytesMut};
use std::collections::HashMap;
use std::fmt;
use std::iter::Iterator;
use std::str::FromStr;

use crate::common::{Hash32, Hash32ParseError};
use crate::utils::forward_try_from_slice;
use crate::utils::serde_hex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::array::TryFromSliceError;

#[repr(transparent)]
#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    derive_more::Deref,
    derive_more::From,
    derive_more::Into,
    derive_more::AsRef,
    derive_more::Display,
    derive_more::FromStr,
    Serialize,
    Deserialize,
)]
#[display("{_0}")]
#[serde(transparent)]
pub struct NodeId(pub Hash32);
forward_try_from_slice!(NodeId, Hash32);

type ChildrenMap = HashMap<Key, NodeId>;

#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Key(pub Bytes);

impl Key {
    pub fn empty() -> Self {
        Self(Bytes::new())
    }
}

impl AsRef<[u8]> for Key {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl FromStr for Key {
    type Err = Hash32ParseError;
    fn from_str(hex: &str) -> Result<Self, Self::Err> {
        if hex.starts_with("0x") {
            return Err(const_hex::FromHexError::InvalidHexCharacter { c: 'x', index: 1 }.into());
        }
        let need = hex.len() / 2;
        let mut buf = BytesMut::with_capacity(need);
        // Ensure we provide a properly sized output slice
        buf.resize(need, 0);
        const_hex::decode_to_slice(hex, &mut buf[..])?;
        Ok(Key(buf.freeze()))
    }
}

impl fmt::Display for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", const_hex::encode(&self.0))
    }
}

impl Serialize for Key {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Key {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// content can be empty (None is equivalent to b""), children can be empty, but if given it is an
/// iterator over the node-id of each child, it will be sorted internally sort the input order is
/// not important and the most performant iterator should be used
pub fn calculate_id<'a>(
    key: impl AsRef<[u8]>,
    content: Option<impl AsRef<[u8]>>,
    children: Option<impl Iterator<Item = &'a [u8]>>,
) -> NodeId {
    let mut ctx = DigestContext::new(DigestAlgorithm::Sha256);
    ctx.update(key.as_ref());
    if let Some(content) = content {
        ctx.update(content.as_ref());
    }
    if let Some(children) = children {
        // Collect and sort children to make the hash order-independent
        let mut child_ids: Vec<&[u8]> = children.collect();
        child_ids.sort();
        for child_node_id in child_ids {
            ctx.update(child_node_id);
        }
    }
    NodeId(ctx.finalize())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Node {
    pub id: NodeId,
    pub key: Key,
    #[serde(
        default,
        with = "serde_hex::opt_bytes",
        skip_serializing_if = "Option::is_none"
    )]
    pub content: Option<Bytes>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub children: Option<ChildrenMap>,
}

impl Node {
    pub fn empty() -> Self {
        Self {
            id: calculate_id(
                b"",
                Option::<&[u8]>::None,
                Option::<std::iter::Empty<&[u8]>>::None,
            ),
            key: Key::empty(),
            content: None,
            children: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};

    #[test]
    fn empty_node_id() {
        let empty_node = Node::empty();
        // original in hathor-core:
        // >>> Node(key=b'', length=0).calculate_id().hex()
        // expected: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let expected = b"\xe3\xb0\xc4\x42\x98\xfc\x1c\x14\x9a\xfb\xf4\xc8\x99\x6f\xb9\x24\x27\xae\x41\xe4\x64\x9b\x93\x4c\xa4\x95\x99\x1b\x78\x52\xb8\x55";
        assert_eq!(empty_node.id.as_bytes(), expected);
    }

    #[test]
    fn non_empty_content_changes_id() {
        let key = b"k";
        let content = b"content";
        let id = calculate_id(
            key,
            Some(&content[..]),
            Option::<std::iter::Empty<&[u8]>>::None,
        );
        // original in hathor-core:
        // >>> Node(key=b'k', content=b'content', length=0).calculate_id().hex()
        // expected: 6bf64c8417a9c4a5ac7bc4c86048f438365ae15cf715b8aadc445547ceea9dc3
        let expected = b"\x6b\xf6\x4c\x84\x17\xa9\xc4\xa5\xac\x7b\xc4\xc8\x60\x48\xf4\x38\x36\x5a\xe1\x5c\xf7\x15\xb8\xaa\xdc\x44\x55\x47\xce\xea\x9d\xc3";
        assert_eq!(id.as_bytes(), expected);
    }

    #[test]
    fn children_order_independent() {
        let c1 = [0x00; 32];
        let c2 = [0x10; 32];
        let c3 = [0xff; 32];

        let key = b"key";
        let content = b"data";

        let id_a = calculate_id(
            key,
            Some(&content[..]),
            Some([c3.as_ref(), c1.as_ref(), c2.as_ref()].into_iter()),
        );
        let id_b = calculate_id(
            key,
            Some(&content[..]),
            Some([c2.as_ref(), c3.as_ref(), c1.as_ref()].into_iter()),
        );
        let id_c = calculate_id(
            key,
            Some(&content[..]),
            Some([c1.as_ref(), c2.as_ref(), c3.as_ref()].into_iter()),
        );
        assert_eq!(id_a.as_ref(), id_b.as_ref());
        assert_eq!(id_b.as_ref(), id_c.as_ref());

        // original in hathor-core:
        // >>> Node(key=b'key', content=b'data', length=0, children={b'1': bytes([0x10]*32), b'2': bytes([0xff]*32), b'3': bytes([0x00]*32)}).calculate_id().hex()
        // expected: 3e498c87a4650f1fac8d0580b072da4f868a75cc4817c4f21c51b60e37313946
        let expected = b"\x3e\x49\x8c\x87\xa4\x65\x0f\x1f\xac\x8d\x05\x80\xb0\x72\xda\x4f\x86\x8a\x75\xcc\x48\x17\xc4\xf2\x1c\x51\xb6\x0e\x37\x31\x39\x46";
        assert_eq!(id_a.as_bytes(), expected);
    }

    #[test]
    fn serde_node_hex_content_and_children() {
        // Build a node with content and children
        let mut children: ChildrenMap = HashMap::new();
        let k1: Key = "aa".parse().unwrap();
        let k2: Key = "bb".parse().unwrap();
        let id1: NodeId = Hash32::from_slice(&[0u8; 32]).unwrap().into();
        let id2: NodeId = Hash32::from_slice(&[0xffu8; 32]).unwrap().into();
        children.insert(k1, id1);
        children.insert(k2, id2);

        let n = Node {
            id: Node::empty().id,
            key: Key::empty(),
            content: Some(Bytes::from_static(b"\x01\x02\x03")),
            children: Some(children.clone()),
        };

        // Serialize to JSON and verify hex content and map keys
        let s = serde_json::to_string(&n).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert_eq!(v["content"], json!("010203"));
        let obj = v["children"].as_object().unwrap();
        assert!(obj.contains_key("aa") && obj.contains_key("bb"));

        // Round-trip: deserialize from a hand-written JSON
        let j = r#"{
            "id": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "key": "",
            "content": "ffff",
            "children": {
                "aa": "c0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696",
                "bb": "a0f19299c2a4dcbb6613a14011ff07b63d6cb809e4cee25e9c1ccccdd6628696"
            }
        }"#;
        let parsed: Node = serde_json::from_str(j).unwrap();
        assert_eq!(parsed.content.as_deref().unwrap(), &b"\xff\xff"[..]);
        assert_eq!(parsed.children.unwrap().len(), 2);
    }

    #[test]
    fn serde_skips_empty_fields() {
        // content is None and children is None → both skipped in JSON
        let n = Node {
            id: Node::empty().id,
            key: Key::empty(),
            content: None,
            children: None,
        };
        let s = serde_json::to_string(&n).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert!(v.get("content").is_none());
        assert!(v.get("children").is_none());

        // Missing fields round-trip to None
        let back: Node = serde_json::from_str(&s).unwrap();
        assert_eq!(back.content, None);
        assert_eq!(back.children, None);
    }

    #[test]
    fn serde_dont_skips_quasi_empty_fields() {
        // content is Some(empty content) and children is Some(empty content) → neither skipped in JSON
        let n = Node {
            id: Node::empty().id,
            key: Key::empty(),
            content: Some(Bytes::new()),
            children: Some(HashMap::new()),
        };
        let s = serde_json::to_string(&n).unwrap();
        let v: Value = serde_json::from_str(&s).unwrap();
        assert!(v.get("content").is_some());
        assert!(v.get("children").is_some());

        // Missing fields round-trip to Some(~empty)
        let back: Node = serde_json::from_str(&s).unwrap();
        assert_eq!(back.content.as_deref().unwrap(), &b""[..]);
        assert_eq!(back.children.unwrap().len(), 0);
    }
}
