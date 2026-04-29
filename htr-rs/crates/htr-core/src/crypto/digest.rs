// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::common::Hash32;

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Algorithm {
    Sha256,
}

/// Streaming SHA-256 context with a backend-agnostic API.
pub struct Context(backend::Context);

impl Context {
    #[inline]
    pub fn new(algo: Algorithm) -> Self {
        Self(backend::Context::new(algo.into()))
    }

    #[inline]
    pub fn new_sha256() -> Self {
        Self(backend::Context::new(Algorithm::Sha256.into()))
    }

    #[inline]
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.0.update(data.as_ref());
    }

    #[inline]
    pub fn finalize(self) -> Hash32 {
        let mut out = Hash32([0u8; 32]);
        out.0.copy_from_slice(self.0.finish().as_ref());
        out
    }
}

pub(super) mod helpers {
    use super::*;

    /// Convenience: hash a bytes slice with SHA-256.
    #[inline]
    pub fn sha256<B: AsRef<[u8]>>(data: B) -> Hash32 {
        let mut ctx = Context::new(Algorithm::Sha256);
        ctx.update(data);
        ctx.finalize()
    }

    /// Convenience: hash a bytes slice with double SHA-256.
    #[inline]
    pub fn sha256d<B: AsRef<[u8]>>(data: B) -> Hash32 {
        sha256(sha256(data))
    }

    #[inline]
    pub fn sha256d_rev<B: AsRef<[u8]>>(data: B) -> Hash32 {
        sha256(sha256(data)).reversed()
    }

    /// Convenience: hash a sequence of byte slices with SHA-256.
    #[inline]
    pub fn sha256_concat<B: AsRef<[u8]>, I: IntoIterator<Item = B>>(parts: I) -> Hash32 {
        let mut ctx = Context::new(Algorithm::Sha256);
        for p in parts {
            ctx.update(p);
        }
        ctx.finalize()
    }

    /// Convenience: hash a sequence of byte slices with double SHA-256.
    #[inline]
    pub fn sha256d_concat<B: AsRef<[u8]>, I: IntoIterator<Item = B>>(parts: I) -> Hash32 {
        sha256(sha256_concat(parts))
    }

    #[inline]
    pub fn sha256d_concat_rev<B: AsRef<[u8]>, I: IntoIterator<Item = B>>(parts: I) -> Hash32 {
        sha256(sha256_concat(parts)).reversed()
    }

    pub fn sha256d_simple_merkle_root<I: IntoIterator<Item = Hash32>>(hashes: I) -> Hash32 {
        hashes
            .into_iter()
            .reduce(|a, b| sha256d_concat_rev([a.reversed(), b.reversed()]))
            .unwrap_or(Hash32::zero())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h32_to_hex(h: &Hash32) -> String {
        h.to_string()
    }

    fn hex_to_h32(h: &str) -> Hash32 {
        let v = const_hex::decode(h).expect("must be hex");
        v.as_slice().try_into().expect("must be 32 bytes")
    }

    #[test]
    fn sha256_known_vectors() {
        // Empty string
        let h = helpers::sha256(&b""[..]);
        assert_eq!(
            h32_to_hex(&h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );

        // "abc"
        let h = helpers::sha256(b"abc");
        assert_eq!(
            h32_to_hex(&h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );

        // "hello world"
        let h = helpers::sha256(b"hello world");
        assert_eq!(
            h32_to_hex(&h),
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
    }

    #[test]
    fn sha256s_known_vectors() {
        // Empty string
        let h = helpers::sha256d(&b""[..]);
        assert_eq!(
            h32_to_hex(&h),
            "5df6e0e2761359d30a8275058e299fcc0381534545f55cf43e41983f5d4c9456"
        );

        // "abc"
        let h = helpers::sha256d(b"abc");
        assert_eq!(
            h32_to_hex(&h),
            "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
        );

        // "hello world"
        let h = helpers::sha256d(b"hello world");
        assert_eq!(
            h32_to_hex(&h),
            "bc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423"
        );
    }

    #[test]
    fn sha256_double_matches_two_passes() {
        for msg in [b"".as_ref(), b"abc".as_ref(), b"hello world".as_ref()] {
            let h1 = helpers::sha256(msg);
            let expected = helpers::sha256(h1);
            assert_eq!(helpers::sha256d(msg), expected);
        }
    }

    #[test]
    fn concat_matches_single_buffer() {
        let parts = [b"abc".as_ref(), b"def".as_ref()];
        let h_concat = helpers::sha256_concat(parts.iter().copied());
        let h_single = helpers::sha256(b"abcdef");
        assert_eq!(h_concat, h_single);

        let hd_concat = helpers::sha256d_concat([b"abc".as_ref(), b"def".as_ref()]);
        let hd_single = helpers::sha256d(b"abcdef");
        assert_eq!(hd_concat, hd_single);
    }

    #[test]
    fn coinbase_merkle_root() {
        let merkle_path: [Hash32; _] = [
            hex_to_h32("32a31fb3f8596e5de0a40a53748839d15e0a1a1d264da5b7dacec9209a59fd2a"),
            hex_to_h32("45c5dcbe62075d366b87fa375fb919c7a8ede24eba0a3a094df491aef55184ca"),
            hex_to_h32("6caec8ea3732c953fa195320bb26d2e9f630be5edf384a48e42e26ae7198f844"),
            hex_to_h32("188c78ef10ce002f2fc3cf8f445d4d1aa12d5f3ce32420e565c9d3cc4d64d8a2"),
            hex_to_h32("67ce1464dc89e67dd30acf8adf74c7ec37fa9f14040b7ecd9127391af1b25f2a"),
            hex_to_h32("ee017b11d10898f3b19194f43d9b5b9cf443b8e992797e49f4edd603fee060c7"),
        ];
        // only 1 element, result is itself
        let h = sha256d_simple_merkle_root(merkle_path[..1].iter().copied());
        assert_eq!(h, merkle_path[0]);
        // 2 elements, one round
        let h = sha256d_simple_merkle_root(merkle_path[..2].iter().copied());
        let e = hex_to_h32("b17a3632d72a1e85d3a2adfcf2d9e24f7dc7664003317ea3fad5a288014f2435");
        assert_eq!(h, e);
        // 3 elements, two rounds (loops correctly)
        let h = sha256d_simple_merkle_root(merkle_path[..3].iter().copied());
        let e = hex_to_h32("1f4e62c8ad160080ff2b40c0933b7f3f8726c3b413d5d1372f8bdabfbe1cf728");
        assert_eq!(h, e);
        // full example
        let h = sha256d_simple_merkle_root(merkle_path[..].iter().copied());
        let e = hex_to_h32("8927d337549640aaafdaa0dcbdb9c09972533a66bfb287aba3eb9c1be5b523ba");
        assert_eq!(h, e);
    }
}
