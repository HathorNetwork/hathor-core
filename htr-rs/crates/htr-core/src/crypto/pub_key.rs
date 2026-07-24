// SPDX-FileCopyrightText: Hathor Labs
// SPDX-License-Identifier: Apache-2.0

use super::*;
use der::Decode;
use spki::SubjectPublicKeyInfoRef;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey(pub(super) SubjectPublicKeyInfoDer<'static>);

impl PublicKey {
    /// Parse and validate a DER-encoded SubjectPublicKeyInfo structure.
    pub fn from_slice(v: &[u8]) -> Result<Self, PublicKeyParseError> {
        SubjectPublicKeyInfoRef::from_der(v).map_err(|_| PublicKeyParseError::Der)?;
        Ok(Self(SubjectPublicKeyInfoDer::from(v).into_owned()))
    }

    pub fn gen_peer_id(&self) -> crate::peer::PeerId {
        sha256d(&*self.0).into()
    }

    pub fn as_der(&self) -> &[u8] {
        self.0.as_ref()
    }
}

// Infallible conversion from already-wrapped DER. This path does not re-validate.
impl<'a> From<SubjectPublicKeyInfoDer<'a>> for PublicKey {
    fn from(der: SubjectPublicKeyInfoDer<'a>) -> Self {
        Self(der.into_owned())
    }
}

#[derive(Error, Debug, PartialEq)]
pub enum PublicKeyParseError {
    #[error("{0}")]
    Base64(#[from] base64::DecodeError),
    #[error("invalid SubjectPublicKeyInfo DER")]
    Der,
}

impl FromStr for PublicKey {
    type Err = PublicKeyParseError;

    #[inline]
    fn from_str(b64: &str) -> Result<Self, Self::Err> {
        // trim to preserve behavior from Python
        let bytes = BASE64_STANDARD.decode(b64.trim())?;
        PublicKey::from_slice(&bytes)
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", BASE64_STANDARD.encode(self.0.as_ref()))
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_slice() {
        let pubkey_bytes = vec![
            48u8, 130, 1, 34, 48, 13, 6, 9, 42, 134, 72, 134, 247, 13, 1, 1, 1, 5, 0, 3, 130, 1,
            15, 0, 48, 130, 1, 10, 2, 130, 1, 1, 0, 189, 183, 179, 49, 224, 211, 110, 188, 185,
            158, 87, 219, 255, 94, 45, 137, 50, 233, 236, 122, 47, 217, 161, 194, 82, 86, 134, 183,
            49, 84, 74, 8, 248, 30, 75, 82, 71, 0, 137, 143, 111, 116, 246, 131, 127, 121, 157, 37,
            177, 143, 175, 129, 234, 115, 68, 215, 182, 46, 231, 9, 211, 20, 172, 70, 4, 233, 197,
            173, 215, 158, 196, 5, 135, 194, 238, 17, 161, 118, 34, 156, 129, 12, 84, 230, 101,
            142, 202, 153, 160, 60, 158, 156, 211, 0, 168, 156, 67, 51, 7, 37, 20, 207, 57, 176,
            116, 137, 86, 102, 252, 104, 151, 65, 161, 171, 180, 4, 122, 11, 59, 17, 5, 156, 130,
            229, 216, 193, 65, 221, 80, 237, 75, 71, 204, 20, 119, 223, 60, 199, 6, 248, 106, 37,
            1, 81, 156, 125, 154, 190, 167, 113, 206, 28, 10, 178, 39, 8, 112, 51, 210, 63, 236,
            170, 160, 88, 247, 183, 34, 40, 183, 91, 155, 53, 245, 1, 139, 102, 245, 1, 158, 186,
            179, 246, 169, 203, 105, 142, 205, 26, 215, 45, 83, 177, 199, 223, 193, 205, 179, 252,
            17, 239, 155, 228, 141, 172, 76, 218, 78, 187, 9, 129, 144, 77, 203, 85, 198, 113, 123,
            85, 166, 183, 158, 111, 157, 140, 235, 147, 203, 165, 23, 45, 241, 113, 126, 212, 157,
            100, 67, 85, 151, 171, 62, 164, 68, 125, 190, 68, 172, 8, 172, 33, 82, 111, 181, 187,
            155, 163, 2, 3, 1, 0, 1,
        ];
        let parsed = PublicKey::from_slice(&pubkey_bytes[..]).expect("valid SPKI DER");
        assert_eq!(
            parsed,
            PublicKey(SubjectPublicKeyInfoDer::from(pubkey_bytes))
        );
    }

    #[test]
    fn from_str() {
        let reference = PublicKey(SubjectPublicKeyInfoDer::from(&b"\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x00\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xbd\xb7\xb3\x31\xe0\xd3\x6e\xbc\xb9\x9e\x57\xdb\xff\x5e\x2d\x89\x32\xe9\xec\x7a\x2f\xd9\xa1\xc2\x52\x56\x86\xb7\x31\x54\x4a\x08\xf8\x1e\x4b\x52\x47\x00\x89\x8f\x6f\x74\xf6\x83\x7f\x79\x9d\x25\xb1\x8f\xaf\x81\xea\x73\x44\xd7\xb6\x2e\xe7\x09\xd3\x14\xac\x46\x04\xe9\xc5\xad\xd7\x9e\xc4\x05\x87\xc2\xee\x11\xa1\x76\x22\x9c\x81\x0c\x54\xe6\x65\x8e\xca\x99\xa0\x3c\x9e\x9c\xd3\x00\xa8\x9c\x43\x33\x07\x25\x14\xcf\x39\xb0\x74\x89\x56\x66\xfc\x68\x97\x41\xa1\xab\xb4\x04\x7a\x0b\x3b\x11\x05\x9c\x82\xe5\xd8\xc1\x41\xdd\x50\xed\x4b\x47\xcc\x14\x77\xdf\x3c\xc7\x06\xf8\x6a\x25\x01\x51\x9c\x7d\x9a\xbe\xa7\x71\xce\x1c\x0a\xb2\x27\x08\x70\x33\xd2\x3f\xec\xaa\xa0\x58\xf7\xb7\x22\x28\xb7\x5b\x9b\x35\xf5\x01\x8b\x66\xf5\x01\x9e\xba\xb3\xf6\xa9\xcb\x69\x8e\xcd\x1a\xd7\x2d\x53\xb1\xc7\xdf\xc1\xcd\xb3\xfc\x11\xef\x9b\xe4\x8d\xac\x4c\xda\x4e\xbb\x09\x81\x90\x4d\xcb\x55\xc6\x71\x7b\x55\xa6\xb7\x9e\x6f\x9d\x8c\xeb\x93\xcb\xa5\x17\x2d\xf1\x71\x7e\xd4\x9d\x64\x43\x55\x97\xab\x3e\xa4\x44\x7d\xbe\x44\xac\x08\xac\x21\x52\x6f\xb5\xbb\x9b\xa3\x02\x03\x01\x00\x01"[..]));
        assert_eq!(
            reference,
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbezMeDTbry5nlfb/14tiTLp7Hov2aHCUlaGtzFUSgj4HktSRwCJj2909oN/eZ0lsY+vgepzRNe2LucJ0xSsRgTpxa3XnsQFh8LuEaF2IpyBDFTmZY7KmaA8npzTAKicQzMHJRTPObB0iVZm/GiXQaGrtAR6CzsRBZyC5djBQd1Q7UtHzBR33zzHBvhqJQFRnH2avqdxzhwKsicIcDPSP+yqoFj3tyIot1ubNfUBi2b1AZ66s/apy2mOzRrXLVOxx9/BzbP8Ee+b5I2sTNpOuwmBkE3LVcZxe1Wmt55vnYzrk8ulFy3xcX7UnWRDVZerPqREfb5ErAisIVJvtbubowIDAQAB".parse().expect("should parse")
        );
        // should ignore spaces:
        assert_eq!(
            reference,
            "   MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbezMeDTbry5nlfb/14tiTLp7Hov2aHCUlaGtzFUSgj4HktSRwCJj2909oN/eZ0lsY+vgepzRNe2LucJ0xSsRgTpxa3XnsQFh8LuEaF2IpyBDFTmZY7KmaA8npzTAKicQzMHJRTPObB0iVZm/GiXQaGrtAR6CzsRBZyC5djBQd1Q7UtHzBR33zzHBvhqJQFRnH2avqdxzhwKsicIcDPSP+yqoFj3tyIot1ubNfUBi2b1AZ66s/apy2mOzRrXLVOxx9/BzbP8Ee+b5I2sTNpOuwmBkE3LVcZxe1Wmt55vnYzrk8ulFy3xcX7UnWRDVZerPqREfb5ErAisIVJvtbubowIDAQAB".parse().expect("should parse")
        );
        assert_eq!(
            reference,
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbezMeDTbry5nlfb/14tiTLp7Hov2aHCUlaGtzFUSgj4HktSRwCJj2909oN/eZ0lsY+vgepzRNe2LucJ0xSsRgTpxa3XnsQFh8LuEaF2IpyBDFTmZY7KmaA8npzTAKicQzMHJRTPObB0iVZm/GiXQaGrtAR6CzsRBZyC5djBQd1Q7UtHzBR33zzHBvhqJQFRnH2avqdxzhwKsicIcDPSP+yqoFj3tyIot1ubNfUBi2b1AZ66s/apy2mOzRrXLVOxx9/BzbP8Ee+b5I2sTNpOuwmBkE3LVcZxe1Wmt55vnYzrk8ulFy3xcX7UnWRDVZerPqREfb5ErAisIVJvtbubowIDAQAB   ".parse().expect("should parse")
        );
        assert_eq!(
            reference,
            "  MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbezMeDTbry5nlfb/14tiTLp7Hov2aHCUlaGtzFUSgj4HktSRwCJj2909oN/eZ0lsY+vgepzRNe2LucJ0xSsRgTpxa3XnsQFh8LuEaF2IpyBDFTmZY7KmaA8npzTAKicQzMHJRTPObB0iVZm/GiXQaGrtAR6CzsRBZyC5djBQd1Q7UtHzBR33zzHBvhqJQFRnH2avqdxzhwKsicIcDPSP+yqoFj3tyIot1ubNfUBi2b1AZ66s/apy2mOzRrXLVOxx9/BzbP8Ee+b5I2sTNpOuwmBkE3LVcZxe1Wmt55vnYzrk8ulFy3xcX7UnWRDVZerPqREfb5ErAisIVJvtbubowIDAQAB   ".parse().expect("should parse")
        );
    }

    #[test]
    fn display() {
        assert_eq!(
            PublicKey(SubjectPublicKeyInfoDer::from(&b"\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x00\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xbd\xb7\xb3\x31\xe0\xd3\x6e\xbc\xb9\x9e\x57\xdb\xff\x5e\x2d\x89\x32\xe9\xec\x7a\x2f\xd9\xa1\xc2\x52\x56\x86\xb7\x31\x54\x4a\x08\xf8\x1e\x4b\x52\x47\x00\x89\x8f\x6f\x74\xf6\x83\x7f\x79\x9d\x25\xb1\x8f\xaf\x81\xea\x73\x44\xd7\xb6\x2e\xe7\x09\xd3\x14\xac\x46\x04\xe9\xc5\xad\xd7\x9e\xc4\x05\x87\xc2\xee\x11\xa1\x76\x22\x9c\x81\x0c\x54\xe6\x65\x8e\xca\x99\xa0\x3c\x9e\x9c\xd3\x00\xa8\x9c\x43\x33\x07\x25\x14\xcf\x39\xb0\x74\x89\x56\x66\xfc\x68\x97\x41\xa1\xab\xb4\x04\x7a\x0b\x3b\x11\x05\x9c\x82\xe5\xd8\xc1\x41\xdd\x50\xed\x4b\x47\xcc\x14\x77\xdf\x3c\xc7\x06\xf8\x6a\x25\x01\x51\x9c\x7d\x9a\xbe\xa7\x71\xce\x1c\x0a\xb2\x27\x08\x70\x33\xd2\x3f\xec\xaa\xa0\x58\xf7\xb7\x22\x28\xb7\x5b\x9b\x35\xf5\x01\x8b\x66\xf5\x01\x9e\xba\xb3\xf6\xa9\xcb\x69\x8e\xcd\x1a\xd7\x2d\x53\xb1\xc7\xdf\xc1\xcd\xb3\xfc\x11\xef\x9b\xe4\x8d\xac\x4c\xda\x4e\xbb\x09\x81\x90\x4d\xcb\x55\xc6\x71\x7b\x55\xa6\xb7\x9e\x6f\x9d\x8c\xeb\x93\xcb\xa5\x17\x2d\xf1\x71\x7e\xd4\x9d\x64\x43\x55\x97\xab\x3e\xa4\x44\x7d\xbe\x44\xac\x08\xac\x21\x52\x6f\xb5\xbb\x9b\xa3\x02\x03\x01\x00\x01"[..])).to_string(),
            "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbezMeDTbry5nlfb/14tiTLp7Hov2aHCUlaGtzFUSgj4HktSRwCJj2909oN/eZ0lsY+vgepzRNe2LucJ0xSsRgTpxa3XnsQFh8LuEaF2IpyBDFTmZY7KmaA8npzTAKicQzMHJRTPObB0iVZm/GiXQaGrtAR6CzsRBZyC5djBQd1Q7UtHzBR33zzHBvhqJQFRnH2avqdxzhwKsicIcDPSP+yqoFj3tyIot1ubNfUBi2b1AZ66s/apy2mOzRrXLVOxx9/BzbP8Ee+b5I2sTNpOuwmBkE3LVcZxe1Wmt55vnYzrk8ulFy3xcX7UnWRDVZerPqREfb5ErAisIVJvtbubowIDAQAB".to_string(),
        )
    }

    #[test]
    fn round_trip() {
        let string = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbezMeDTbry5nlfb/14tiTLp7Hov2aHCUlaGtzFUSgj4HktSRwCJj2909oN/eZ0lsY+vgepzRNe2LucJ0xSsRgTpxa3XnsQFh8LuEaF2IpyBDFTmZY7KmaA8npzTAKicQzMHJRTPObB0iVZm/GiXQaGrtAR6CzsRBZyC5djBQd1Q7UtHzBR33zzHBvhqJQFRnH2avqdxzhwKsicIcDPSP+yqoFj3tyIot1ubNfUBi2b1AZ66s/apy2mOzRrXLVOxx9/BzbP8Ee+b5I2sTNpOuwmBkE3LVcZxe1Wmt55vnYzrk8ulFy3xcX7UnWRDVZerPqREfb5ErAisIVJvtbubowIDAQAB".to_string();
        assert_eq!(
            string
                .parse::<PublicKey>()
                .expect("should parse")
                .to_string(),
            string,
        )
    }

    #[test]
    fn invalid_byte() {
        let parsed = "-IIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbezMeDTbry5nlfb/14tiTLp7Hov2aHCUlaGtzFUSgj4HktSRwCJj2909oN/eZ0lsY+vgepzRNe2LucJ0xSsRgTpxa3XnsQFh8LuEaF2IpyBDFTmZY7KmaA8npzTAKicQzMHJRTPObB0iVZm/GiXQaGrtAR6CzsRBZyC5djBQd1Q7UtHzBR33zzHBvhqJQFRnH2avqdxzhwKsicIcDPSP+yqoFj3tyIot1ubNfUBi2b1AZ66s/apy2mOzRrXLVOxx9/BzbP8Ee+b5I2sTNpOuwmBkE3LVcZxe1Wmt55vnYzrk8ulFy3xcX7UnWRDVZerPqREfb5ErAisIVJvtbubowIDAQAB".parse::<PublicKey>();
        assert!(matches!(
            parsed,
            Err(PublicKeyParseError::Base64(
                base64::DecodeError::InvalidByte(0, 45)
            ))
        ));
    }

    #[test]
    fn invalid_length() {
        let parsed = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbezMeDTbry5nlfb/14tiTLp7Hov2aHCUlaGtzFUSgj4HktSRwCJj2909oN/eZ0lsY+vgepzRNe2LucJ0xSsRgTpxa3XnsQFh8LuEaF2IpyBDFTmZY7KmaA8npzTAKicQzMHJRTPObB0iVZm/GiXQaGrtAR6CzsRBZyC5djBQd1Q7UtHzBR33zzHBvhqJQFRnH2avqdxzhwKsicIcDPSP+yqoFj3tyIot1ubNfUBi2b1AZ66s/apy2mOzRrXLVOxx9/BzbP8Ee+b5I2sTNpOuwmBkE3LVcZxe1Wmt55vnYzrk8ulFy3xcX7UnWRDVZerPqREfb5ErAisIVJvtbubowIDAQABB".parse::<PublicKey>();
        assert!(matches!(
            parsed,
            Err(PublicKeyParseError::Base64(
                base64::DecodeError::InvalidLength(393)
            ))
        ));
    }

    #[test]
    fn ser_de() {
        use serde_test::{Token, assert_tokens};
        assert_tokens(
            &PublicKey::from_slice(b"\x30\x82\x01\x22\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x82\x01\x0f\x00\x30\x82\x01\x0a\x02\x82\x01\x01\x00\xbd\xb7\xb3\x31\xe0\xd3\x6e\xbc\xb9\x9e\x57\xdb\xff\x5e\x2d\x89\x32\xe9\xec\x7a\x2f\xd9\xa1\xc2\x52\x56\x86\xb7\x31\x54\x4a\x08\xf8\x1e\x4b\x52\x47\x00\x89\x8f\x6f\x74\xf6\x83\x7f\x79\x9d\x25\xb1\x8f\xaf\x81\xea\x73\x44\xd7\xb6\x2e\xe7\x09\xd3\x14\xac\x46\x04\xe9\xc5\xad\xd7\x9e\xc4\x05\x87\xc2\xee\x11\xa1\x76\x22\x9c\x81\x0c\x54\xe6\x65\x8e\xca\x99\xa0\x3c\x9e\x9c\xd3\x00\xa8\x9c\x43\x33\x07\x25\x14\xcf\x39\xb0\x74\x89\x56\x66\xfc\x68\x97\x41\xa1\xab\xb4\x04\x7a\x0b\x3b\x11\x05\x9c\x82\xe5\xd8\xc1\x41\xdd\x50\xed\x4b\x47\xcc\x14\x77\xdf\x3c\xc7\x06\xf8\x6a\x25\x01\x51\x9c\x7d\x9a\xbe\xa7\x71\xce\x1c\x0a\xb2\x27\x08\x70\x33\xd2\x3f\xec\xaa\xa0\x58\xf7\xb7\x22\x28\xb7\x5b\x9b\x35\xf5\x01\x8b\x66\xf5\x01\x9e\xba\xb3\xf6\xa9\xcb\x69\x8e\xcd\x1a\xd7\x2d\x53\xb1\xc7\xdf\xc1\xcd\xb3\xfc\x11\xef\x9b\xe4\x8d\xac\x4c\xda\x4e\xbb\x09\x81\x90\x4d\xcb\x55\xc6\x71\x7b\x55\xa6\xb7\x9e\x6f\x9d\x8c\xeb\x93\xcb\xa5\x17\x2d\xf1\x71\x7e\xd4\x9d\x64\x43\x55\x97\xab\x3e\xa4\x44\x7d\xbe\x44\xac\x08\xac\x21\x52\x6f\xb5\xbb\x9b\xa3\x02\x03\x01\x00\x01").unwrap(),
            &[
                Token::Str("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvbezMeDTbry5nlfb/14tiTLp7Hov2aHCUlaGtzFUSgj4HktSRwCJj2909oN/eZ0lsY+vgepzRNe2LucJ0xSsRgTpxa3XnsQFh8LuEaF2IpyBDFTmZY7KmaA8npzTAKicQzMHJRTPObB0iVZm/GiXQaGrtAR6CzsRBZyC5djBQd1Q7UtHzBR33zzHBvhqJQFRnH2avqdxzhwKsicIcDPSP+yqoFj3tyIot1ubNfUBi2b1AZ66s/apy2mOzRrXLVOxx9/BzbP8Ee+b5I2sTNpOuwmBkE3LVcZxe1Wmt55vnYzrk8ulFy3xcX7UnWRDVZerPqREfb5ErAisIVJvtbubowIDAQAB"),
            ],
        );
    }
}
