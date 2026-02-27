/// A 32-byte token UID.
pub type TokenUid = [u8; 32];

/// Zero token UID representing HTR.
pub const HTR_TOKEN_UID: TokenUid = [0u8; 32];

/// Size of a serialized Pedersen commitment (compressed point).
pub const COMMITMENT_SIZE: usize = 33;

/// Size of a serialized generator (compressed point).
pub const GENERATOR_SIZE: usize = 33;
