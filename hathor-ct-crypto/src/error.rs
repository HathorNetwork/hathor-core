use thiserror::Error;

#[derive(Error, Debug)]
pub enum HathorCtError {
    #[error("invalid blinding factor: {0}")]
    InvalidBlindingFactor(String),

    #[error("invalid commitment: {0}")]
    InvalidCommitment(String),

    #[error("invalid generator: {0}")]
    InvalidGenerator(String),

    #[error("range proof error: {0}")]
    RangeProofError(String),

    #[error("surjection proof error: {0}")]
    SurjectionProofError(String),

    #[error("balance verification error: {0}")]
    BalanceError(String),

    #[error("serialization error: {0}")]
    SerializationError(String),

    #[error("secp256k1 error: {0}")]
    Secp256k1Error(String),
}

impl From<secp256k1_zkp::Error> for HathorCtError {
    fn from(e: secp256k1_zkp::Error) -> Self {
        HathorCtError::Secp256k1Error(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, HathorCtError>;
