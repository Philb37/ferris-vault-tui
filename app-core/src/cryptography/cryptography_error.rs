#[derive(Debug)]
pub enum CryptographyError {
    MissingKeyError,
    DerivationError(String),
    BinaryEncodingError(String),
    BinaryDecodingError(String),
    EncryptionError(String),
    DecryptionError(String)
}

impl std::fmt::Display for CryptographyError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CryptographyError::MissingKeyError => write!(formatter, "Error couldn't find the key."),
            CryptographyError::DerivationError(error) => write!(formatter, "Error couldn't derive the key: {}", error),
            CryptographyError::BinaryEncodingError(error) => write!(formatter, "Error couldn't encode struct to binary: {}", error),
            CryptographyError::BinaryDecodingError(error) => write!(formatter, "Error couldn't decode struct to binary: {}", error),
            CryptographyError::EncryptionError(error) => write!(formatter, "Error couldn't encrypt data: {}", error),
            CryptographyError::DecryptionError(error) => write!(formatter, "Error couldn't decrypt data: {}", error)
        }
    }
}

impl std::error::Error for CryptographyError {}

pub type Result<T> = std::result::Result<T, CryptographyError>;