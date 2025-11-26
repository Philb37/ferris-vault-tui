#[derive(Debug)]
pub enum CoreError {
    InternalError(String),
    VaultManagerError(String),
    CryptographyError(String),
    PasswordGeneratorError(String)
}

impl std::fmt::Display for CoreError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CoreError::InternalError(message) => write!(formatter, "Internal error on core: {}", message),
            CoreError::VaultManagerError(message) => write!(formatter, "Error in the vault manager adapter: {}", message),
            CoreError::CryptographyError(message) => write!(formatter, "Error in the cryptography adapter: {}", message),
            CoreError::PasswordGeneratorError(message) => write!(formatter, "Error in the password generator: {}", message)
        }
    }
}

impl std::error::Error for CoreError {}

pub type Result<T> = std::result::Result<T, CoreError>;