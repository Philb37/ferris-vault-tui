#[derive(Debug)]
pub enum VaultError {
    ExchangeFailed(String),
    AlreadyLoggedIn(String),
    NotLoggedIn(String),
    NotFound,
    Internal(String)
}

impl std::fmt::Display for VaultError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            VaultError::ExchangeFailed(message) => write!(formatter, "Error during webserver's exchange : {}", message),
            VaultError::AlreadyLoggedIn(message) => write!(formatter, "Already logged in : {}", message),
            VaultError::NotLoggedIn(message) => write!(formatter, "Not logged in : {}", message),
            VaultError::NotFound => write!(formatter, "Vault not found"),
            VaultError::Internal(message) => write!(formatter, "Internal error : {}", message)
        }
    }
}

impl std::error::Error for VaultError {}

pub type Result<T> = std::result::Result<T, VaultError>;