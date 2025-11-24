#[derive(Debug)]
pub enum CoreError {
    Internal(String)
}

impl std::fmt::Display for CoreError {

    fn fmt(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            CoreError::Internal(message) => write!(formatter, "Internal error on core : {}", message)
        }
    }
}

impl std::error::Error for CoreError {}

pub type Result<T> = std::result::Result<T, CoreError>;