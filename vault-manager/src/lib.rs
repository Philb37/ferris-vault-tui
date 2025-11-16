use core::errors::vault_error::VaultError;

pub mod opaque;
pub mod opaque_api;
mod http_utils;
mod error_utils;
mod constants;

#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, VaultError>;