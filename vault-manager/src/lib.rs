use app_core::errors::vault_error::VaultError;

pub mod opaque_vault_manager;
pub mod opaque_api;
mod http_utils;
mod error_utils;
mod constants;

#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, VaultError>;