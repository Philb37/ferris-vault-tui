use app_core::errors::vault_error::VaultError;

use opaque_ke::errors::ProtocolError;

pub fn to_exchange_failed_vault_error(protocol_error: ProtocolError) -> VaultError {
    VaultError::ExchangeFailed(protocol_error.to_string())
}

pub fn to_internal_vault_error(reqwest_error: reqwest::Error) -> VaultError {
    VaultError::Internal(reqwest_error.to_string())
}