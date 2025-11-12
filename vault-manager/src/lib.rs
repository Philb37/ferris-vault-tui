use core::ports::vault_manager::{
    VaultManager,
    Vault
};
use opaque::OpaqueService;

mod opaque;
mod http_utils;
mod webclient;
mod constants;

// Error constants
const CANNOT_SAVE_VAULT_IF_NOT_LOGGED_IN: &'static str = "Cannot create a new vault if you are already logged in.";
const CANNOT_CREATE_VAULT_IF_LOGGED_IN:   &'static str = "Cannot save a vault if you are not logged in.";
const NO_EXPORT_KEY_AFTER_LOGIN:          &'static str = "No export key found after login.";

pub struct OpaqueVaultManager {
    opaque_service: OpaqueService
}

impl OpaqueVaultManager {

    pub fn new(server_url: String) -> Self {
        Self {
            opaque_service: OpaqueService::new(server_url),
        }
    }
}

impl VaultManager for OpaqueVaultManager {

    fn create(&mut self, username: &str, password: &str) -> Result<Vault, String> {

        // For now there is no feature to handle multiple vault at the same time
        if self.opaque_service.is_logged_in() {
            return Err(CANNOT_CREATE_VAULT_IF_LOGGED_IN.to_string());
        }

        self.opaque_service.register(username, password)?;
        self.opaque_service.login(username, password)?;

        let vault_content = self.opaque_service.get_vault()?;

        let decryption_key = match self.opaque_service.get_export_key() {
            Some(key) => key,
            None => return Err(NO_EXPORT_KEY_AFTER_LOGIN.to_string())
        };

        Ok(Vault::new(String::from(username), vault_content, decryption_key))
    }

    fn retrieve(&mut self, username: &str, password: &str) -> Result<Vault, String> {

        if !self.opaque_service.is_logged_in() {
            self.opaque_service.login(username, password)?;
        }

        let vault_content = self.opaque_service.get_vault()?;

        let decryption_key = match self.opaque_service.get_export_key() {
            Some(key) => key,
            None => return Err(NO_EXPORT_KEY_AFTER_LOGIN.to_string())
        };

        Ok(Vault::new(String::from(username), vault_content, decryption_key))
    }

    fn save(&self, vault: Vault) -> Result<(), String> {
        
        if !self.opaque_service.is_logged_in() {
            return Err(CANNOT_SAVE_VAULT_IF_NOT_LOGGED_IN.to_string());
        }

        self.opaque_service.save_vault(vault.get_content())?;

        Ok(())
    }
}