use app_core::{
    errors::vault_error::*,
    ports::vault_manager::{Key, Vault, VaultManager},
};

use crate::{Result, error_utils::to_exchange_failed_vault_error, opaque_api::Api};

use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, argon2::Argon2, rand::rngs::OsRng,
};

// Error constants
const CANNOT_SAVE_VAULT_IF_NOT_LOGGED_IN: &'static str =
    "Cannot create a new vault if you are already logged in.";
const CANNOT_CREATE_VAULT_IF_LOGGED_IN: &'static str =
    "Cannot save a vault if you are not logged in.";
const NO_EXPORT_KEY_AFTER_LOGIN: &'static str = "No export key found after login.";

/// Standard Cipher Suite for the vault-manager
/// Using Ristretto255 as an Oprf and. Triple Diffie Hellman for key exchange algorithm and sha512 for hashing
/// And Argon2 (default parameters, argon2id) as a key derivation
pub struct StandardCipherSuite;

impl CipherSuite for StandardCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

pub struct OpaqueVaultManager<T: Api> {
    api: T,
    export_key: Option<Key>,
}

impl<T: Api> OpaqueVaultManager<T> {
    pub fn new(api: T) -> Self {
        Self {
            api,
            export_key: None,
        }
    }

    fn register(&mut self, username: &str, password: &str) -> Result<()> {
        let mut client_rng = OsRng;

        let client_registration_start_result =
            ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
                .map_err(to_exchange_failed_vault_error)?;

        let server_registration_response = self
            .api
            .start_server_registration(username, &client_registration_start_result)?;

        let client_registration_finish_result = client_registration_start_result
            .state
            .finish(
                &mut client_rng,
                password.as_bytes(),
                server_registration_response,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(to_exchange_failed_vault_error)?;

        self.export_key = Some(Key::new(
            client_registration_finish_result.export_key.to_vec(),
        ));

        Ok(self
            .api
            .finish_server_registration(username, &client_registration_finish_result)?)
    }

    fn login(&mut self, username: &str, password: &str) -> Result<()> {
        let mut client_rng = OsRng;

        let client_login_start_result =
            ClientLogin::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
                .map_err(to_exchange_failed_vault_error)?;

        let server_login_response = self
            .api
            .start_server_login(username, &client_login_start_result)?;

        let client_login_finish_result = client_login_start_result
            .state
            .finish(
                &mut client_rng,
                password.as_bytes(),
                server_login_response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(to_exchange_failed_vault_error)?;

        self.export_key = Some(Key::new(client_login_finish_result.export_key.to_vec()));

        Ok(self
            .api
            .finish_server_login(username, &client_login_finish_result)?)
    }

    fn get_vault(&self) -> Result<Vec<u8>> {
        Ok(self.api.get_vault()?)
    }

    fn save_vault(&self, content: Vec<u8>) -> Result<()> {
        Ok(self.api.save_vault(content)?)
    }

    fn get_export_key(&mut self) -> Option<Key> {
        self.export_key.take()
    }
}

impl<T: Api> VaultManager for OpaqueVaultManager<T> {
    fn create(&mut self, username: &str, password: &str) -> Result<Vault> {
        // For now there is no feature to handle multiple vault at the same time
        if self.api.is_logged_in() {
            return Err(VaultError::AlreadyLoggedIn(
                CANNOT_CREATE_VAULT_IF_LOGGED_IN.to_string(),
            ));
        }

        self.register(username, password)?;
        self.login(username, password)?;

        let vault_content = self.get_vault()?;

        let encryption_key = match self.get_export_key() {
            Some(key) => key,
            None => {
                return Err(VaultError::ExchangeFailed(
                    NO_EXPORT_KEY_AFTER_LOGIN.to_string(),
                ));
            }
        };

        Ok(Vault::new(
            vault_content,
            encryption_key,
        ))
    }

    fn retrieve(&mut self, username: &str, password: &str) -> Result<Vault> {
        if !self.api.is_logged_in() {
            self.login(username, password)?;
        }

        let vault_content = self.get_vault()?;

        let encryption_key = match self.get_export_key() {
            Some(key) => key,
            None => {
                return Err(VaultError::ExchangeFailed(
                    NO_EXPORT_KEY_AFTER_LOGIN.to_string(),
                ));
            }
        };

        Ok(Vault::new(
            vault_content,
            encryption_key,
        ))
    }

    fn save(&self, vault: Vault) -> Result<()> {
        if !self.api.is_logged_in() {
            return Err(VaultError::NotLoggedIn(
                CANNOT_SAVE_VAULT_IF_NOT_LOGGED_IN.to_string(),
            ));
        }

        self.save_vault(vault.content)?;

        Ok(())
    }
}
