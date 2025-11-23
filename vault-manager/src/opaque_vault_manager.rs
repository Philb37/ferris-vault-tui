use app_core::{
    cryptography::key::Key,
    errors::vault_error::*,
    ports::vault_manager::VaultManager, vault::crypted_vault::CryptedVault,
};
use crypto_common::OutputSizeUser;

use crate::{Result, error_utils::to_exchange_failed_vault_error, opaque_api::Api};

use opaque_ke::{
    CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult,
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationFinishResult,
    argon2::Argon2, rand::rngs::OsRng,
};

// Error constants
const CANNOT_SAVE_VAULT_IF_NOT_LOGGED_IN: &'static str =
    "Cannot create a new vault if you are already logged in.";
const CANNOT_CREATE_VAULT_IF_LOGGED_IN: &'static str =
    "Cannot save a vault if you are not logged in.";

pub type ExportKeySize<CS> =
    <<<CS as CipherSuite>::OprfCs as voprf::CipherSuite>::Hash as OutputSizeUser>::OutputSize;

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
}

impl<T: Api> OpaqueVaultManager<T> {
    pub fn new(api: T) -> Self {
        Self { api }
    }

    fn register(
        &self,
        username: &str,
        password: &str,
    ) -> Result<ClientRegistrationFinishResult<StandardCipherSuite>> {
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

        self.api
            .finish_server_registration(username, &client_registration_finish_result)?;

        Ok(client_registration_finish_result)
    }

    fn login(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<ClientLoginFinishResult<StandardCipherSuite>> {
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

        self.api
            .finish_server_login(username, &client_login_finish_result)?;

        Ok(client_login_finish_result)
    }

    fn get_vault(&self) -> Result<Vec<u8>> {
        Ok(self.api.get_vault()?)
    }

    fn save_vault(&self, content: Vec<u8>) -> Result<()> {
        Ok(self.api.save_vault(content)?)
    }
}

impl<T: Api> VaultManager for OpaqueVaultManager<T> {
    type KeySize = ExportKeySize<StandardCipherSuite>;

    fn create(&mut self, username: &str, password: &str) -> Result<CryptedVault<Self::KeySize>> {
        // For now there is no feature to handle multiple vault at the same time
        if self.api.is_logged_in() {
            return Err(VaultError::AlreadyLoggedIn(
                CANNOT_CREATE_VAULT_IF_LOGGED_IN.to_string(),
            ));
        }

        let _ = self.register(username, password)?;
        let client_login_finish_result = self.login(username, password)?;

        let export_key = Key::new(client_login_finish_result.export_key);

        let vault_content = self.get_vault()?;

        Ok(CryptedVault::new(vault_content, export_key))
    }

    fn retrieve(&mut self, username: &str, password: &str) -> Result<CryptedVault<Self::KeySize>> {
        let client_login_finish_result = self.login(username, password)?;

        let vault_content = self.get_vault()?;

        let export_key = Key::new(client_login_finish_result.export_key);

        Ok(CryptedVault::new(vault_content, export_key))
    }

    fn save(&self, vault: &CryptedVault<Self::KeySize>) -> Result<()> {
        if !self.api.is_logged_in() {
            return Err(VaultError::NotLoggedIn(
                CANNOT_SAVE_VAULT_IF_NOT_LOGGED_IN.to_string(),
            ));
        }

        self.save_vault(vault.content.clone())?;

        Ok(())
    }
}
