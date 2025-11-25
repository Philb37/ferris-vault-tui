use generic_array::{GenericArray, typenum::U64};

use crate::{
    cryptography::cryptography_error::CryptographyError, password::password_restriction::PasswordRestriction, ports::{cryptography::{Cryptography, NoKeyCipher}, password_generator::PasswordGenerator, vault_manager::VaultManager}, uncrypted_vault::UncryptedVault, vault::{crypted_vault::CryptedVault, key::Key, vault_error::VaultError}
};

#[test]
fn should_create_account() {}

#[test]
fn should_logging() {}

#[test]
fn should_get_entries() {}

#[test]
fn should_add_entry() {}

#[test]
fn should_generate_password() {}

#[test]
fn should_save_vault() {}

#[test]
fn should_copy_to_clipboard() {}

struct MockVaultManager {
    mock_in_error: bool,
}

impl VaultManager for MockVaultManager {
    type KeySize = U64;

    fn create(
        &mut self,
        _: &str,
        _: &str,
    ) -> crate::vault::vault_error::Result<CryptedVault<Self::KeySize>> {
        match self.mock_in_error {
            true => Err(VaultError::Internal("mock error".to_string())),
            false => Ok(CryptedVault {
                content: vec![],
                encryption_key: Key::new(
                    GenericArray::<u8, Self::KeySize>::from_slice(&[42; 64]).clone(),
                ),
            }),
        }
    }

    fn retrieve(
        &mut self,
        _: &str,
        _: &str,
    ) -> crate::vault::vault_error::Result<CryptedVault<Self::KeySize>> {
        match self.mock_in_error {
            true => Err(VaultError::Internal("mock error".to_string())),
            false => Ok(CryptedVault {
                content: vec![],
                encryption_key: Key::new(
                    GenericArray::<u8, Self::KeySize>::from_slice(&[42; 64]).clone(),
                ),
            }),
        }
    }

    fn save(&self, _: Vec<u8>) -> crate::vault::vault_error::Result<()> {
        match self.mock_in_error {
            true => Err(VaultError::Internal("mock error".to_string())),
            false => Ok(()),
        }
    }
}

struct MockCryptography {
    mock_in_error: bool,
}

impl Cryptography for MockCryptography {
    fn encrypt(&self, _: &crate::uncrypted_vault::UncryptedVault) -> crate::cryptography::cryptography_error::Result<Vec<u8>> {
        match self.mock_in_error {
            true => Err(CryptographyError::EncryptionError("mock error".to_string())),
            false => Ok(vec![42]),
        }
    }

    fn decrypt(&self, _: &[u8]) -> crate::cryptography::cryptography_error::Result<UncryptedVault> {
        match self.mock_in_error {
            true => Err(CryptographyError::DecryptionError("mock error".to_string())),
            false => Ok(
                UncryptedVault::new()
            ),
        }
    }
}

struct MockNoKeyCipher;

impl NoKeyCipher for MockNoKeyCipher {

    type Crypto = MockCryptography;

    fn create_cipher_from_key(_: &[u8]) -> crate::cryptography::cryptography_error::Result<Self::Crypto> {
        Ok(MockCryptography { mock_in_error: false })
    }
}

struct MockPasswordGenerator;

impl PasswordGenerator for MockPasswordGenerator {

    fn generate_password(_: PasswordRestriction) -> Result<Vec<u8>, String> {
        Ok(vec![42])
    }
}