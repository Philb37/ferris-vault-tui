use cli_clipboard::{ClipboardContext, ClipboardProvider};
use generic_array::{GenericArray, typenum::U64};

use crate::{
    core::vault_core::{Core, CoreService, LoggedCore},
    cryptography::cryptography_error::CryptographyError,
    password::password_restriction::PasswordRestriction,
    ports::{
        cryptography::{Cryptography, NoKeyCipher},
        password_generator::PasswordGenerator,
        vault_manager::VaultManager,
    },
    uncrypted_vault::UncryptedVault,
    vault::{crypted_vault::CryptedVault, key::Key, vault_error::VaultError},
};

const USERNAME: &'static str = "username";
const PASSWORD: &'static str = "password";
const TITLE: &'static str = "title";

#[test]
fn should_create_account() {
    // A-rrange

    let mock_vault_manager = MockVaultManager::new(false);
    let core_service: CoreService<MockVaultManager, MockPasswordGenerator, MockNoKeyCipher> =
        CoreService::new(mock_vault_manager);

    // A-ct

    let result = core_service.create_account(USERNAME, PASSWORD);

    // A-ssert

    assert!(result.is_ok());
    assert_eq!(result.unwrap().get_entries().len(), 0);
}

#[test]
fn should_logging() {
    // A-rrange

    let mock_vault_manager = MockVaultManager::new(false);
    let core_service: CoreService<MockVaultManager, MockPasswordGenerator, MockNoKeyCipher> =
        CoreService::new(mock_vault_manager);

    // A-ct

    let result = core_service.logging_in(USERNAME, PASSWORD);

    // A-ssert

    assert!(result.is_ok());
    assert_eq!(result.unwrap().get_entries().len(), 0);
}

#[test]
fn should_get_entries() {
    // A-rrange

    let mock_vault_manager = MockVaultManager::new(false);
    let core_service: CoreService<MockVaultManager, MockPasswordGenerator, MockNoKeyCipher> =
        CoreService::new(mock_vault_manager);
    let logged_core_service = core_service.create_account(USERNAME, PASSWORD).unwrap();

    // A-ct

    let result = logged_core_service.get_entries();

    // A-ssert
    assert_eq!(result.len(), 0);
}

#[test]
fn should_add_entry() {
    // A-rrange

    let mock_vault_manager = MockVaultManager::new(false);
    let core_service: CoreService<MockVaultManager, MockPasswordGenerator, MockNoKeyCipher> =
        CoreService::new(mock_vault_manager);
    let mut logged_core_service = core_service.create_account(USERNAME, PASSWORD).unwrap();

    // A-ct

    logged_core_service.add_entry(
        TITLE.to_string(),
        USERNAME.to_string(),
        PASSWORD.to_string(),
    );

    let result = logged_core_service.get_entries();

    // A-ssert
    assert_eq!(result.len(), 1);
    assert_eq!(result.get(0).unwrap().title, TITLE);
    assert_eq!(result.get(0).unwrap().username, USERNAME);
    assert_eq!(result.get(0).unwrap().password, PASSWORD);
}

#[test]
fn should_generate_password() {
    // A-rrange

    let mock_vault_manager = MockVaultManager::new(false);
    let core_service: CoreService<MockVaultManager, MockPasswordGenerator, MockNoKeyCipher> =
        CoreService::new(mock_vault_manager);
    let logged_core_service = core_service.create_account(USERNAME, PASSWORD).unwrap();
    let restrictions = PasswordRestriction { length: 18, lower_case: true, upper_case: true, numbers: true, special_characters: true };

    // A-ct

    let result = logged_core_service.generate_password(&restrictions);

    // A-ssert
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), vec![42]);
}

#[test]
fn should_save_vault() {

    // A-rrange

    let mock_vault_manager = MockVaultManager::new(false);
    let core_service: CoreService<MockVaultManager, MockPasswordGenerator, MockNoKeyCipher> =
        CoreService::new(mock_vault_manager);
    let logged_core_service = core_service.create_account(USERNAME, PASSWORD).unwrap();
    
    // A-ct

    let result = logged_core_service.save_vault();

    // A-ssert
    assert!(result.is_ok());
}

#[ignore]
#[test]
fn should_copy_to_clipboard() {

    // A-rrange

    let mock_vault_manager = MockVaultManager::new(false);
    let core_service: CoreService<MockVaultManager, MockPasswordGenerator, MockNoKeyCipher> =
        CoreService::new(mock_vault_manager);
    let logged_core_service = core_service.create_account(USERNAME, PASSWORD).unwrap();
    let test = "test";

    // A-ct

    let result = logged_core_service.copy_to_clipboard(test.to_string());

    // A-ssert
    assert!(result.is_ok());

    let mut ctx = ClipboardContext::new().unwrap();

    assert_eq!(ctx.get_contents().unwrap(), test);
}

struct MockVaultManager {
    mock_in_error: bool,
}

impl MockVaultManager {
    fn new(mock_in_error: bool) -> Self {
        Self { mock_in_error }
    }
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

impl MockCryptography {
    fn new(mock_in_error: bool) -> Self {
        Self { mock_in_error }
    }
}

impl Cryptography for MockCryptography {
    fn encrypt(
        &self,
        _: &crate::uncrypted_vault::UncryptedVault,
    ) -> crate::cryptography::cryptography_error::Result<Vec<u8>> {
        match self.mock_in_error {
            true => Err(CryptographyError::EncryptionError("mock error".to_string())),
            false => Ok(vec![42]),
        }
    }

    fn decrypt(&self, _: &[u8]) -> crate::cryptography::cryptography_error::Result<UncryptedVault> {
        match self.mock_in_error {
            true => Err(CryptographyError::DecryptionError("mock error".to_string())),
            false => Ok(UncryptedVault::new()),
        }
    }
}

struct MockNoKeyCipher;

impl NoKeyCipher for MockNoKeyCipher {
    type Crypto = MockCryptography;

    fn create_cipher_from_key(
        _: &[u8],
    ) -> crate::cryptography::cryptography_error::Result<Self::Crypto> {
        Ok(MockCryptography::new(false))
    }
}

struct MockPasswordGenerator;

impl PasswordGenerator for MockPasswordGenerator {
    fn generate_password(_: &PasswordRestriction) -> Result<Vec<u8>, String> {
        Ok(vec![42])
    }
}
