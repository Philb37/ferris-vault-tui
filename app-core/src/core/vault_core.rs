use std::marker::PhantomData;

use cli_clipboard::{ClipboardContext, ClipboardProvider};

use crate::{
    core::core_errors::*,
    password::password_restriction::PasswordRestriction,
    ports::{
        cryptography::{Cryptography, NoKeyCipher},
        password_generator::PasswordGenerator,
        vault_manager::VaultManager,
    },
    uncrypted_vault::{Entry, UncryptedVault},
};

pub trait Core<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> {
    type LoggedType: LoggedCore<VM, PG, NKC::Crypto>;

    fn create_account(self, username: &str, password: &str) -> Result<Self::LoggedType>;
    fn logging_in(self, username: &str, password: &str) -> Result<Self::LoggedType>;
}

pub trait LoggedCore<VM: VaultManager, PG: PasswordGenerator, C: Cryptography> {
    fn get_entries(&self) -> &[Entry];
    fn add_entry(&mut self, title: String, username: String, password: String);
    fn update_entry(&mut self, entry: Entry);
    fn generate_password(&self, restrictions: &PasswordRestriction) -> Result<Vec<u8>>;
    fn save_vault(&self) -> Result<()>;
    fn copy_to_clipboard(&self, content: String) -> Result<()>;
}

#[derive(Debug, Default)]
pub struct CoreService<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> {
    vault_manager: VM,
    _phantom_pg: PhantomData<PG>,
    _phantom_nkc: PhantomData<NKC>,
}

impl<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> CoreService<VM, PG, NKC> {
    pub fn new(vault_manager: VM) -> CoreService<VM, PG, NKC> {
        Self {
            vault_manager,
            _phantom_pg: std::marker::PhantomData,
            _phantom_nkc: std::marker::PhantomData,
        }
    }
}

impl<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> Core<VM, PG, NKC>
    for CoreService<VM, PG, NKC>
{
    type LoggedType = LoggedCoreService<VM, PG, NKC::Crypto>;

    fn create_account(mut self, username: &str, password: &str) -> Result<Self::LoggedType> {
        let crypted_vault = self
            .vault_manager
            .create(username, password)
            .map_err(|error| CoreError::VaultManagerError(error.to_string()))?;

        let cryptography = NKC::create_cipher_from_key(crypted_vault.encryption_key.as_bytes())
            .map_err(|error| CoreError::CryptographyError(error.to_string()))?;

        Ok(LoggedCoreService {
            vault_manager: self.vault_manager,
            _phantom: std::marker::PhantomData,
            cryptography,
            vault: UncryptedVault::new(),
        })
    }

    fn logging_in(mut self, username: &str, password: &str) -> Result<Self::LoggedType> {
        let crypted_vault = self
            .vault_manager
            .retrieve(username, password)
            .map_err(|error| CoreError::VaultManagerError(error.to_string()))?;

        let cryptography = NKC::create_cipher_from_key(crypted_vault.encryption_key.as_bytes())
            .map_err(|error| CoreError::CryptographyError(error.to_string()))?;

        let uncrypted_vault = cryptography
            .decrypt(&crypted_vault.content)
            .map_err(|error| CoreError::CryptographyError(error.to_string()))?;

        Ok(LoggedCoreService {
            vault_manager: self.vault_manager,
            _phantom: std::marker::PhantomData,
            cryptography,
            vault: uncrypted_vault,
        })
    }
}

#[derive(Debug, Default)]
pub struct LoggedCoreService<VM: VaultManager, PG: PasswordGenerator, C: Cryptography> {
    vault_manager: VM,
    _phantom: std::marker::PhantomData<PG>,
    cryptography: C,
    vault: UncryptedVault,
}

impl<VM: VaultManager, PG: PasswordGenerator, C: Cryptography> LoggedCore<VM, PG, C>
    for LoggedCoreService<VM, PG, C>
{
    fn get_entries(&self) -> &[Entry] {
        self.vault.get_entries()
    }

    fn add_entry(&mut self, title: String, username: String, password: String) {
        self.vault.add_entry(title, username, password);
    }

    fn update_entry(&mut self, entry: Entry) {
        self.vault.update_entry(entry);
    }

    fn generate_password(&self, restrictions: &PasswordRestriction) -> Result<Vec<u8>> {
        PG::generate_password(restrictions)
            .map_err(|error| CoreError::PasswordGeneratorError(error.to_string()))
    }

    fn save_vault(&self) -> Result<()> {
        let crypted_vault = self
            .cryptography
            .encrypt(&self.vault)
            .map_err(|error| CoreError::CryptographyError(error.to_string()))?;

        self.vault_manager
            .save(crypted_vault)
            .map_err(|error| CoreError::VaultManagerError(error.to_string()))
    }

    fn copy_to_clipboard(&self, content: String) -> Result<()> {
        let mut ctx =
            ClipboardContext::new().map_err(|error| CoreError::InternalError(error.to_string()))?;

        ctx.set_contents(content)
            .map_err(|error| CoreError::InternalError(error.to_string()))?;

        Ok(())
    }
}
