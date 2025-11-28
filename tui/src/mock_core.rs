use std::marker::PhantomData;

use app_core::{
    cli_clipboard::{ClipboardContext, ClipboardProvider},
    core::{
        core_errors::{CoreError, Result},
        vault_core::{Core, LoggedCore},
    },
    password::password_restriction::PasswordRestriction,
    ports::{
        cryptography::{Cryptography, NoKeyCipher},
        password_generator::PasswordGenerator,
        vault_manager::VaultManager,
    },
    uncrypted_vault::{Entry, UncryptedVault},
};
use password_generator::SecurePasswordGenerator;

#[derive(Debug)]
pub struct MockCore<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> {
    pub _phantom_vm: PhantomData<VM>,
    pub _phantom_pg: PhantomData<PG>,
    pub _phantom_nkc: PhantomData<NKC>,
}

impl<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> Core<VM, PG, NKC> for MockCore<VM, PG, NKC> {
    type LoggedType = MockLoggedCore<VM, PG, NKC::Crypto>;

    fn create_account(self, _: &str, _: &str) -> Result<Self::LoggedType> {
        Ok(MockLoggedCore {
            _phantom_c: PhantomData,
            _phantom_pg: PhantomData,
            _phantom_vm: PhantomData,
            vault: UncryptedVault::new(),
        })
    }

    fn logging_in(self, _: &str, _: &str) -> Result<Self::LoggedType> {
        Ok(MockLoggedCore {
            _phantom_c: PhantomData,
            _phantom_pg: PhantomData,
            _phantom_vm: PhantomData,
            vault: UncryptedVault::new(),
        })
    }
}

#[derive(Debug)]
pub struct MockLoggedCore<VM: VaultManager, PG: PasswordGenerator, C: Cryptography> {
    _phantom_vm: PhantomData<VM>,
    _phantom_pg: PhantomData<PG>,
    _phantom_c: PhantomData<C>,
    vault: UncryptedVault,
}

impl<VM: VaultManager, PG: PasswordGenerator, C: Cryptography> LoggedCore<VM, PG, C>
    for MockLoggedCore<VM, PG, C>
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
        SecurePasswordGenerator::generate_password(restrictions)
            .map_err(|error| CoreError::PasswordGeneratorError(error.to_string()))
    }

    fn save_vault(&self) -> Result<()> {
        Ok(())
    }

    fn copy_to_clipboard(&self, content: String) -> Result<()> {
        let mut ctx =
            ClipboardContext::new().map_err(|error| CoreError::InternalError(error.to_string()))?;

        ctx.set_contents(content)
            .map_err(|error| CoreError::InternalError(error.to_string()))?;

        Ok(())
    }
}