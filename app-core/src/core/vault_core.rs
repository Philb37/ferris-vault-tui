use std::marker::PhantomData;

use crate::{
    core::core_errors::Result,
    ports::{
        cryptography::{Cryptography, NoKeyCipher},
        password_generator::PasswordGenerator,
        vault_manager::VaultManager,
    },
    uncrypted_vault::Entry,
};

pub trait Core<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> {
    type LoggedType: LoggedCore<VM, PG, NKC::Crypto>;

    fn create_account(self, username: &str, password: &str) -> Result<Self::LoggedType>;
    fn logging_in(self, username: &str, password: &str) -> Result<Self::LoggedType>;
}

pub trait LoggedCore<VM: VaultManager, PG: PasswordGenerator, C: Cryptography> {
    fn get_entries(&self) -> Vec<Entry>;
    fn add_entry(&mut self, title: String, username: String, password: String);
    fn update_entry(&mut self, entry: Entry);
    fn generate_password(&self) -> Result<Vec<u8>>;
}

pub struct CoreService<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> {
    vault_manager: VM,
    password_generator: PG,
    _phantom: PhantomData<NKC>,
}

impl<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> CoreService<VM, PG, NKC> {
    pub fn new(vault_manager: VM, password_generator: PG) -> CoreService<VM, PG, NKC> {
        Self {
            vault_manager,
            password_generator,
            _phantom: std::marker::PhantomData,
        }
    }
}

impl<VM: VaultManager, PG: PasswordGenerator, NKC: NoKeyCipher> Core<VM, PG, NKC>
    for CoreService<VM, PG, NKC>
{
    type LoggedType = LoggedCoreService<VM, PG, NKC::Crypto>;

    fn create_account(mut self, username: &str, password: &str) -> Result<Self::LoggedType> {
        let Ok(crypted_vault) = self.vault_manager.create(username, password) else {
            todo!("Handle vault manager error")
        };

        let Ok(cryptography) = NKC::create_cipher_from_key(crypted_vault.encryption_key.as_bytes())
        else {
            todo!("Handle cipher error")
        };

        Ok(LoggedCoreService {
            vault_manager: self.vault_manager,
            password_generator: self.password_generator,
            cryptography,
        })
    }

    fn logging_in(mut self, username: &str, password: &str) -> Result<Self::LoggedType> {
        let Ok(crypted_vault) = self.vault_manager.retrieve(username, password) else {
            todo!("Handle vault manager error")
        };

        let Ok(cryptography) = NKC::create_cipher_from_key(crypted_vault.encryption_key.as_bytes())
        else {
            todo!("Handle cipher error")
        };

        Ok(LoggedCoreService {
            vault_manager: self.vault_manager,
            password_generator: self.password_generator,
            cryptography,
        })
    }
}

pub struct LoggedCoreService<VM: VaultManager, PG: PasswordGenerator, C: Cryptography> {
    vault_manager: VM,
    password_generator: PG,
    cryptography: C,
}

impl<VM: VaultManager, PG: PasswordGenerator, C: Cryptography> LoggedCore<VM, PG, C>
    for LoggedCoreService<VM, PG, C>
{
    fn get_entries(&self) -> Vec<Entry> {
        todo!()
    }

    fn add_entry(&mut self, title: String, username: String, password: String) {
        todo!()
    }

    fn update_entry(&mut self, entry: Entry) {
        todo!()
    }

    fn generate_password(&self) -> Result<Vec<u8>> {
        todo!()
    }
}
