use generic_array::ArrayLength;

use crate::{errors::vault_error::Result, vault::crypted_vault::CryptedVault};

pub trait VaultManager {
    type KeySize: ArrayLength<u8>;

    fn create(&mut self, username: &str, password: &str) -> Result<CryptedVault<Self::KeySize>>;
    fn retrieve(&mut self, username: &str, password: &str) -> Result<CryptedVault<Self::KeySize>>;
    fn save(&self, vault: &CryptedVault<Self::KeySize>) -> Result<()>;
}
