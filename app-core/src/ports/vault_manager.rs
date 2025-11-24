use generic_array::ArrayLength;

use crate::{vault::crypted_vault::CryptedVault, vault::vault_error::Result};

pub trait VaultManager {
    type KeySize: ArrayLength<u8>;

    fn create(&mut self, username: &str, password: &str) -> Result<CryptedVault<Self::KeySize>>;
    fn retrieve(&mut self, username: &str, password: &str) -> Result<CryptedVault<Self::KeySize>>;
    fn save(&self, vault: &CryptedVault<Self::KeySize>) -> Result<()>;
}
