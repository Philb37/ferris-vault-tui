use generic_array::ArrayLength;

use crate::vault::{crypted_vault::CryptedVault, uncrypted_vault::UncryptedVault};

pub trait Cryptography<N: ArrayLength<u8>> {
    fn encrypt(&self, clear_vault: &UncryptedVault) -> CryptedVault<N>;
    fn decrypt(&self, vault: CryptedVault<N>) -> UncryptedVault;
}
