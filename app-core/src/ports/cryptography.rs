use crate::cryptography::{cryptography_error::Result, uncrypted_vault::UncryptedVault};

pub trait Cryptography {
    fn encrypt(&self, uncrypted_vault: &UncryptedVault) -> Result<Vec<u8>>;
    fn decrypt(&self, vault: &[u8]) -> Result<UncryptedVault>;   
}

pub trait NoKeyCipher {

    type Crypto: Cryptography;

    fn create_cipher_from_key(key: &[u8]) -> Result<Self::Crypto>;
}