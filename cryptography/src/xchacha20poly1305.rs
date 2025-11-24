use app_core::{
    cryptography::{
        cryptography_error::{CryptographyError, Result},
        uncrypted_vault::UncryptedVault,
    },
    generic_array::GenericArray,
    ports::cryptography::{Cryptography, NoKeyCipher},
};
use chacha20poly1305::{
    AeadCore, Key, KeyInit,
    aead::{Aead, OsRng},
    consts::U32,
};
use hkdf::Hkdf;
use sha2::Sha256;

pub(crate) const NONCE_LENGTH: usize = 24;

pub struct NoKeyXChaCha20Poly1305;

impl NoKeyCipher for NoKeyXChaCha20Poly1305 {

    type Crypto = XChaCha20Poly1305;

    /// Used in order to convert the key from 64 to 32 bytes
    fn derive_key(key: &[u8]) -> Result<Self::Crypto> {
        if key.len() == 32 {
            return Ok(XChaCha20Poly1305 {
                key: GenericArray::<u8, U32>::clone_from_slice(key),
            });
        }

        let hkdf = Hkdf::<Sha256>::new(None, key);
        let mut derived = GenericArray::<u8, U32>::default();

        hkdf.expand(b"xchacha20-poly1305-key", &mut derived)
            .map_err(|error| CryptographyError::DerivationError(error.to_string()))?;

        Ok(XChaCha20Poly1305 { key: derived })
    }
}

pub struct XChaCha20Poly1305 {
    key: Key,
}

impl Cryptography for XChaCha20Poly1305 {
    fn encrypt(&self, uncrypted_vault: &UncryptedVault) -> Result<Vec<u8>> {
        let data = uncrypted_vault.as_bytes()?;

        let cipher = chacha20poly1305::XChaCha20Poly1305::new(&self.key);
        let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut OsRng);

        let data = cipher
            .encrypt(&nonce, data.as_ref())
            .map_err(|error| CryptographyError::EncryptionError(error.to_string()))?;

        // nonce.len() should be 24
        let mut crypted_vault = Vec::with_capacity(NONCE_LENGTH + data.len());
        crypted_vault.extend_from_slice(&nonce);
        crypted_vault.extend_from_slice(&data);

        Ok(crypted_vault)
    }

    fn decrypt(&self, crypted_vault: &[u8]) -> Result<UncryptedVault> {
        let cipher = chacha20poly1305::XChaCha20Poly1305::new(&self.key);
        let (nonce, data) = crypted_vault.split_at(NONCE_LENGTH);
        let nonce = GenericArray::from_slice(nonce);

        let data = cipher
            .decrypt(&nonce, data.as_ref())
            .map_err(|error| CryptographyError::DecryptionError(error.to_string()))?;

        UncryptedVault::decode(&data)
    }
}
