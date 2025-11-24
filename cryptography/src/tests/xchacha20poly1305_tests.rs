use app_core::{
    cryptography::uncrypted_vault::UncryptedVault, generic_array::GenericArray,
    ports::cryptography::{Cryptography, NoKeyCipher},
};
use chacha20poly1305::{
    AeadCore, KeyInit,
    aead::{Aead, OsRng},
    consts::U32,
};

use crate::xchacha20poly1305::{NoKeyXChaCha20Poly1305, NONCE_LENGTH};

#[test]
fn should_encrypt_vault() {
    // A-rrange

    let mut uncrypted_vault = UncryptedVault::new();
    uncrypted_vault.add_entry(
        "title".to_string(),
        "username".to_string(),
        "password".to_string(),
    );

    let key = &[42; 32];

    let xchacha = NoKeyXChaCha20Poly1305::create_cipher_from_key(key).unwrap();

    let key = GenericArray::<u8, U32>::clone_from_slice(key);

    let cipher = chacha20poly1305::XChaCha20Poly1305::new(&key);

    // A-ct

    let result = xchacha.encrypt(&uncrypted_vault);

    // A-ssert
    assert!(result.is_ok());

    let result = result.unwrap();

    let (nonce, data) = result.split_at(NONCE_LENGTH);
    let nonce = GenericArray::clone_from_slice(nonce);

    let result = cipher.decrypt(&nonce, data).unwrap();

    assert_eq!(result, uncrypted_vault.as_bytes().unwrap());
}

#[test]
fn should_decrypt_vault() {
    // A-rrange

    let mut uncrypted_vault = UncryptedVault::new();
    uncrypted_vault.add_entry(
        "title".to_string(),
        "username".to_string(),
        "password".to_string(),
    );

    let key = &[42; 32];

    let xchacha = NoKeyXChaCha20Poly1305::create_cipher_from_key(key).unwrap();

    let key = GenericArray::<u8, U32>::clone_from_slice(key);
    let cipher = chacha20poly1305::XChaCha20Poly1305::new(&key);
    let nonce = chacha20poly1305::XChaCha20Poly1305::generate_nonce(&mut OsRng);

    let crypted_vault = cipher
        .encrypt(&nonce, uncrypted_vault.as_bytes().unwrap().as_ref())
        .unwrap();

    let mut data = Vec::with_capacity(NONCE_LENGTH + crypted_vault.len());
    data.extend_from_slice(&nonce);
    data.extend_from_slice(&crypted_vault);

    // A-ct

    let result = xchacha.decrypt(&data);

    // A-ssert
    assert!(result.is_ok());

    let result = result.unwrap();

    assert_eq!(result, uncrypted_vault);
}

#[test]
fn should_derive_key_from_64_bytes() {
    // A-rrange

    let key = &[42; 64];

    // A-ct

    let result = NoKeyXChaCha20Poly1305::create_cipher_from_key(key);

    // A-ssert
    assert!(result.is_ok());
}

#[test]
fn should_derive_key_from_16_bytes() {
    // A-rrange

    let key = &[42; 16];

    // A-ct

    let result = NoKeyXChaCha20Poly1305::create_cipher_from_key(key);

    // A-ssert
    assert!(result.is_ok());
}

#[test]
fn should_not_derive_key_from_32_bytes() {
    // A-rrange

    let key = &[42; 32];

    // A-ct

    let result = NoKeyXChaCha20Poly1305::create_cipher_from_key(key);

    // A-ssert
    assert!(result.is_ok());
}
