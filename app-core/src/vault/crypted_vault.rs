use generic_array::ArrayLength;

use crate::cryptography::key::Key;

pub struct CryptedVault<N: ArrayLength<u8>> {
    pub content: Vec<u8>,
    pub encryption_key: Key<N>
}

impl<N: ArrayLength<u8>> CryptedVault<N> {
    pub fn new(content: Vec<u8>, encryption_key: Key<N>) -> Self {
        Self {
            content,
            encryption_key
        }
    }
}