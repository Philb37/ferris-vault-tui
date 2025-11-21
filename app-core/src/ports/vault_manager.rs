use crate::errors::vault_error::Result;

pub trait VaultManager {
    fn create(&mut self, username: &str, password: &str) -> Result<Vault>;
    fn retrieve(&mut self, username: &str, password: &str) -> Result<Vault>;
    fn save(&self, vault: Vault) -> Result<()>;
}

pub struct Vault {
    pub content: Vec<u8>,
    pub encryption_key: Key
}

impl Vault {
    pub fn new(content: Vec<u8>, encryption_key: Key) -> Self {
        Self {
            content,
            encryption_key
        }
    }
}

pub struct Key {
    pub bytes: Vec<u8>
}

impl Key {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes
        }
    }
}