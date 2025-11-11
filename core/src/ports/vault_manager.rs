pub trait VaultManager {
    fn create(&mut self, username: &str, password: &str) -> Result<Vault, String>;
    fn retrieve(&mut self, username: &str, password: &str) -> Result<Vault, String>;
    fn save(&self, vault: Vault) -> Result<(), String>;
}

pub struct Vault {
    username: String,
    content: Vec<u8>,
    decryption_key: Key
}

impl Vault {
    pub fn new(username: String, content: Vec<u8>, decryption_key: Key) -> Self {
        Self {
            username,
            content,
            decryption_key
        }
    }
}

pub struct Key {
    bytes: Vec<u8>
}

impl Key {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self {
            bytes
        }
    }
}