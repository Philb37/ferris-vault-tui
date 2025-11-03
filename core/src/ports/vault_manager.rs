pub trait VaultManager {
    fn create(&self, username: &str, password: &str) -> Result<Vault, String>;
    fn retrieve(&self, username: &str) -> Result<Vault, String>;
    fn save(&self, vault: Vault);
}

pub struct Vault {
    pub username: String,
    pub content: Vec<u8>,
    pub decryption_key: Vec<u8>
}