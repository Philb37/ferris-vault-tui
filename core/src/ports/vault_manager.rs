pub trait VaultManager {
    fn create_vault(username: &str, password: &str) -> Result<Vault, String>;
    fn retrieve(username: &str) -> Result<Vault, String>;
    fn save(vault: Vault);
}

pub struct Vault {
    username: String,
    content: Vec<u8>
}