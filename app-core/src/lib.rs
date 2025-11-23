// Re-export for other crates
pub use generic_array;

use crate::vault::uncrypted_vault::{Entry, UncryptedVault};

pub mod ports;
pub mod errors;
pub mod vault;
pub mod cryptography;

pub enum Commands {

}

pub fn create_account(username: &str, password: &str) -> UncryptedVault {
    UncryptedVault::new(vec![])
}

pub fn logging_in(username: &str, password: &str) -> UncryptedVault {
    UncryptedVault::new(vec![])
}

pub fn add_entry(entry: Entry, uncrypted_vault: &mut UncryptedVault) {
    uncrypted_vault.add_entry(entry);
}

pub fn update_entry(entry: Entry, uncrypted_vault: &mut UncryptedVault) {
    uncrypted_vault.update_entry(entry);
}

pub fn generate_password(entry: &mut Entry) {
    let password = ""; // TODO : Call password_manager implementation
    entry.save_password(password);
}

pub fn display_commands() -> Vec<Commands> {
    vec![]
}