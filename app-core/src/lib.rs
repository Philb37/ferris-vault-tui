// Re-export for other crates
pub use generic_array;
pub use bincode;

pub mod core;
pub mod ports;
pub mod vault;
pub mod cryptography;

pub use cryptography::uncrypted_vault;

pub enum Commands {

}

pub fn display_commands() -> Vec<Commands> {
    vec![]
}