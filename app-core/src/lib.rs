// Re-export for other crates
pub use bincode;
pub use generic_array;

pub use cryptography::uncrypted_vault;
pub use cli_clipboard;

pub mod core;
pub mod cryptography;
pub mod password;
pub mod ports;
pub mod vault;

#[cfg(test)]
mod tests;