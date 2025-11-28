#[derive(Debug, Default)]
pub enum CurrentScreen {
    #[default]
    Home,
    VaultName,
    Password,
    Vault,
    Entry
}