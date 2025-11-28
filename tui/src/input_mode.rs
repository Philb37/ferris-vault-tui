#[derive(Debug, Default)]
pub enum InputMode {
    #[default]
    Neutral,
    Loggin,
    Register,
    CreatingEntry,
    // EditingEntry
}