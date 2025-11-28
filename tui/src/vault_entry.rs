use app_core::uncrypted_vault::Entry;
use ratatui::{style::palette::tailwind::SLATE, text::Line, widgets::ListItem};

#[derive(Debug, Default)]
pub struct VaultEntry(pub Entry);

pub fn entries_to_vault_entries(entries: &[Entry]) -> Vec<VaultEntry> {
    let mut result = Vec::new();

    for entry in entries {
        result.push(VaultEntry(entry.clone()));
    }

    result
}

impl From<&VaultEntry> for ListItem<'_> {
    fn from(value: &VaultEntry) -> Self {
        ListItem::new(Line::styled(
            format!(
                " 🔐 Entry: {} | username: {}",
                value.0.title, value.0.username
            ),
            SLATE.c200,
        ))
    }
}