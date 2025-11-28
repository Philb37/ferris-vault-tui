use ratatui::widgets::ListState;

#[derive(Debug, Default)]
pub struct State {
    pub index_vault_item: usize,
    vault_items: Vec<String>,
    pub vault_items_state: ListState,
    pub index_entry_item: usize,
    pub vault_entries_state: ListState,
    pub selected_entry_textarea: usize
}

impl State {

    pub fn set_vault_items(&mut self, names: Vec<String>) {
        self.vault_items = names;
    }

    pub fn get_vault_items(&self) -> &[String] {
        &self.vault_items
    }

    pub fn add_vault_item(&mut self, name: &str) {
        self.vault_items.push(name.to_string());
    }
}