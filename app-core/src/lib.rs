pub mod ports;
pub mod errors;

pub struct UncryptedVault {
    entries: Vec<Entry>
}

impl UncryptedVault {
    fn add_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    fn update_entry(&mut self, entry: Entry) {
        self.entries.pop_if(|e| e.id == entry.id);
        self.add_entry(entry);
    }
}

pub struct Entry {
    id: String,
    title: String,
    username: String,
    password: String
}

impl Entry {
    fn save_password(&mut self, password: &str) {
        self.password = password.to_string();
    }
}

pub enum Commands {

}

pub fn create_account(username: &str, password: &str) -> UncryptedVault {
    UncryptedVault { entries: vec![] }
}

pub fn logging_in(username: &str, password: &str) -> UncryptedVault {
    UncryptedVault { entries: vec![] }
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