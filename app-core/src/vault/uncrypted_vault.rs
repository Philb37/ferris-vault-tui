pub struct UncryptedVault {
    entries: Vec<Entry>
}

impl UncryptedVault {

    pub fn new(entries: Vec<Entry>) -> Self {
        Self {
            entries
        }
    }

    pub fn add_entry(&mut self, entry: Entry) {
        self.entries.push(entry);
    }

    pub fn update_entry(&mut self, entry: Entry) {
        self.entries.pop_if(|e| e.id == entry.id);
        self.add_entry(entry);
    }
}

pub struct Entry {
    id: usize,
    title: String,
    username: String,
    password: String
}

impl Entry {
    pub fn save_password(&mut self, password: &str) {
        self.password = password.to_string();
    }
}