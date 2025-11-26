use bincode::{Decode, Encode, config};

use crate::cryptography::cryptography_error::{CryptographyError, Result};

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct UncryptedVault {
    entries: Vec<Entry>,
}

impl UncryptedVault {
    pub fn new() -> Self {
        Self { entries: vec![] }
    }

    pub fn get_entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn add_entry(&mut self, title: String, username: String, password: String) {
        let next_id = self
            .entries
            .iter()
            .max_by(|first_entry, second_entry| first_entry.id.cmp(&second_entry.id))
            .map(|entry| entry.id);

        let id = match next_id {
            Some(value) => value + 1,
            None => 0,
        };

        let entry = Entry {
            id,
            title,
            username,
            password,
        };

        self.entries.push(entry);
    }

    pub fn update_entry(&mut self, entry: Entry) {
        self.entries.pop_if(|e| e.id == entry.id);
        self.entries.push(entry);
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>> {
        bincode::encode_to_vec(self, config::standard())
            .map_err(|error| CryptographyError::BinaryEncodingError(error.to_string()))
    }

    pub fn decode(data: &[u8]) -> Result<Self> {
        let (uncrypted_vault, _) = bincode::decode_from_slice(data, config::standard())
            .map_err(|error| CryptographyError::BinaryDecodingError(error.to_string()))?;

        Ok(uncrypted_vault)
    }
}

#[derive(Encode, Decode, PartialEq, Debug)]
pub struct Entry {
    id: usize,
    pub title: String,
    pub username: String,
    pub password: String,
}

impl Entry {
    pub fn save_password(&mut self, password: &str) {
        self.password = password.to_string();
    }
}
