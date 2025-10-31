pub trait Cryptography {
    fn encrypt(data: &[u8], key: Key) -> Vec<u8>; // TODO : Fix
    fn decrypt(data: &[u8], key: Key) -> Vec<u8>; // TODO : Fix
}

pub struct Key {
    content: Vec<u8>,
    algorithm: String
}