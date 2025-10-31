use core::ports::password_generator::{
    PasswordGenerator,
    PasswordRestriction
};
use rand::seq::{IndexedRandom, SliceRandom};

const MORE_RESTRINCTIONS_THAN_LENGTH_ERROR: &'static str = "There cannot be more restrictions than the desired length.";
const NO_RESTRICTION_FOUND_ERROR:           &'static str = "You must choose at least one password restriction.";
const ZERO_LENGTH_ERROR:                    &'static str = "A password cannot be of length 0.";

const LOWER_CASE_LETTERS: &'static [u8; 26] = b"abcdefghijklmnopqrstuvwxyz";
const UPPER_CASE_LETTERS: &'static [u8; 26] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const NUMBERS:            &'static [u8; 10] = b"0123456789";
const SPECIAL_CHARACTERS: &'static [u8; 32] = b"!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

pub struct SecurePasswordGenerator { }

impl PasswordGenerator for SecurePasswordGenerator {

    fn generate_password(restrictions: &PasswordRestriction) -> Result<Vec<u8>, String> {

        if restrictions.length == 0 {
            return Err(ZERO_LENGTH_ERROR.to_string());
        }

        let mut rng = rand::rng();

        let mut password_charset = Vec::new();
        let mut password = Vec::with_capacity(restrictions.length);

        let mut count = 0;

        if restrictions.lower_case {
            password_charset.extend_from_slice(LOWER_CASE_LETTERS);
            password.push(LOWER_CASE_LETTERS.choose(&mut rng).unwrap().to_owned());
            count += 1;
        }

        if restrictions.upper_case {
            password_charset.extend_from_slice(UPPER_CASE_LETTERS);
            password.push(UPPER_CASE_LETTERS.choose(&mut rng).unwrap().to_owned());
            count += 1;
        }

        if restrictions.numbers {
            password_charset.extend_from_slice(NUMBERS);
            password.push(NUMBERS.choose(&mut rng).unwrap().to_owned());
            count += 1;
        }

        if restrictions.special_characters {
            password_charset.extend_from_slice(SPECIAL_CHARACTERS);
            password.push(SPECIAL_CHARACTERS.choose(&mut rng).unwrap().to_owned());
            count += 1;
        }

        if restrictions.length < count {
            return Err(MORE_RESTRINCTIONS_THAN_LENGTH_ERROR.to_string());
        }

        if password_charset.is_empty() {
            return Err(NO_RESTRICTION_FOUND_ERROR.to_string());
        }

        let remaining_character_count = restrictions.length.saturating_sub(password.len());

        for _ in 0..remaining_character_count {
            password.push(password_charset.choose(&mut rng).unwrap().to_owned());
        }

        password.shuffle(&mut rng);

        Ok(password)
    }
}

#[cfg(test)]
mod tests;