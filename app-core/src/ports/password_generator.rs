use crate::password::password_restriction::PasswordRestriction;

pub trait PasswordGenerator {
    fn generate_password(restrictions: &PasswordRestriction) -> Result<Vec<u8>, String>;
}

