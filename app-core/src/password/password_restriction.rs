#[derive(Clone, Debug, Default)]
pub struct PasswordRestriction {
    pub length: usize,
    pub lower_case: bool,
    pub upper_case: bool,
    pub numbers: bool,
    pub special_characters: bool
}