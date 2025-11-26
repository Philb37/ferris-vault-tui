use crate::{
    PasswordRestriction, SecurePasswordGenerator, LOWER_CASE_LETTERS, MORE_RESTRINCTIONS_THAN_LENGTH_ERROR, NO_RESTRICTION_FOUND_ERROR, NUMBERS, SPECIAL_CHARACTERS, UPPER_CASE_LETTERS, ZERO_LENGTH_ERROR
};
use app_core::ports::password_generator::PasswordGenerator;

#[test]
fn should_contain_one_of_each_restriction_and_have_18_chars() {

    // A-ssuming

    let length = 18;

    let restriction = PasswordRestriction {
        length,
        lower_case: true,
        upper_case: true,
        numbers: true,
        special_characters: true
    };

    // A-ction

    let result = match SecurePasswordGenerator::generate_password(restriction) {
        Ok(result) => result,
        Err(error) => panic!("{error}")
    };

    // A-ssert

    assert_eq!(length, result.len());
    assert!(
        result
        .iter()
        .any(|character| LOWER_CASE_LETTERS.contains(&character))
    );
    assert!(
        result
        .iter()
        .any(|character| UPPER_CASE_LETTERS.contains(&character))
    );
    assert!(
        result
        .iter()
        .any(|character| NUMBERS.contains(&character))
    );
    assert!(
        result
        .iter()
        .any(|character| SPECIAL_CHARACTERS.contains(&character))
    );

    let password = str::from_utf8(&result).unwrap();
    println!("Generated password: {password}");
}

#[test]
fn should_contain_only_lower_case_and_have_18_chars() {

    // A-ssuming

    let length = 18;

    let restriction = PasswordRestriction {
        length,
        lower_case: true,
        upper_case: false,
        numbers: false,
        special_characters: false
    };

    // A-ction

    let result = match SecurePasswordGenerator::generate_password(restriction) {
        Ok(result) => result,
        Err(error) => panic!("{error}")
    };

    // A-ssert

    assert_eq!(length, result.len());
    assert!(
        result
        .iter()
        .any(|character| LOWER_CASE_LETTERS.contains(&character))
    );
    assert!(
        !result
        .iter()
        .any(|character| UPPER_CASE_LETTERS.contains(&character))
    );
    assert!(
        !result
        .iter()
        .any(|character| NUMBERS.contains(&character))
    );
    assert!(
        !result
        .iter()
        .any(|character| SPECIAL_CHARACTERS.contains(&character))
    );

    let password = str::from_utf8(&result).unwrap();
    println!("Generated password: {password}");
}

#[test]
fn should_contain_only_upper_case_and_have_18_chars() {

    // A-ssuming

    let length = 18;

    let restriction = PasswordRestriction {
        length,
        lower_case: false,
        upper_case: true,
        numbers: false,
        special_characters: false
    };

    // A-ction

    let result = match SecurePasswordGenerator::generate_password(restriction) {
        Ok(result) => result,
        Err(error) => panic!("{error}")
    };

    // A-ssert

    assert_eq!(length, result.len());
    assert!(
        !result
        .iter()
        .any(|character| LOWER_CASE_LETTERS.contains(&character))
    );
    assert!(
        result
        .iter()
        .any(|character| UPPER_CASE_LETTERS.contains(&character))
    );
    assert!(
        !result
        .iter()
        .any(|character| NUMBERS.contains(&character))
    );
    assert!(
        !result
        .iter()
        .any(|character| SPECIAL_CHARACTERS.contains(&character))
    );

    let password = str::from_utf8(&result).unwrap();
    println!("Generated password: {password}");
}

#[test]
fn should_contain_numbers_case_and_have_18_chars() {

    // A-ssuming

    let length = 18;

    let restriction = PasswordRestriction {
        length,
        lower_case: false,
        upper_case: false,
        numbers: true,
        special_characters: false
    };

    // A-ction

    let result = match SecurePasswordGenerator::generate_password(restriction) {
        Ok(result) => result,
        Err(error) => panic!("{error}")
    };

    // A-ssert

    assert_eq!(length, result.len());
    assert!(
        !result
        .iter()
        .any(|character| LOWER_CASE_LETTERS.contains(&character))
    );
    assert!(
        !result
        .iter()
        .any(|character| UPPER_CASE_LETTERS.contains(&character))
    );
    assert!(
        result
        .iter()
        .any(|character| NUMBERS.contains(&character))
    );
    assert!(
        !result
        .iter()
        .any(|character| SPECIAL_CHARACTERS.contains(&character))
    );

    let password = str::from_utf8(&result).unwrap();
    println!("Generated password: {password}");
}

#[test]
fn should_contain_only_special_characters_and_have_18_chars() {

    // A-ssuming

    let length = 18;

    let restriction = PasswordRestriction {
        length,
        lower_case: false,
        upper_case: false,
        numbers: false,
        special_characters: true
    };

    // A-ction

    let result = match SecurePasswordGenerator::generate_password(restriction) {
        Ok(result) => result,
        Err(error) => panic!("{error}")
    };

    // A-ssert

    assert_eq!(length, result.len());
    assert!(
        !result
        .iter()
        .any(|character| LOWER_CASE_LETTERS.contains(&character))
    );
    assert!(
        !result
        .iter()
        .any(|character| UPPER_CASE_LETTERS.contains(&character))
    );
    assert!(
        !result
        .iter()
        .any(|character| NUMBERS.contains(&character))
    );
    assert!(
        result
        .iter()
        .any(|character| SPECIAL_CHARACTERS.contains(&character))
    );

    let password = str::from_utf8(&result).unwrap();
    println!("Generated password: {password}");
}

#[test]
fn should_be_error_no_restriction() {

    // A-ssuming

    let length = 18;

    let restriction = PasswordRestriction {
        length,
        lower_case: false,
        upper_case: false,
        numbers: false,
        special_characters: false
    };

    // A-ction and A-ssert

    match SecurePasswordGenerator::generate_password(restriction) {
        Ok(_) => panic!("Should have been an Err, got an Ok. A password shouldn't be generated if there is no restrictions."),
        Err(error) => assert_eq!(error, NO_RESTRICTION_FOUND_ERROR)
    };
}

#[test]
fn should_be_error_zero_length() {

    // A-ssuming

    let length = 0;

    let restriction = PasswordRestriction {
        length,
        lower_case: true,
        upper_case: false,
        numbers: false,
        special_characters: false
    };

    // A-ction and A-ssert

    match SecurePasswordGenerator::generate_password(restriction) {
        Ok(_) => panic!("Should have been an Err, got an Ok. A password shouldn't be generated if there is a 0 length."),
        Err(error) => assert_eq!(error, ZERO_LENGTH_ERROR)
    };
}

#[test]
fn should_be_error_more_restriction_than_length() {

    // A-ssuming

    let length = 3;

    let restriction = PasswordRestriction {
        length,
        lower_case: true,
        upper_case: true,
        numbers: true,
        special_characters: true
    };

    // A-ction and A-ssert

    match SecurePasswordGenerator::generate_password(restriction) {
        Ok(_) => panic!("Should have been an Err, got an Ok. A password shouldn't be generated if there is more restriction than the desired length."),
        Err(error) => assert_eq!(error, MORE_RESTRINCTIONS_THAN_LENGTH_ERROR)
    };
}