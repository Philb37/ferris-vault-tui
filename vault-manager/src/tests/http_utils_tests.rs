use crate::http_utils::*;
use hmac::Mac;
use mock_instant::global::{UNIX_EPOCH, MockClock, SystemTime};
use std::time::Duration;

const CONTENT_TYPE: &'static str = "Content-Type";
const X_TIMESTAMP: &'static str = "X-Timestamp";
const X_SIGNATURE: &'static str = "X-Signature";

#[test]
fn default_headers_should_only_contain_content_type() {

    // A-rrange

    let content_type_value = "application/octet-stream";
    
    // A-ct

    let headers = get_default_headers();

    // A-ssert

    assert!(headers.contains_key(CONTENT_TYPE));
    assert_eq!(headers.get(CONTENT_TYPE).unwrap(), content_type_value);
    assert_eq!(headers.len(), 1);
}

#[test]
fn vault_headers_should_contain_timestamp_signature_as_sensitive() {

    // A-rrange

    let content_type_value = "application/octet-stream";
    let session_key = "session_key".as_bytes();
    let uri = "uri";

    let duration = Duration::from_millis(1763127134822);
    MockClock::set_system_time(duration);
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let raw_signature = format!("{}|{}|{}", "GET", uri, timestamp);

    let mut mac = HmacSha512::new_from_slice(session_key).unwrap();
    mac.update(raw_signature.as_bytes());

    let signature = hex::encode(mac.finalize().into_bytes().to_vec());

    // A-ct

    let headers = get_vault_request_headers(session_key, uri).unwrap();

    // A-ssert

    assert!(headers.contains_key(CONTENT_TYPE));
    assert_eq!(headers.get(CONTENT_TYPE).unwrap(), content_type_value);

    assert!(headers.contains_key(X_SIGNATURE));
    assert_eq!(headers.get(X_SIGNATURE).unwrap(), &signature);
    assert!(headers.get(X_SIGNATURE).unwrap().is_sensitive());

    assert!(headers.contains_key(X_TIMESTAMP));
    assert_eq!(headers.get(X_TIMESTAMP).unwrap(), &timestamp);
    assert!(headers.get(X_TIMESTAMP).unwrap().is_sensitive());

    assert_eq!(headers.len(), 3);
}

#[test]
fn should_construct_body_as_bytes() {

    // A-rrange

    let username = "username";
    let message = "message";

    let expected_body = format!("{};{}", username, message);

    // A-ct

    let body = construct_body(username, message.as_bytes());

    // A-ssert

    assert!(!body.is_empty());
    assert_eq!(body, expected_body.as_bytes());
}