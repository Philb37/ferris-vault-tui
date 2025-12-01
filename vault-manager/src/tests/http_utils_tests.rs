use crate::http_utils::*;
use hmac::Mac;
use mock_instant::global::{UNIX_EPOCH, MockClock, SystemTime};
use reqwest::header::HOST;
use std::time::Duration;

const CONTENT_TYPE: &'static str = "Content-Type";
const X_TIMESTAMP: &'static str = "X-Timestamp";
const X_SIGNATURE: &'static str = "X-Signature";
const X_USERNAME: &'static str = "X-Username";

#[test]
fn opaque_headers_should_contain_content_type_and_username() {

    // A-rrange

    let username = "username";
    let content_type_value = "application/octet-stream";
    
    // A-ct

    let headers = get_opaque_headers(username);

    // A-ssert

    assert!(headers.is_ok());

    let headers = headers.unwrap();

    assert!(headers.contains_key(CONTENT_TYPE));
    assert_eq!(headers.get(CONTENT_TYPE).unwrap(), content_type_value);

    assert!(headers.contains_key(X_USERNAME));
    assert_eq!(headers.get(X_USERNAME).unwrap(), username);
    assert!(headers.get(X_USERNAME).unwrap().is_sensitive());

    assert_eq!(headers.len(), 2);
}

#[test]
fn vault_headers_should_contain_timestamp_signature_as_sensitive() {

    // A-rrange

    let content_type_value = "application/octet-stream";
    let session_key = "session_key".as_bytes();
    let verb = "GET";
    let server_url = "http://localhost";
    let path = "/test";

    let uri = format!("{}{}", server_url, path);

    let duration = Duration::from_millis(1763127134822);
    MockClock::set_system_time(duration);
    let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();

    let raw_signature = format!("{}|{}|{}", verb, uri, timestamp);

    let mut mac = HmacSha512::new_from_slice(session_key).unwrap();
    mac.update(raw_signature.as_bytes());

    let signature = hex::encode(mac.finalize().into_bytes().to_vec());

    // A-ct

    let headers = get_vault_request_headers(session_key, verb, server_url, path).unwrap();

    // A-ssert

    assert!(headers.contains_key(CONTENT_TYPE));
    assert_eq!(headers.get(CONTENT_TYPE).unwrap(), content_type_value);

    assert!(headers.contains_key(HOST));
    assert_eq!(headers.get(HOST).unwrap(), server_url);

    assert!(headers.contains_key(X_SIGNATURE));
    assert_eq!(headers.get(X_SIGNATURE).unwrap(), &signature);
    assert!(headers.get(X_SIGNATURE).unwrap().is_sensitive());

    assert!(headers.contains_key(X_TIMESTAMP));
    assert_eq!(headers.get(X_TIMESTAMP).unwrap(), &timestamp);
    assert!(headers.get(X_TIMESTAMP).unwrap().is_sensitive());

    assert_eq!(headers.len(), 4);
}