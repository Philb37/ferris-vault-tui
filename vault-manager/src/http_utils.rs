use reqwest::{
    header::{HeaderMap, HeaderValue},
};
use std::time::{SystemTime, UNIX_EPOCH};
use hmac::{Hmac, Mac};
use sha2::Sha512;
use crate::constants::GET;

const APPLICATION_OCTET_STREAM: &'static str = "application/octet-stream";
const CONTENT_TYPE: &'static str = "Content-Type";
const X_TIMESTAMP: &'static str = "X-Timestamp";
const X_SIGNATURE: &'static str = "X-Signature";
const SEPARATOR: &'static str = ";";

type HmacSha512 = Hmac<Sha512>;

pub fn get_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(APPLICATION_OCTET_STREAM),
    );
    headers
}

pub fn get_vault_request_headers(session_key: &[u8], uri: &str) -> Result<HeaderMap, String> {
    let mut headers = get_default_headers();

    let timestamp = get_current_time_to_string()?;

    let mut timestamp_header_value =
        HeaderValue::from_str(&timestamp).map_err(|error| error.to_string())?;
    timestamp_header_value.set_sensitive(true);

    headers.insert(X_TIMESTAMP, timestamp_header_value);

    let signature = create_signature(uri, &timestamp, session_key)?;

    let mut signature_header_value =
        HeaderValue::from_str(&hex::encode(signature)).map_err(|error| error.to_string())?;
    signature_header_value.set_sensitive(true);

    headers.insert(X_SIGNATURE, signature_header_value);

    Ok(headers)
}

pub fn get_current_time_to_string() -> Result<String, String> {

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| error.to_string())?
        .as_secs();

    Ok(timestamp.to_string())
}

pub fn create_signature(uri: &str, timestamp: &str, session_key: &[u8]) -> Result<Vec<u8>, String> {

    let raw_signature = format!("{}|{}|{}", GET, uri, timestamp);

    let mut mac =
        HmacSha512::new_from_slice(session_key)
            .map_err(|error| error.to_string())?;

    mac.update(raw_signature.as_bytes());

    Ok(mac.finalize().into_bytes().to_vec())
}

pub fn construct_body(username: &str, message: &[u8]) -> Vec<u8> {

    let mut body = Vec::new();
    body.extend_from_slice(username.as_bytes());
    body.extend_from_slice(SEPARATOR.as_bytes());
    body.extend_from_slice(message);
    body
}