use crate::Result;
use app_core::vault::vault_error::VaultError;
use hmac::{Hmac, Mac};
use reqwest::header::{HeaderMap, HeaderValue};
use sha2::Sha512;

#[cfg(test)]
use mock_instant::global::{SystemTime, UNIX_EPOCH};

#[cfg(not(test))]
use std::time::{SystemTime, UNIX_EPOCH};

const APPLICATION_OCTET_STREAM: &'static str = "application/octet-stream";
const CONTENT_TYPE: &'static str = "Content-Type";
const X_TIMESTAMP: &'static str = "X-Timestamp";
const X_SIGNATURE: &'static str = "X-Signature";
const SEPARATOR: &'static str = ";";

pub type HmacSha512 = Hmac<Sha512>;

pub fn get_default_headers() -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        CONTENT_TYPE,
        HeaderValue::from_static(APPLICATION_OCTET_STREAM),
    );
    headers
}

pub fn get_vault_request_headers(session_key: &[u8], verb: &str, uri: &str) -> Result<HeaderMap> {
    let mut headers = get_default_headers();

    let timestamp = get_current_time_to_string()?;

    let mut timestamp_header_value = HeaderValue::from_str(&timestamp)
        .map_err(|error| VaultError::Internal(error.to_string()))?;
    timestamp_header_value.set_sensitive(true);

    headers.insert(X_TIMESTAMP, timestamp_header_value);

    let signature = create_signature(verb, uri, &timestamp, session_key)?;

    let mut signature_header_value = HeaderValue::from_str(&hex::encode(signature))
        .map_err(|error| VaultError::Internal(error.to_string()))?;
    signature_header_value.set_sensitive(true);

    headers.insert(X_SIGNATURE, signature_header_value);

    Ok(headers)
}

pub fn construct_body(username: &str, message: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(username.as_bytes());
    body.extend_from_slice(SEPARATOR.as_bytes());
    body.extend_from_slice(message);
    body
}

fn get_current_time_to_string() -> Result<String> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| VaultError::Internal(error.to_string()))?
        .as_secs();

    Ok(timestamp.to_string())
}

fn create_signature(verb: &str, uri: &str, timestamp: &str, session_key: &[u8]) -> Result<Vec<u8>> {
    let raw_signature = format!("{}|{}|{}", verb, uri, timestamp);

    let mut mac = HmacSha512::new_from_slice(session_key)
        .map_err(|error| VaultError::Internal(error.to_string()))?;

    mac.update(raw_signature.as_bytes());

    Ok(mac.finalize().into_bytes().to_vec())
}
