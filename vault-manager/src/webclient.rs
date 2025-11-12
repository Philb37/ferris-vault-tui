use reqwest::{
    blocking::{Client, Response},
    header::{HeaderMap},
};
use crate::constants::*;

pub struct WebClient {
    client: Client,
}

impl WebClient {

    pub fn new() -> Self {
        Self {
            client: Client::new()
        }
    }

    pub fn web_server_request(
        &self,
        uri: String,
        verb: &'static str, // Change to ENUM ? todo!()
        body: Option<Vec<u8>>,
        headers: HeaderMap,
        bearer_token: Option<String>,
    ) -> Result<Response, String> {
        
        // Check if you need the mut and reassignement of client below todo!()
        let mut client = match verb {
            GET => self.client.get(uri),
            POST => self.client.post(uri),
            _ => return Err("This verb isn't allowed.".to_string()),
        };

        if let Some(body) = body {
            client = client.body(body);
        };

        if let Some(bearer_token) = bearer_token {
            client = client.bearer_auth(bearer_token);
        }

        client
            .headers(headers)
            .send()
            .map_err(|error| error.to_string())
    }
}
