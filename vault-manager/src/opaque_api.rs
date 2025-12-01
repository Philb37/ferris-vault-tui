use opaque_ke::{
    ClientLoginFinishResult, ClientLoginStartResult, ClientRegistrationFinishResult,
    ClientRegistrationStartResult, CredentialResponse, RegistrationResponse,
};
use reqwest::{
    blocking::{Client, Response},
    header::HeaderMap,
};

use hkdf::Hkdf;
use sha2::Sha512;

use crate::{
    Result,
    constants::*,
    error_utils::{to_exchange_failed_vault_error, to_internal_vault_error},
    http_utils::{get_opaque_headers, get_vault_request_headers},
    opaque_vault_manager::StandardCipherSuite,
};
use app_core::vault::vault_error::VaultError;

const METHOD_NOT_ALLOWED: &'static str = "Method not allowed.";
const NO_SESSION_AFTER_LOGIN: &'static str = "No session after loggin.";

pub trait Api {
    fn start_server_registration(
        &self,
        username: &str,
        client_registration_start_result: &ClientRegistrationStartResult<StandardCipherSuite>,
    ) -> Result<RegistrationResponse<StandardCipherSuite>>;

    fn finish_server_registration(
        &self,
        username: &str,
        client_registration_finish_result: &ClientRegistrationFinishResult<StandardCipherSuite>,
    ) -> Result<()>;

    fn start_server_login(
        &self,
        username: &str,
        client_login_start_result: &ClientLoginStartResult<StandardCipherSuite>,
    ) -> Result<CredentialResponse<StandardCipherSuite>>;

    fn finish_server_login(
        &mut self,
        username: &str,
        client_login_finish_result: &ClientLoginFinishResult<StandardCipherSuite>,
    ) -> Result<()>;

    fn get_vault(&self) -> Result<Vec<u8>>;
    fn save_vault(&self, vault: Vec<u8>) -> Result<()>;
    fn is_logged_in(&self) -> bool;
}

#[derive(Debug, Default)]
struct Session {
    session_key: Vec<u8>,
    session_token: String,
}

impl Session {
    pub fn new(session_key: Vec<u8>, session_token: String) -> Self {
        Self {
            session_key,
            session_token,
        }
    }
}

#[derive(Debug, Default)]
pub struct OpaqueApi {
    client: Client,
    server_url: String,
    session: Option<Session>,
}

impl OpaqueApi {
    pub fn new(server_url: String) -> Self {
        Self {
            client: Client::new(),
            server_url,
            session: None,
        }
    }

    fn web_server_request(
        &self,
        uri: String,
        verb: &'static str, // Change to ENUM ? todo!()
        body: Option<Vec<u8>>,
        headers: HeaderMap,
        bearer_token: Option<&str>,
    ) -> Result<Response> {
        // Check if you need the mut and reassignement of client below todo!()
        let mut client = match verb {
            GET => self.client.get(uri),
            POST => self.client.post(uri),
            _ => return Err(VaultError::Internal(METHOD_NOT_ALLOWED.to_string())),
        };

        if let Some(body) = body {
            client = client.body(body);
        };

        if let Some(bearer_token) = bearer_token {
            client = client.bearer_auth(bearer_token);
        }

        let response = client
            .headers(headers)
            .send()
            .map_err(|error| VaultError::ExchangeFailed(error.to_string()))?;

        if let Err(error) = response.error_for_status_ref() {
            return Err(VaultError::ExchangeFailed(error.to_string()));
        }

        Ok(response)
    }

    fn create_session(&mut self, session_key: &[u8]) -> Result<()> {
        let hkdf = Hkdf::<Sha512>::from_prk(session_key)
            .map_err(|error| VaultError::Internal(error.to_string()))?;

        let mut token = vec![0u8; 64];

        hkdf.expand(b"opaque-session-token", &mut token)
            .map_err(|error| VaultError::Internal(error.to_string()))?;

        self.session = Some(Session::new(session_key.to_owned(), hex::encode(token)));

        Ok(())
    }

    fn vault_request(
        &self,
        verb: &'static str,
        content: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>> {
        let uri = format!("{}{}", &self.server_url, VAULT);

        let Some(session) = self.session.as_ref() else {
            return Err(VaultError::NotLoggedIn(NO_SESSION_AFTER_LOGIN.to_string()));
        };

        let headers =
            get_vault_request_headers(&session.session_key, verb, &self.server_url, VAULT)?;

        let vault_response =
            self.web_server_request(uri, verb, content, headers, Some(&session.session_token))?;

        let vault_reponse_bytes = vault_response.bytes().map_err(to_internal_vault_error)?;

        Ok(Some(vault_reponse_bytes.to_vec()))
    }
}

impl Api for OpaqueApi {
    fn start_server_registration(
        &self,
        username: &str,
        client_registration_start_result: &ClientRegistrationStartResult<StandardCipherSuite>,
    ) -> Result<RegistrationResponse<StandardCipherSuite>> {
        let registration_response = self.web_server_request(
            format!("{}{}", &self.server_url, OPAQUE_REGISTRATION_START),
            POST,
            Some(
                client_registration_start_result
                    .message
                    .serialize()
                    .to_vec(),
            ),
            get_opaque_headers(username)?,
            None,
        )?;

        let registration_response_bytes = registration_response
            .bytes()
            .map_err(to_internal_vault_error)?;

        Ok(
            RegistrationResponse::deserialize(&registration_response_bytes)
                .map_err(to_exchange_failed_vault_error)?,
        )
    }

    fn finish_server_registration(
        &self,
        username: &str,
        client_registration_finish_result: &ClientRegistrationFinishResult<StandardCipherSuite>,
    ) -> Result<()> {
        let _ = self.web_server_request(
            format!("{}{}", &self.server_url, OPAQUE_REGISTRATION_FINISH),
            POST,
            Some(
                client_registration_finish_result
                    .message
                    .serialize()
                    .to_vec(),
            ),
            get_opaque_headers(username)?,
            None,
        )?;

        Ok(())
    }

    fn start_server_login(
        &self,
        username: &str,
        client_login_start_result: &ClientLoginStartResult<StandardCipherSuite>,
    ) -> Result<CredentialResponse<StandardCipherSuite>> {
        let login_response = self.web_server_request(
            format!("{}{}", &self.server_url, OPAQUE_LOGIN_START),
            POST,
            Some(client_login_start_result.message.serialize().to_vec()),
            get_opaque_headers(username)?,
            None,
        )?;

        let login_response_bytes = login_response.bytes().map_err(to_internal_vault_error)?;

        Ok(CredentialResponse::deserialize(&login_response_bytes)
            .map_err(to_exchange_failed_vault_error)?)
    }

    fn finish_server_login(
        &mut self,
        username: &str,
        client_login_finish_result: &ClientLoginFinishResult<StandardCipherSuite>,
    ) -> Result<()> {
        let _ = self.web_server_request(
            format!("{}{}", &self.server_url, OPAQUE_LOGIN_FINISH),
            POST,
            Some(client_login_finish_result.message.serialize().to_vec()),
            get_opaque_headers(username)?,
            None,
        )?;

        self.create_session(&client_login_finish_result.session_key)?;

        Ok(())
    }

    fn get_vault(&self) -> Result<Vec<u8>> {
        let Some(vault) = self.vault_request(GET, None)? else {
            return Err(VaultError::NotFound);
        };

        Ok(vault)
    }

    fn save_vault(&self, vault: Vec<u8>) -> Result<()> {
        let _ = self.vault_request(POST, Some(vault))?;

        Ok(())
    }

    fn is_logged_in(&self) -> bool {
        match self.session {
            Some(_) => true,
            None => false,
        }
    }
}
