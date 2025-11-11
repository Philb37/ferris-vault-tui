use core::ports::vault_manager::Key;
use opaque_ke::{
    argon2::Argon2, rand::rngs::OsRng, CipherSuite, ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse
};

use hkdf::Hkdf;
use sha2::Sha512;

use crate::webclient::WebClient;
use crate::http_utils::*;
use crate::constants::{
    POST,
    GET   
};

/// Standard Cipher Suite for the vault-manager
/// Using Ristretto255 as an Oprf and. Triple Diffie Hellman for key exchange algorithm and sha512 for hashing
/// And Argon2 (default parameters, argon2id) as a key derivation
struct StandardCipherSuite;

impl CipherSuite for StandardCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

struct Session {
    session_key: Vec<u8>,
    session_token: Vec<u8>,
}

impl Session {

    pub fn new(session_key: Vec<u8>, session_token: Vec<u8>) -> Self {
        Self {
            session_key,
            session_token
        }
    }
}

pub struct OpaqueService {
    web_client: WebClient,
    session: Option<Session>,
    export_key: Option<Key>,
    server_url: String,
}

impl OpaqueService {

    pub fn new(server_url: String) -> Self {
        Self {
            web_client: WebClient::new(),
            session: None,
            export_key: None,
            server_url,
        }
    }

    pub fn register(&mut self, username: &str, password: &str) -> Result<(), String> {
        let mut client_rng = OsRng;

        let client_registration_start_result =
            ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
                .map_err(|protocol_error| protocol_error.to_string())?;

        let registration_response = self.web_client.web_server_request(
            &format!("{}{}", &self.server_url, "/opaque/registration/start"),
            POST,
            Some(construct_body(username, &client_registration_start_result.message.serialize())),
            get_default_headers(),
            None,
        )?;

        let registration_response_bytes = registration_response
            .bytes()
            .map_err(|error| error.to_string())?;

        let server_registration_response =
            RegistrationResponse::deserialize(&registration_response_bytes)
                .map_err(|protocol_error| protocol_error.to_string())?;

        let client_registration_finish_result = client_registration_start_result
            .state
            .finish(
                &mut client_rng,
                password.as_bytes(),
                server_registration_response,
                ClientRegistrationFinishParameters::default(),
            )
            .map_err(|protocol_error| protocol_error.to_string())?;

        self.export_key = Some(Key::new(
            client_registration_finish_result.export_key.to_vec(),
        ));

        let _ = self.web_client.web_server_request(
            &format!("{}{}", &self.server_url, "/opaque/registration/finish"),
            POST,
            Some(construct_body(username, &client_registration_finish_result.message.serialize())),
            get_default_headers(),
            None,
        )?;

        Ok(())
    }

    pub fn login(&mut self, username: &str, password: &str) -> Result<(), String> {
        let mut client_rng = OsRng;

        let client_login_start_result =
            ClientLogin::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .map_err(|protocol_error| protocol_error.to_string())?;

        let login_response = self.web_client.web_server_request(
            &format!("{}{}", &self.server_url, "/opaque/login/start"),
            POST,
            Some(construct_body(username, &client_login_start_result.message.serialize())),
            get_default_headers(),
            None,
        )?;

        let login_response_bytes = login_response
            .bytes()
            .map_err(|error| error.to_string())?;

        let server_login_response =
            CredentialResponse::deserialize(&login_response_bytes)
                .map_err(|protocol_error| protocol_error.to_string())?;

        let client_login_finish_result = client_login_start_result
            .state
            .finish(
                &mut client_rng,
                password.as_bytes(),
                server_login_response,
                ClientLoginFinishParameters::default(),
            )
            .map_err(|protocol_error| protocol_error.to_string())?;

        self.export_key = Some(Key::new(
            client_login_finish_result.export_key.to_vec(),
        ));

        let _ = self.web_client.web_server_request(
            &format!("{}{}", &self.server_url, "/opaque/login/finish"),
            POST,
            Some(construct_body(username, &client_login_finish_result.message.serialize())),
            get_default_headers(),
            None,
        )?;

        let _ = self.create_session(&client_login_finish_result.session_key)?;

        Ok(())
    }

    pub fn get_vault(&self) -> Result<Vec<u8>, String> {

        let uri = format!("{}{}", &self.server_url, "/vault");

        if let None = self.session {
            return Err("No session after loggin.".to_string());
        }

        let session = self.session.as_ref().unwrap();

        let headers = get_vault_request_headers(&session.session_key, &uri)
            .map_err(|error| error.to_string())?;

        let bearer_token = str::from_utf8(&session.session_token)
            .map_err(|error| error.to_string())?;

        let vault_response = self.web_client.web_server_request(
            &uri, 
            GET, 
            None, 
            headers, 
            Some(bearer_token.to_string())
        )?;

        let vault_reponse_bytes = vault_response
            .bytes()
            .map_err(|error| error.to_string())?;

        Ok(vault_reponse_bytes.to_vec())
    }

    pub fn get_export_key(&mut self) -> Option<Key> {
        self.export_key.take()
    }

    fn create_session(&mut self, session_key: &[u8]) -> Result<(), String> {
        
        let hkdf = Hkdf::<Sha512>::new(None, session_key);
        let mut token = vec![0u8, 64];

        hkdf.expand(b"opaque-session-token", &mut token).map_err(|error| error.to_string())?;

        self.session = Some(Session::new(session_key.to_owned(), token));

        Ok(())
    }
}