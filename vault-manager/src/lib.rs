use core::ports::vault_manager::{
    VaultManager,
    Vault
};
use opaque_ke::{
    argon2::Argon2, rand::rngs::OsRng, CipherSuite, ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse, ServerRegistration
};
use reqwest::blocking::Client;

pub struct OpaqueVaultManager {
    client: Client,
    server_url: String
}

/// Standard Cipher Suite for the vault-manager
/// Using Ristretto255 as an Oprf and. Triple Diffie Hellman for key exchange algorithm and sha512 for hashing
/// And Argon2 (default parameters, argon2id) as a key derivation
struct StandardCipherSuite;

impl CipherSuite for StandardCipherSuite {
    type OprfCs = opaque_ke::Ristretto255;
    type KeyExchange = opaque_ke::TripleDh<opaque_ke::Ristretto255, sha2::Sha512>;
    type Ksf = Argon2<'static>;
}

impl OpaqueVaultManager {

    pub fn new(server_url: String) -> Self {
        Self {
            client: Client::new(),
            server_url
        }
    }
}

impl VaultManager for OpaqueVaultManager {

    fn create(&self, username: &str, password: &str) -> Result<Vault, String> {

        let mut client_rng = OsRng;

        let client_registration_start_result =
            ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .map_err(|protocol_error| protocol_error.to_string())?;

        let registration_request = client_registration_start_result.message.serialize();

        let registration_response_bytes = self.client
            .post(format!("{}/opaque/registration/start", self.server_url))
            .header("Content-Type", "application/octet-stream")
            .body(registration_request.to_vec())
            .send()
            .map_err(|error| error.to_string())?;

        // todo!() replace &[1] with registration_response_bytes content
        let server_registration_response = 
            RegistrationResponse::deserialize(&[1])
            .map_err(|protocol_error| protocol_error.to_string())?;

        let client_registration_finish_result = client_registration_start_result
            .state
            .finish(
                &mut client_rng, 
                password.as_bytes(), 
                server_registration_response, 
                ClientRegistrationFinishParameters::default()
            )
            .map_err(|protocol_error| protocol_error.to_string())?;

        Ok(
            Vault {
                username: String::from(username),
                content: vec!(1), // todo!()
                decryption_key: client_registration_finish_result.export_key.to_vec()
            }
        )
    }

    fn retrieve(&self, username: &str) -> Result<Vault, String> {
        todo!()
    }

    fn save(&self, vault: Vault) {
        todo!()
    }
}
