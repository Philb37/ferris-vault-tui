use core::ports::vault_manager::{
    VaultManager,
    Vault
};
use opaque_ke::{
    argon2::Argon2, generic_array::GenericArray, rand::rngs::OsRng, CipherSuite, ClientRegistration, ClientRegistrationFinishParameters, RegistrationResponse, ServerRegistration
};

pub struct OpaqueVaultManager;

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

}

impl VaultManager for OpaqueVaultManager {

    fn create(username: &str, password: &str) -> Result<Vault, String> {

        let mut client_rng = OsRng;

        let client_registration_start_result =
            ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes())
            .map_err(|protocol_error| protocol_error.to_string())?;

        let registration_request = client_registration_start_result.message.serialize();

        // send to server todo!()
 
        let server_registration_response = RegistrationResponse::deserialize(&[1]).map_err(|protocol_error| protocol_error.to_string())?;

        let client_registration_finish_result = client_registration_start_result
            .state
            .finish(
                &mut client_rng, 
                password.as_bytes(), 
                server_registration_response, 
                ClientRegistrationFinishParameters::default()
            )
            .map_err(|protocol_error| protocol_error.to_string())?;

        

        todo!()
    }

    fn retrieve(username: &str) -> Result<Vault, String> {
        todo!()
    }

    fn save(vault: Vault) {
        todo!()
    }
}
