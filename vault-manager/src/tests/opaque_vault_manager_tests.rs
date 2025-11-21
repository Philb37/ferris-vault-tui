use app_core::errors::vault_error::VaultError;
use app_core::ports::vault_manager::{Key, Vault, VaultManager};
use std::cell::RefCell;
use std::collections::{HashMap};

use crate::opaque_api::{Api};
use crate::opaque_vault_manager::{OpaqueVaultManager, StandardCipherSuite};
use opaque_ke::generic_array::GenericArray;
use opaque_ke::{ClientRegistration, ClientRegistrationFinishParameters, ServerLogin, ServerLoginParameters, ServerLoginStartResult, ServerRegistration, ServerRegistrationLen, ServerSetup};

use opaque_ke::rand::rngs::OsRng;

#[test]
fn should_create_vault() {

    // A-rrange

    let mut opaque_vault_manager = create_opaque_vault_manager(MockOpaqueClient::new(false));
    let username = "username";
    let password = "password";

    // A-ct

    let vault = opaque_vault_manager.create(username, password).unwrap();

    // A-ssert

    assert_eq!(vault.content, vec![42]);
    assert!(!vault.encryption_key.bytes.is_empty())
}

#[test]
fn should_not_create_vault_if_logged_in() {

    // A-rrange

    let mut opaque_vault_manager = create_opaque_vault_manager(MockOpaqueClient::new(true));
    let username = "username";
    let password = "password";

    // A-ct

    let vault = opaque_vault_manager.create(username, password);

    // A-ssert

    match vault {
        Err(VaultError::AlreadyLoggedIn(error)) => assert_eq!(error, "Cannot save a vault if you are not logged in."),
        _ => panic!("Test result should be: 'AlreadyLoggedIn' error.")
    }
}

#[test]
fn should_retrieve_vault() {

    // A-rrange

    let username = "username";
    let password = "password";

    let mock_opaque_api = MockOpaqueClient::new(false);
    
    let mut client_rng = OsRng;

    let client_registration_start_result =
            ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap();

    let server_registration_response = mock_opaque_api
        .start_server_registration(username, &client_registration_start_result).unwrap();

    let client_registration_finish_result = client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            server_registration_response,
            ClientRegistrationFinishParameters::default(),
        ).unwrap();
    
    mock_opaque_api.finish_server_registration(username, &client_registration_finish_result).unwrap();
    
    let mut opaque_vault_manager = create_opaque_vault_manager(mock_opaque_api);

    // A-ct

    let vault = opaque_vault_manager.retrieve(username, password).unwrap();

    // A-ssert

    assert_eq!(vault.content, vec![42]);
    assert!(!vault.encryption_key.bytes.is_empty());
}

#[test]
fn should_save_vault() {

    // A-rrange

    let opaque_vault_manager = create_opaque_vault_manager(MockOpaqueClient::new(true));
    let vault = Vault::new(vec![], Key::new(vec![]));

    // A-ct

    let result = opaque_vault_manager.save(vault);

    // A-ssert
    assert!(result.is_ok());
}

#[test]
fn should_not_save_vault_if_not_logged_in() {

    // A-rrange

    let opaque_vault_manager = create_opaque_vault_manager(MockOpaqueClient::new(false));
    let vault = Vault::new(vec![], Key::new(vec![]));

    // A-ct

    let result = opaque_vault_manager.save(vault);

    // A-ssert
    
    match result {
        Err(VaultError::NotLoggedIn(error)) => assert_eq!(error, "Cannot create a new vault if you are already logged in."),
        _ => panic!("Test result should be: 'NotLoggedIn' error.")
    }
}

struct ServerState {
    server_setup: ServerSetup<StandardCipherSuite>,
    users: HashMap::<String, GenericArray<u8, ServerRegistrationLen<StandardCipherSuite>>>,
    server_login_start_result: Option<ServerLoginStartResult<StandardCipherSuite>>
}

impl ServerState {

    fn new() -> Self {

        let mut rng = OsRng;
        let server_setup = ServerSetup::<StandardCipherSuite>::new(&mut rng);

        Self {
            server_login_start_result: None,
            server_setup,
            users: HashMap::new()
        }
    }

    fn add_user(&mut self, username: String, password_file: GenericArray<u8, ServerRegistrationLen<StandardCipherSuite>>) {
        self.users.insert(username, password_file);
    }
}

struct MockOpaqueClient {
    server_state: RefCell<ServerState>,
    is_logged_in: bool
}

impl MockOpaqueClient {

    fn new(is_logged_in: bool) -> Self {
        Self {
            server_state: RefCell::new(ServerState::new()),
            is_logged_in
        }
    }
}

impl Api for MockOpaqueClient {

    fn start_server_registration(
        &self,
        username: &str,
        client_registration_start_result: &opaque_ke::ClientRegistrationStartResult<StandardCipherSuite>,
    ) -> crate::Result<opaque_ke::RegistrationResponse<StandardCipherSuite>> {
        
        let server_registration_start_result = ServerRegistration::<StandardCipherSuite>::start(
            &self.server_state.borrow().server_setup,
            client_registration_start_result.message.clone(),
            username.as_bytes(),
        ).unwrap();

        Ok(server_registration_start_result.message)
    }

    fn finish_server_registration(
        &self,
        username: &str,
        client_registration_finish_result: &opaque_ke::ClientRegistrationFinishResult<StandardCipherSuite>,
    ) -> crate::Result<()> {
        
        let password_file = ServerRegistration::<StandardCipherSuite>::finish(
            client_registration_finish_result.message.clone(),
        );

        self.server_state.borrow_mut().add_user(username.to_string(), password_file.serialize());

        Ok(())
    }

    fn start_server_login(
        &self,
        username: &str,
        client_login_start_result: &opaque_ke::ClientLoginStartResult<StandardCipherSuite>,
    ) -> crate::Result<opaque_ke::CredentialResponse<StandardCipherSuite>> {

        let mut server_state = self.server_state.borrow_mut();
       
        let password_file_bytes = server_state.users.get(username).unwrap();

        let password_file = 
            ServerRegistration::<StandardCipherSuite>::deserialize(&password_file_bytes).unwrap();

        let mut server_rng = OsRng;
        
        let server_login_start_result = ServerLogin::start(
            &mut server_rng,
            &server_state.server_setup,
            Some(password_file),
            client_login_start_result.message.clone(),
            username.as_bytes(),
            ServerLoginParameters::default(),
        ).unwrap();

        server_state.server_login_start_result = Some(server_login_start_result.clone());

        Ok(server_login_start_result.message)
    }

    fn finish_server_login(
        &mut self,
        _: &str,
        client_login_finish_result: &opaque_ke::ClientLoginFinishResult<StandardCipherSuite>,
    ) -> crate::Result<()> {
        
        let _= self.server_state.borrow_mut()
            .server_login_start_result.take().unwrap()
            .state.finish(
            client_login_finish_result.message.clone(),
            ServerLoginParameters::default(),
        ).unwrap();

        Ok(())
    }

    fn get_vault(&self) -> crate::Result<Vec<u8>> {
        Ok(vec![42])
    }

    fn save_vault(&self, _: Vec<u8>) -> crate::Result<()> {
        Ok(())
    }

    fn is_logged_in(&self) -> bool {
        self.is_logged_in
    }
}

fn create_opaque_vault_manager(mock_opaque_client: MockOpaqueClient) -> OpaqueVaultManager<MockOpaqueClient> {
    OpaqueVaultManager::new(mock_opaque_client)
}