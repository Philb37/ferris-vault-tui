use app_core::{vault::vault_error::VaultError};
use mockito::Server;
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientLoginFinishResult, ClientLoginStartResult,
    ClientRegistration, ClientRegistrationFinishParameters, ClientRegistrationFinishResult,
    ClientRegistrationStartResult, CredentialResponse, RegistrationResponse, ServerLogin,
    ServerLoginParameters, ServerLoginStartResult, ServerRegistration,
    ServerRegistrationStartResult, ServerSetup, rand::rngs::OsRng,
};

use crate::{
    constants::{GET, OPAQUE_LOGIN_FINISH, OPAQUE_LOGIN_START, OPAQUE_REGISTRATION_FINISH, OPAQUE_REGISTRATION_START, POST, VAULT},
    opaque_api::{Api, OpaqueApi},
    opaque_vault_manager::StandardCipherSuite,
};

const USERNAME: &'static str = "username";
const PASSWORD: &'static str = "password";

#[test]
fn should_start_server_registration() {
    // A-rrange

    let client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<StandardCipherSuite>::new(&mut server_rng);

    let client_registration_start_result = start_client_registration(client_rng, PASSWORD);

    let server_registration_start_result =
        start_server_registration(USERNAME, &server_setup, &client_registration_start_result);

    let server_registration_start_result_bytes = server_registration_start_result.message.serialize();

    let expected_server_response =
        RegistrationResponse::deserialize(&server_registration_start_result_bytes)
            .unwrap();

    let mut server = Server::new();

    let mock = server
        .mock(POST, OPAQUE_REGISTRATION_START)
        .with_status(200)
        .with_header("Content-Type", "application/octet-stream")
        .with_body(server_registration_start_result_bytes)
        .create();

    let opaque_api = OpaqueApi::new(server.url());

    // A-ct

    let result = opaque_api.start_server_registration(USERNAME, &client_registration_start_result);

    // A-ssert

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected_server_response);
    assert!(!opaque_api.is_logged_in());

    mock.assert();
}

#[test]
fn should_finish_server_registration() {
    // A-rrange

    let client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<StandardCipherSuite>::new(&mut server_rng);

    let client_registration_start_result = start_client_registration(client_rng, PASSWORD);

    let server_registration_start_result =
        start_server_registration(USERNAME, &server_setup, &client_registration_start_result);

    let server_registration_response =
        RegistrationResponse::deserialize(&server_registration_start_result.message.serialize())
            .unwrap();

    let client_registration_finish_result = finish_client_registration(
        client_registration_start_result,
        client_rng,
        PASSWORD,
        server_registration_response,
    );

    let mut server = Server::new();

    let mock = server
        .mock(POST, OPAQUE_REGISTRATION_FINISH)
        .with_status(200)
        .create();

    let opaque_api = OpaqueApi::new(server.url());

    // A-ct

    let result =
        opaque_api.finish_server_registration(USERNAME, &client_registration_finish_result);

    // A-ssert

    assert!(result.is_ok());
    assert!(!opaque_api.is_logged_in());

    mock.assert();
}

#[test]
fn should_start_server_login() {
    // A-rrange

    let client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<StandardCipherSuite>::new(&mut server_rng);

    let password_file = register_user(USERNAME, PASSWORD, client_rng, &server_setup);

    let client_login_start_result = start_client_login(client_rng, PASSWORD);

    let server_login_start_result = start_server_login(server_rng, &server_setup, password_file, &client_login_start_result, USERNAME);

    let server_login_start_result_bytes = server_login_start_result.message.serialize();

    let expected_server_result = CredentialResponse::deserialize(&server_login_start_result_bytes).unwrap();
    
    let mut server = Server::new();

    let mock = server
        .mock(POST, OPAQUE_LOGIN_START)
        .with_status(200)
        .with_header("Content-Type", "application/octet-stream")
        .with_body(server_login_start_result_bytes)
        .create();

    let opaque_api = OpaqueApi::new(server.url());

    // A-ct

    let result = opaque_api.start_server_login(USERNAME, &client_login_start_result);

    // A-ssert

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), expected_server_result);
    assert!(!opaque_api.is_logged_in());

    mock.assert();
}

#[test]
fn should_finish_server_login() {
    // A-rrange
    
    let client_login_finish_result = login();
    
    let mut server = Server::new();

    let mock = server
        .mock(POST, OPAQUE_LOGIN_FINISH)
        .with_status(200)
        .create();

    let mut opaque_api = OpaqueApi::new(server.url());

    // A-ct

    let result = opaque_api.finish_server_login(USERNAME, &client_login_finish_result);

    // A-ssert

    assert!(result.is_ok());
    assert!(opaque_api.is_logged_in());

    mock.assert();
}

#[test]
fn should_get_vault() {

    // A-rrange

    let client_login_finish_result = login();

    let expected = vec![42];

    let mut server = Server::new();

    let _ = server
        .mock(POST, OPAQUE_LOGIN_FINISH)
        .with_status(200)
        .create();

    let vault_mock = server
        .mock(GET, VAULT)
        .with_status(200)
        .with_header("Content-Type", "application/octet-stream")
        .with_body(&expected)
        .create();

    let mut opaque_api = OpaqueApi::new(server.url());

    opaque_api.finish_server_login(USERNAME, &client_login_finish_result).unwrap();

    // A-ct

    let result = opaque_api.get_vault();

    // A-ssert

    assert!(result.is_ok());

    let result = result.unwrap();

    assert!(!result.is_empty());
    assert_eq!(result, expected);

    vault_mock.assert();
}

#[test]
fn should_save_vault() {

    // A-rrange

    let client_login_finish_result = login();

    let mut server = Server::new();

    let _ = server
        .mock(POST, OPAQUE_LOGIN_FINISH)
        .with_status(200)
        .create();

    let vault_mock = server
        .mock(POST, VAULT)
        .with_status(200)
        .create();

    let mut opaque_api = OpaqueApi::new(server.url());

    opaque_api.finish_server_login(USERNAME, &client_login_finish_result).unwrap();

    let vault = vec![42];

    // A-ct

    let result = opaque_api.save_vault(vault);

    // A-ssert

    assert!(result.is_ok());

    vault_mock.assert();
}

#[test]
fn should_be_exchange_failed_error() {

    // A-rrange

    let client_rng = OsRng;

    let client_registration_start_result = start_client_registration(client_rng, PASSWORD);

    let server = Server::new();

    let opaque_api = OpaqueApi::new(server.url());

    // A-ct

    let result = opaque_api.start_server_registration(USERNAME, &client_registration_start_result);

    // A-ssert

    assert!(result.is_err());
    
    match result {
        Err(VaultError::ExchangeFailed(_)) => assert!(true),
        _ => panic!("Test result should be Err(VaultError::ExchangeFailed).")
    }
}

fn start_client_registration(
    mut client_rng: OsRng,
    password: &str,
) -> ClientRegistrationStartResult<StandardCipherSuite> {
    ClientRegistration::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap()
}

fn start_server_registration(
    username: &str,
    server_setup: &ServerSetup<StandardCipherSuite>,
    client_registration_start_result: &ClientRegistrationStartResult<StandardCipherSuite>,
) -> ServerRegistrationStartResult<StandardCipherSuite> {
    ServerRegistration::<StandardCipherSuite>::start(
        server_setup,
        client_registration_start_result.message.clone(),
        username.as_bytes(),
    )
    .unwrap()
}

fn finish_client_registration(
    client_registration_start_result: ClientRegistrationStartResult<StandardCipherSuite>,
    mut client_rng: OsRng,
    password: &str,
    server_registration_response: RegistrationResponse<StandardCipherSuite>,
) -> ClientRegistrationFinishResult<StandardCipherSuite> {
    client_registration_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            server_registration_response,
            ClientRegistrationFinishParameters::default(),
        )
        .unwrap()
}

fn finish_server_registration(
    client_registration_finish_result: ClientRegistrationFinishResult<StandardCipherSuite>,
) -> ServerRegistration<StandardCipherSuite> {
    ServerRegistration::<StandardCipherSuite>::finish(
        client_registration_finish_result.message.clone(),
    )
}

fn register_user(
    username: &str,
    password: &str,
    client_rng: OsRng,
    server_setup: &ServerSetup<StandardCipherSuite>,
) -> ServerRegistration<StandardCipherSuite> {
    let client_registration_start_result = start_client_registration(client_rng, password);
    let server_registration_response =
        start_server_registration(username, server_setup, &client_registration_start_result);
    let client_registration_finish_result = finish_client_registration(
        client_registration_start_result,
        client_rng,
        password,
        RegistrationResponse::deserialize(&server_registration_response.message.serialize())
            .unwrap(),
    );
    finish_server_registration(client_registration_finish_result)
}

fn start_client_login(
    mut client_rng: OsRng,
    password: &str,
) -> ClientLoginStartResult<StandardCipherSuite> {
    ClientLogin::<StandardCipherSuite>::start(&mut client_rng, password.as_bytes()).unwrap()
}

fn start_server_login(
    mut server_rng: OsRng,
    server_setup: &ServerSetup<StandardCipherSuite>,
    password_file: ServerRegistration<StandardCipherSuite>,
    client_login_start_result: &ClientLoginStartResult<StandardCipherSuite>,
    username: &str,
) -> ServerLoginStartResult<StandardCipherSuite> {
    ServerLogin::start(
        &mut server_rng,
        server_setup,
        Some(password_file),
        client_login_start_result.message.clone(),
        username.as_bytes(),
        ServerLoginParameters::default(),
    )
    .unwrap()
}

fn finish_client_login(
    client_login_start_result: ClientLoginStartResult<StandardCipherSuite>,
    mut client_rng: OsRng,
    password: &str,
    server_login_response: CredentialResponse<StandardCipherSuite>,
) -> ClientLoginFinishResult<StandardCipherSuite> {
    client_login_start_result
        .state
        .finish(
            &mut client_rng,
            password.as_bytes(),
            server_login_response,
            ClientLoginFinishParameters::default(),
        )
        .unwrap()
}

fn login() -> ClientLoginFinishResult<StandardCipherSuite> {

    let client_rng = OsRng;
    let mut server_rng = OsRng;
    let server_setup = ServerSetup::<StandardCipherSuite>::new(&mut server_rng);

    let password_file = register_user(USERNAME, PASSWORD, client_rng, &server_setup);

    let client_login_start_result = start_client_login(client_rng, PASSWORD);

    let server_login_start_result = start_server_login(server_rng, &server_setup, password_file, &client_login_start_result, USERNAME);

    let server_login_start_result_bytes = server_login_start_result.message.serialize();

    let server_login_response = CredentialResponse::deserialize(&server_login_start_result_bytes).unwrap();
    
    finish_client_login(client_login_start_result, client_rng, PASSWORD, server_login_response)
}