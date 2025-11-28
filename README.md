# Description

Ferry-Vault-TUI is a TUI password manager written in rust.

### Important

The state of the TUI is catastrophic. No correct error handling, weird state handling, could be refactored. The goal was to have a first version working.

It seems clipboard copy doesn't work on linux, failed in CI.

## User features

- Creating a new account
- Logging in to an existing account
- Accessing his vault
- Creating new entries or managing existing ones in the vault
- Inputing manually a new password in an entry, or generating automatically a new one based on requirements like special character, spaces, numbers, alphabetical, etc...
- Seeing a list of command that can be executed on an entry, like ctrl+v to copy/paste automatically, on the TUI

# Project Architecture

This project is based on a hexagonal architecture.

![Project Architecture](architecture.svg)

# Security

This project is design to be a Zero-knowledge architecture based on the OPAQUE protocol.

In a production scenario the password vault in itself should not be stored where the TUI is. There is a trait defining the contract a lib must fulfil in order to retrieve and deliver the vault (decrypted).

In our case this lib should be calling a web-server written in rust through the OPAKE protocol in order to never reveal the password to the server, and storing a crypted vault with the crypted "password-file" on the server.

The password-file will contain all the information needed for the OPAQUE protocol (user private-public keypair, server public key, and user encryption key), it will be crypted using the user's master-password, and the vault will be crypted using the encryption-key stored inside the password-file.

You can find information about Zero-knowledge Architecture and OPAQUE here :

- [NordPass Zero-Knowledge Architecture](https://nordpass.com/features/zero-knowledge-architecture/)
- [Cloudflare blogpost on OPAQUE](https://blog.cloudflare.com/opaque-oblivious-passwords/)
- [OPAQUE resource](https://opaque-auth.com/docs/resources)
- [Audited Rust OPAQUE Implementation](https://github.com/facebook/opaque-ke/tree/main)
- [OPAQUE RFC](https://datatracker.ietf.org/doc/rfc9807/)
- [OPAQUE Paper](https://eprint.iacr.org/2018/163.pdf)