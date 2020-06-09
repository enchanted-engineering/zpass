# ZPass

This is a proof of concept for a serverless password manager.

## 🚨✋🚫✋
❗I'm **NOT** a security or cryptography expert.
❗This project is in no way close to being done.

## How

- When you create a new vault, ZPass creates a secret key.
- ZPass generates a password by passing the secret key along with the domain, username and version to the SHA-3.
- ZPass encrypts the secret key using AES 256, and a user-provided passphrase.

## Why

- 🔑 Since passwords are generated deterministically, with the secret key alone, you can recover all your passwords.
- 🔒 You can keep everything local. Just export the encrypted secret key, for example, as a QR Code and keep it somewhere safe.
- 💪 If you don't trust existing providers, why not write your own.

# Attribution
I enjoyed reading
- https://bodil.lol/parser-combinators/ before writing the parser and
- https://blog.burntsushi.net/rust-error-handling/ when implementing the error handling logic

I'm using
- https://github.com/aweinstock314/rust-clipboard to copy the password into the clipboard
- The SHA-3 implementation from https://github.com/RustCrypto/hashes for generating the passwords
- https://github.com/rust-random/rand for creating the secret key
- https://github.com/serde-rs/serde and https://github.com/serde-rs/json for serialization and deserialization of the vaults
- https://github.com/J-F-Liu/pom to parse the CLI arguments
- https://github.com/conradkleinespel/rpassword to read the passphrase from stdin
- AES and Blockmodes from https://github.com/RustCrypto/block-ciphers to encrypt the secret key
