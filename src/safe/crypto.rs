//! # Crypto
//! Wrappers for working with cryptographic primitives.

// Encryption
use aes::Aes256;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, BlockModeError, Cbc, InvalidKeyIvLength};
// Random Secret
use rand::Rng;
// Hashing
use sha3::{Digest, Sha3_256};
// Serialization
use serde::{Deserialize, Serialize};
// Comparision
use std::cmp::PartialEq;
// Error
use std::error;
use std::fmt;

#[derive(Debug)]
pub enum CryptoError {
    FailedToDecrypt(BlockModeError),
    InvalidKeyIvLength(InvalidKeyIvLength),
}

impl fmt::Display for CryptoError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::FailedToDecrypt(ref err) => write!(f, "Failed to decrypt:\n{}", err),
            Self::InvalidKeyIvLength(ref err) => write!(f, "Invalid Key or IV length:\n{}", err),
        }
    }
}

impl error::Error for CryptoError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::FailedToDecrypt(ref err) => Some(err),
            Self::InvalidKeyIvLength(ref err) => Some(err),
        }
    }
}

impl From<BlockModeError> for CryptoError {
    fn from(err: BlockModeError) -> Self {
        CryptoError::FailedToDecrypt(err)
    }
}

impl From<InvalidKeyIvLength> for CryptoError {
    fn from(err: InvalidKeyIvLength) -> Self {
        CryptoError::InvalidKeyIvLength(err)
    }
}

/// Parameters that affect the generated password.
pub struct PasswordParam<'a> {
    pub domain: &'a str,
    pub username: &'a str,
    pub length: usize,
    pub version: usize,
}

/// Defines the interface for generating passwords.
pub trait PasswordGenerator {
    /// Password generation is deterministic.
    /// We can use the Key to decrypt the secret that become an input to the password generator
    /// along with the other password paramters.
    fn get(&self, key: &str, param: PasswordParam) -> Result<String, CryptoError>; // TODO: this should return a generic error: Box<dyn Error>
}

/// # Secret
/// Implements PasswordGenerator trait so it can be used to create passwords.
/// Implements Serialize and Deserialize so it can be included in the vault.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Secret {
    encrypted_secret: Vec<u8>,
    iv: String,
}

impl Secret {
    /// Creates a secret given a key, initial vector IV and expected secret length.
    pub fn new(key: &str, iv: &str, length: usize) -> Result<Secret, CryptoError> {
        let secret = Self::random_secret(length);
        let encrypted_secret = Cipher::new(key, iv)?.encrypt(&secret);
        let iv = iv.to_owned();
        Ok(Secret {
            encrypted_secret,
            iv,
        })
    }

    /// Returns a sequence of random bytes of the given length
    fn random_secret(length: usize) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let secret = (0..length).map(|_| rng.gen::<u8>()).collect();
        secret
    }

    /// Maps bytes to a subset of ascii character range.
    fn to_ascii_range(v: Vec<u8>) -> String {
        v.iter().map(|b| (b % 92 + 33) as char).collect()
    }

    /// Hashs data to 256 bits or 16 bytes.
    fn hash(data: &Vec<u8>) -> Vec<u8> {
        let hash = Sha3_256::digest(&data);
        hash.iter().map(|b| *b).collect()
    }
}

impl PasswordGenerator for Secret {
    fn get(&self, key: &str, _params: PasswordParam) -> Result<String, CryptoError> {
        let secret = Cipher::new(key, &self.iv)?.decrypt(&self.encrypted_secret)?;
        // TODO: include the password params in the preimage
        let ascii_password = Self::to_ascii_range(Self::hash(&secret));
        Ok(ascii_password)
    }
}

/// Cipher Block Chaining
type Aes256Cbc = Cbc<Aes256, Pkcs7>;
/// Initial Vector length for AES 256
const IV_LENGTH_FOR_AES_256_IN_BYTES: usize = 16;

/// # Cipher
/// A wrapper around Aes256Cbc
struct Cipher {
    alg: Aes256Cbc,
}

impl Cipher {
    /// Retuns a new Cipher given a key and initial vector IV.
    pub fn new(key: &str, iv: &str) -> Result<Cipher, CryptoError> {
        let key = Self::hash(key);
        let iv = Self::hash(iv);
        let alg = Aes256Cbc::new_var(&key, &iv[..IV_LENGTH_FOR_AES_256_IN_BYTES])?;
        Ok(Cipher { alg })
    }

    /// Encrypts a plain text
    pub fn encrypt(self, plaintext: &Vec<u8>) -> Vec<u8> {
        self.alg.encrypt_vec(plaintext)
    }

    /// Decrypts a cipher text
    pub fn decrypt(self, ciphertext: &Vec<u8>) -> Result<Vec<u8>, CryptoError> {
        let plaintext = self.alg.decrypt_vec(ciphertext)?;
        Ok(plaintext)
    }

    /// Hashs a given string slice to 256 bits or 16 bytes
    fn hash(data: &str) -> Vec<u8> {
        let data = data.as_bytes().to_vec();
        let hash = Sha3_256::digest(&data);
        hash.iter().map(|b| *b).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inverse() {
        let key = "EXAMPLE_KEY";
        let iv = "EXAMPLE_IV";
        let secret = "SECRET".as_bytes().to_vec();
        let cipher = Cipher::new(&key, &iv).unwrap().encrypt(&secret);
        let message = Cipher::new(&key, &iv).unwrap().decrypt(&cipher).unwrap();

        assert_eq!(message, secret);
    }
}
