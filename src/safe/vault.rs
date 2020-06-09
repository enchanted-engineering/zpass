use super::collection::List;
use super::constants;
use super::crypto;
use super::preference;
// Serialization and deserialization
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::Error as SerializationError;
use std::{
    cmp::PartialEq,
    fs, io,
    ops::{Deref, DerefMut},
    path,
    path::{Path, PathBuf},
};
// Error
use std::error;
use std::fmt;

#[derive(Debug)]
pub enum VaultError {
    SecretError(crypto::CryptoError),
    PreferenceError(preference::PreferenceError),
    SerializationError(SerializationError),
    IOError(io::Error),
    NoMatchingPreference,
    VaultAlreadyExists,
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::SecretError(ref err) => write!(f, "Failed to decrypt:\n{}", err),
            Self::PreferenceError(ref err) => write!(f, "Invalid Key or IV length:\n{}", err),
            Self::SerializationError(ref err) => write!(f, "de/serialization error:\n{}", err),
            Self::IOError(ref err) => write!(f, "IO error:\n{}", err),
            Self::NoMatchingPreference => write!(f, "No matching preference found"),
            Self::VaultAlreadyExists => write!(f, "Vault already exists"),
        }
    }
}

impl error::Error for VaultError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::SecretError(ref err) => Some(err),
            Self::PreferenceError(ref err) => Some(err),
            Self::SerializationError(ref err) => Some(err),
            Self::IOError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<crypto::CryptoError> for VaultError {
    fn from(err: crypto::CryptoError) -> Self {
        VaultError::SecretError(err)
    }
}

impl From<preference::PreferenceError> for VaultError {
    fn from(err: preference::PreferenceError) -> Self {
        VaultError::PreferenceError(err)
    }
}

impl From<SerializationError> for VaultError {
    fn from(err: SerializationError) -> Self {
        VaultError::SerializationError(err)
    }
}

impl From<io::Error> for VaultError {
    fn from(err: io::Error) -> Self {
        VaultError::IOError(err)
    }
}

/// # Vault
/// Has a secret and keeps the user preferences
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Vault<S: Serialize> {
    // name is the identifier for the vault
    name: String,
    // secret is the encrypted secret that defines the vault
    secret: S,
    // preferences collection of pereferences based on previous user interactions
    pub preferences: preference::Preferences,
    // default indicates wheather this is the default vault
    default: bool,
}

impl<S: Serialize> Vault<S> {
    /// Creates a new Vault.
    pub fn new(name: &str, secret: S, default: bool) -> Vault<S> {
        let name = name.to_owned();
        let preferences = preference::Preferences::new();
        Vault {
            name,
            secret,
            preferences,
            default,
        }
    }

    /// Returns a mutable reference to the matching preference
    pub fn get_preference_mut(
        &mut self,
        domain: &str,
        username: &str,
    ) -> Result<&mut preference::Preference, VaultError> {
        self.preferences
            .get_mut(|p| p.domain == domain && p.username == username)
            .ok_or(VaultError::NoMatchingPreference)
    }
}

impl<S: Serialize + crypto::PasswordGenerator> Vault<S> {
    /// Generates a password. All the password parameters other than domain and key
    /// are populated from the default preference if not specified.
    pub fn get_password(
        &self,
        domain: &str,
        key: &str,
        username: Option<&str>,
        length: Option<usize>,
        version: Option<usize>,
    ) -> Result<String, VaultError> {
        let preference = if let Some(username) = username {
            self.preferences
                .get(|p| p.domain == domain && p.username == username)
        } else {
            self.preferences.get_default(|p| p.domain == domain)
        };

        let preference = preference.ok_or(VaultError::NoMatchingPreference)?;
        let username = username.unwrap_or(&preference.username);
        let length = length.unwrap_or(preference.length);
        let version = version.unwrap_or(preference.version);

        let password = self.secret.get(
            key,
            crypto::PasswordParam {
                domain,
                username,
                length,
                version,
            },
        )?;
        Ok(password)
    }
}

impl<S: Serialize + DeserializeOwned> Vault<S> {
    /// Deserializes a Vault from a JSON object.
    pub fn deserialize(serialized: String) -> Result<Vault<S>, VaultError> {
        let deserialized = serde_json::from_slice(serialized.as_bytes())?;
        Ok(deserialized)
    }
}

impl<S: Serialize> Vault<S> {
    /// Serializes a Vault into a JSON string
    fn serialize(&self) -> Result<String, VaultError> {
        let serialized = serde_json::to_string_pretty(self)?;
        Ok(serialized)
    }

    /// Returns the path to where the vault is stored on disk.
    fn path(&self) -> PathBuf {
        let mut path = PathBuf::new();
        path.push(constants::ROOT_PATH);
        path.push(&self.name);
        path.with_extension("json")
    }

    /// Serializes the Vault and stores it on disk.
    fn store(&self) -> Result<(), VaultError> {
        let root = Path::new(constants::ROOT_PATH);
        if !root.exists() {
            // create the root directory if it doesn't exists
            fs::create_dir(root)?;
        }
        let serialized = self.serialize()?;
        fs::write(self.path(), serialized)?;
        Ok(())
    }
}

impl<S: Serialize> Drop for Vault<S> {
    /// When a Vault is dropped, it is written to disk.
    /// So you never have to think about persisting changes after a mutation.
    /// Just before the memory for the vault is reclaimed, we store on disk.
    fn drop(&mut self) {
        self.store().unwrap()
    }
}

pub struct Vaults<S: Serialize> {
    items: List<Vault<S>>,
}

impl<S: Serialize + DeserializeOwned> Vaults<S> {
    /// Reads all the vaults under the root-path into memory.
    pub fn new() -> Result<Vaults<S>, VaultError> {
        let root = path::Path::new(constants::ROOT_PATH);
        if !root.exists() {
            return Ok(Vaults { items: List::new() });
        };

        let contents = get_dir_contents(root)?;
        let vaults = contents
            .into_iter()
            .map(|c| Vault::deserialize(c).unwrap())
            .collect();
        let vaults = List::from(vaults);
        return Ok(Vaults { items: vaults });
    }
}

impl<S: Serialize> Vaults<S> {
    /// Creates a new Vault with the given name and adds to the collection of vaults.
    /// If this is the first Vault that's getting created, the vault is marked as default.
    pub fn add(&mut self, name: &str, secret: S) -> Result<(), VaultError> {
        // make sure the name is unique
        if self.has(|v| v.name == name) {
            return Err(VaultError::VaultAlreadyExists);
        }

        // if this is the first vault, label it as default
        let default = self.is_empty();
        self.items.add(Vault::new(name, secret, default));
        Ok(())
    }

    /// Returns the default vault.
    pub fn get_default_mut(&mut self) -> Option<&mut Vault<S>> {
        self.get_mut(|p| p.default == true)
    }
}

impl<S: Serialize> Deref for Vaults<S> {
    type Target = List<Vault<S>>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl<S: Serialize> DerefMut for Vaults<S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.items
    }
}

/// Returns all the files in a directory as a sequence of strings.
fn get_dir_contents(root: &path::Path) -> Result<Vec<String>, VaultError> {
    let mut contents = Vec::new();
    let reader = fs::read_dir(root)?;

    for path in reader {
        let path = path?.path();
        let content = fs::read_to_string(path)?;
        contents.push(content);
    }

    Ok(contents)
}

#[cfg(test)]
mod tests {
    use super::super::crypto::Secret;
    use super::*;

    #[test]
    fn vault_serialization() {
        let name = "VALT_NAME";
        let key = "KEY";
        let iv = "IV";
        let secret = Secret::new(key, iv, 40).unwrap();
        let vault = Vault::new(name, secret, true);

        let serialized = vault.serialize().unwrap();
        let deserialized = Vault::deserialize(serialized).unwrap();

        assert_eq!(vault, deserialized);
    }
}
