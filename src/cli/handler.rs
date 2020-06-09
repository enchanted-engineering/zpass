use super::parser::ParamName;
use crate::safe::constants;
use crate::safe::crypto::{CryptoError, Secret};
use crate::safe::preference::{Preference, PreferenceError};
use crate::safe::vault::{VaultError, Vaults};
use clipboard::{ClipboardContext, ClipboardProvider};
use rpassword;
use std::collections::HashMap;
use std::{error, fmt, io, num};

#[derive(Debug)]
pub enum HandlerError {
    MissingVault,
    IOError(io::Error),
    MissingParam(ParamName),
    VaultError(VaultError),
    SecretError(CryptoError),
    PreferenceError(PreferenceError),
    ClipboardError(Box<dyn error::Error>),
    ConversionError(num::ParseIntError),
}

impl fmt::Display for HandlerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::MissingParam(name) => write!(f, "Expected param:\n{:?}", name),
            Self::VaultError(ref err) => write!(f, "Vault error:\n{}", err),
            Self::SecretError(ref err) => write!(f, "Secret error:\n{}", err),
            Self::PreferenceError(ref err) => write!(f, "Preference error:\n{}", err),
            Self::IOError(ref err) => write!(f, "IO error:\n{}", err),
            Self::ClipboardError(ref err) => write!(f, "Clipboard Error:\n{}", err),
            Self::ConversionError(ref err) => write!(f, "Conversion Error:\n{}", err),
            Self::MissingVault => write!(f, "Failed to find the vault"),
        }
    }
}

impl error::Error for HandlerError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match self {
            Self::VaultError(ref err) => Some(err),
            Self::SecretError(ref err) => Some(err),
            Self::PreferenceError(ref err) => Some(err),
            Self::IOError(ref err) => Some(err),
            Self::ClipboardError(ref err) => Some(err.as_ref()),
            Self::ConversionError(ref err) => Some(err),
            _ => None,
        }
    }
}

impl From<VaultError> for HandlerError {
    fn from(err: VaultError) -> Self {
        HandlerError::VaultError(err)
    }
}

impl From<CryptoError> for HandlerError {
    fn from(err: CryptoError) -> Self {
        HandlerError::SecretError(err)
    }
}

impl From<PreferenceError> for HandlerError {
    fn from(err: PreferenceError) -> Self {
        HandlerError::PreferenceError(err)
    }
}

impl From<io::Error> for HandlerError {
    fn from(err: io::Error) -> Self {
        HandlerError::IOError(err)
    }
}

impl From<Box<dyn error::Error>> for HandlerError {
    fn from(err: Box<dyn error::Error>) -> Self {
        HandlerError::ClipboardError(err)
    }
}

impl From<num::ParseIntError> for HandlerError {
    fn from(err: num::ParseIntError) -> Self {
        HandlerError::ConversionError(err)
    }
}

/// Creates a new vault
pub fn add_vault(params: &HashMap<ParamName, String>) -> Result<(), HandlerError> {
    let mut vs: Vaults<Secret> = Vaults::new()?;
    let key = read_key_from_std_in("Key:")?;
    let name = params
        .get(&ParamName::VaultName)
        .ok_or(HandlerError::MissingParam(ParamName::VaultName))?;
    let secret = Secret::new(&key, &name, constants::SECRET_LENGTH)?;
    vs.add(&name, secret)?;
    Ok(())
}

/// Stores the defaults for a password
pub fn add_password(params: &HashMap<ParamName, String>) -> Result<(), HandlerError> {
    let mut m: Vaults<Secret> = Vaults::new()?;
    let v = m.get_default_mut().ok_or(HandlerError::MissingVault)?;
    let domain = params
        .get(&ParamName::DomainName)
        .ok_or(HandlerError::MissingParam(ParamName::DomainName))?;
    let username = params
        .get(&ParamName::UserName)
        .ok_or(HandlerError::MissingParam(ParamName::UserName))?;
    let length = params
        .get(&ParamName::Length)
        .ok_or(HandlerError::MissingParam(ParamName::Length))?
        .parse::<usize>()?;
    let p = Preference::new(domain, username, length);
    v.preferences.add(p)?;
    Ok(())
}

/// Generates a password
pub fn get_password(params: &HashMap<ParamName, String>) -> Result<(), HandlerError> {
    let mut m: Vaults<Secret> = Vaults::new()?;
    let v = m.get_default_mut().ok_or(HandlerError::MissingVault)?;
    let key = read_key_from_std_in("Key:")?;
    let domain = params
        .get(&ParamName::DomainName)
        .ok_or(HandlerError::MissingParam(ParamName::DomainName))?;
    let username = params.get(&ParamName::UserName).map(|v| &v[..]);
    let length = match params.get(&ParamName::Length) {
        Some(l) => match l.parse::<usize>() {
            Ok(l) => Some(l),
            Err(err) => return Err(HandlerError::ConversionError(err)),
        },
        None => None,
    };
    let password = v.get_password(domain, &key, username, length, None)?;
    copy_password_to_clipboard(password)?;
    Ok(())
}

// --------------------------------- Helpers ----------------------------------

/// Reads a line from stdin while concealing what's being typed.
fn read_key_from_std_in(message: &str) -> Result<String, HandlerError> {
    let key = rpassword::read_password_from_tty(Some(message))?;
    Ok(key)
}

/// Copeis a string to the clipboard
fn copy_password_to_clipboard(password: String) -> Result<(), HandlerError> {
    let mut ctx: ClipboardContext = ClipboardProvider::new()?;
    ctx.set_contents(password)?;
    Ok(())
}
