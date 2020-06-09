use super::collection::List;
use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;
use std::ops::{Deref, DerefMut};

use std::error;
use std::fmt;

#[derive(Debug)]
pub enum PreferenceError {
    PreferenceExists,
    NoMatchingPreferenceFound,
}

impl fmt::Display for PreferenceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::PreferenceExists => write!(f, "Precodition violation: preference already exists"),
            Self::NoMatchingPreferenceFound => write!(f, "Failed to find a matching preference"),
        }
    }
}

impl error::Error for PreferenceError {}

/// # Preference
/// Associated with each domain + username are default parameters based on previous user interactions
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Preference {
    // domain name such as "google.com"
    pub domain: String,
    // username to differentiate multiple users for same domain
    pub username: String,
    // length of the password in characters
    pub length: usize,
    // version is incremented everytime we update ta password
    pub version: usize,
    // default indicates wheather this is the default preference for the domain
    default: bool,
}

impl Preference {
    /// Creates a new preference struct.
    pub fn new(domain: &str, username: &str, length: usize) -> Preference {
        Preference {
            domain: domain.to_owned(),
            username: username.to_owned(),
            length,
            version: 0,
            default: false,
        }
    }
}

/// # Preferences
/// A collection of preference items.
/// Enforces a constraint that only one preference for each domain can be the default preference.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct Preferences {
    #[serde(flatten)]
    items: List<Preference>,
}

impl Preferences {
    /// Creates an empty Preferences collection.
    pub fn new() -> Preferences {
        Preferences { items: List::new() }
    }

    /// Adds a preference item to the collection.
    pub fn add(&mut self, preference: Preference) -> Result<(), PreferenceError> {
        if self.has(|p| p.domain == preference.domain && p.username == preference.username) {
            return Err(PreferenceError::PreferenceExists);
        }
        let default = !self.has_default(|p| p.domain == preference.domain);
        let preference = Preference {
            default,
            ..preference
        };
        self.items.add(preference);
        Ok(())
    }

    /// Returns true of a default preference satisfies the predicate.
    pub fn has_default<F>(&self, f: F) -> bool
    where
        F: Fn(&Preference) -> bool,
    {
        self.has(|p| p.default == true && f(p))
    }

    /// Returns an immutable reference to the first default preference satisfying the predicate.
    pub fn get_default<F>(&self, f: F) -> Option<&Preference>
    where
        F: Fn(&Preference) -> bool,
    {
        self.get(|p| p.default == true && f(p))
    }

    /// Sets a new default preference for a domain. This method ensures that the there is only one
    /// default preference for each domain.
    pub fn set_default(&mut self, domain: &str, username: &str) -> Result<(), PreferenceError> {
        if !self.has(|p| p.domain == domain && p.username == username) {
            return Err(PreferenceError::NoMatchingPreferenceFound);
        }

        self.items.apply(|mut p| {
            if p.domain == domain {
                p.default = p.username == username;
            }
        });

        Ok(())
    }
}

impl Deref for Preferences {
    type Target = List<Preference>;

    fn deref(&self) -> &Self::Target {
        &self.items
    }
}

impl DerefMut for Preferences {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.items
    }
}
