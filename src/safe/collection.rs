//! # Collection
//! Wrappers for working with data structures that act like collections.

use serde::{Deserialize, Serialize};
use std::cmp::PartialEq;

/// # List
/// Represents a sequence of items. It is a wrapper around Vec that does not expose the underlying Vec.
#[derive(Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct List<T> {
    items: Vec<T>,
}

impl<T> List<T> {
    /// Creates an empty List.
    pub fn new() -> List<T> {
        List { items: Vec::new() }
    }

    /// Creates a new List from a Vec.
    pub fn from(items: Vec<T>) -> List<T> {
        List { items }
    }

    /// Adds an item to the List.
    pub fn add(&mut self, item: T) {
        self.items.push(item);
    }

    /// Returns true if an item satisfies the predicate.
    pub fn has<F>(&self, f: F) -> bool
    where
        F: Fn(&T) -> bool,
    {
        match self.items.iter().position(f) {
            None => false,
            Some(_) => true,
        }
    }

    /// Returns an immutable reference to the first item that satisfies the predicate.
    pub fn get<F>(&self, f: F) -> Option<&T>
    where
        F: Fn(&T) -> bool,
    {
        match self.items.iter().position(f) {
            None => None,
            Some(position) => self.items.get(position),
        }
    }

    /// Returns a mutable reference to the first item that satisfies the predicate.
    pub fn get_mut<F>(&mut self, f: F) -> Option<&mut T>
    where
        F: Fn(&T) -> bool,
    {
        match self.items.iter().position(f) {
            None => None,
            Some(position) => self.items.get_mut(position),
        }
    }

    /// Applies a closure to all the items in the List.
    pub fn apply<F>(&mut self, f: F) -> ()
    where
        F: FnMut(&mut T) -> (),
    {
        self.items.iter_mut().for_each(f);
    }

    /// Returns true if List contains no items.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}
