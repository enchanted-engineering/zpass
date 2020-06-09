// constants are shared
pub mod constants;
// collection defines helpers to interact with Rust collection primitives
pub mod collection;
// crypto is wrapper around crypto constructs
pub mod crypto;
// preferences are managed through a vault and they are not exposed directly to the client.
pub mod preference;
// vault manages preferences and answers most queries.
pub mod vault;
