//! # Parser
//! - add vault -n example
//! - add vault --name=example
//! - add password -d example.com -u example -l 40
//! - add password --domain=example.com --username=example --length=40
//! - get password -d example.com
//! - get password -d example.com -u example
//! - get password -d example.com -u example -l 40
//! - get password --domain=example.com --username=example --length=40

use std::collections::HashMap;

/// Users specify a command: <Operation> <Resource> [<Param>]
/// where param is either: `-key vaule` or `--key=value`
pub struct Command {
    pub op: Operation,
    pub on: Resource,
    pub params: HashMap<ParamName, String>,
}

/// The action we want to perform on a resource.
pub enum Operation {
    Add,
    Get,
}

/// The objects are can interact with.
pub enum Resource {
    Password,
    Vault,
}

/// Options are specified as `-key vaule` or `--key=value`
#[derive(Hash, Eq, PartialEq, Debug)]
pub enum ParamName {
    VaultName,
    DomainName,
    UserName,
    Length,
}

/// Parses a slice of strings into a Command
pub fn parse(input: &[String]) -> Result<Command, String> {
    let input = input.join(" ");
    command(&input)
}

use pom::parser::Parser;
use pom::parser::*;

fn param_long<'a>(name: &'a str) -> Parser<'a, u8, String> {
    let key = seq(b"--") + seq(name.as_bytes()) + sym(b'=');
    let value = none_of(b" ").repeat(1..).convert(|s| String::from_utf8(s));
    key * value
}

fn param_short<'a>(name: &'a str) -> Parser<'a, u8, String> {
    let key = seq(b"-") + seq(name.as_bytes());
    let space = sym(b' ').repeat(1..);
    let value = none_of(b" ").repeat(1..).convert(|s| String::from_utf8(s));
    key * space * value
}

fn space<'a>() -> Parser<'a, u8, ()> {
    sym(b' ').repeat(0..).discard()
}

fn param<'a>() -> Parser<'a, u8, (ParamName, String)> {
    space() * {
        param_long("name").map(|v| (ParamName::VaultName, v))
            | param_long("domain").map(|v| (ParamName::DomainName, v))
            | param_long("username").map(|v| (ParamName::UserName, v))
            | param_long("length").map(|v| (ParamName::Length, v))
            | param_short("n").map(|v| (ParamName::VaultName, v))
            | param_short("d").map(|v| (ParamName::DomainName, v))
            | param_short("u").map(|v| (ParamName::UserName, v))
            | param_short("l").map(|v| (ParamName::Length, v))
    } - space()
}

fn operation<'a>() -> Parser<'a, u8, Operation> {
    let op = seq(b"add").map(|_| Operation::Add) | seq(b"get").map(|_| Operation::Get);
    space() * op - space()
}

fn resource<'a>() -> Parser<'a, u8, Resource> {
    let re = seq(b"password").map(|_| Resource::Password) | seq(b"vault").map(|_| Resource::Vault);
    space() * re - space()
}

fn params<'a>() -> Parser<'a, u8, Vec<(ParamName, String)>> {
    param().repeat(0..)
}

fn command(input: &str) -> Result<Command, String> {
    let ((op, on), ps) = { operation() + resource() + params() }
        .parse(input.as_bytes())
        .unwrap();
    let mut params = HashMap::new();
    for (k, v) in ps {
        params.insert(k, v);
    }

    Ok(Command { op, on, params })
}
