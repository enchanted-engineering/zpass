use super::handler;
use super::parser::{parse, Command, Operation, Resource};
use std::env;

/// Reads a the arguments that were used to start the app and executes them as a command.
pub fn start() {
    let args: Vec<String> = env::args().collect();
    match parse(&args[1..]) {
        Err(msg) => println!("Failed to parse the command:\n{}", msg),
        Ok(cmd) => {
            if let Err(msg) = execute_command(cmd) {
                println!("Failed to execute the command:\n{}", msg)
            }
        }
    }
}

/// Calls the handler associated with the Command.
fn execute_command(cmd: Command) -> Result<(), String> {
    match cmd {
        Command {
            op: Operation::Add,
            on: Resource::Vault,
            ..
        } => handler::add_vault(&cmd.params).map_err(|e| format!("{}", e)),
        Command {
            op: Operation::Add,
            on: Resource::Password,
            ..
        } => handler::add_password(&cmd.params).map_err(|e| format!("{}", e)),
        Command {
            op: Operation::Get,
            on: Resource::Password,
            ..
        } => handler::get_password(&cmd.params).map_err(|e| format!("{}", e)),
        _ => Err("Unexpected command".to_owned()),
    }
}
