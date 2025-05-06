use clap::{Command, Arg};
use nix::unistd::{setuid, Uid, User};
use pam::client::Client;
use rpassword::read_password;
use std::process::{Command as ProcessCommand, exit, ExitStatus};
use std::io::{self, Write};

mod config;

use config::Config;

fn main() {
    let matches = Command::new("Nexus")
        .version("1.0")
        .author("Dustin")
        .about("A Rusty spin on doas and sudo")
        .arg(Arg::new("command")
             .help("The command and arguments to run")
             .required(true)
             .num_args(1..)
             .value_name("COMMAND")
             .last(true))
        .arg(Arg::new("user")
             .short('u')
             .long("user")
             .value_name("USER")
             .help("Run as a different user")
             .num_args(1))
        .get_matches();

    let command_and_args = matches
        .get_many::<String>("command")
        .expect("COMMAND is required")
        .collect::<Vec<_>>();
    let command = command_and_args[0];
    let args: Vec<&str> = command_and_args[1..].iter().map(|s| s.as_str()).collect();
    let user = matches.get_one::<String>("user").map(|u| u.as_str());

    // Step 1: Prompt for password
    print!("Password: ");
    io::stdout().flush().unwrap();

    let password = read_password().expect("failed to read password");

    // Step 2: Authentication
    if verify_password(&password) {
        println!("Access granted.");
        println!("Running command: {}", command);


        // Step 3: Handle Privileges
        match user {
            Some(username) => {
                match User::from_name(username).unwrap_or(None) {
                    Some(user_struct) => {
                        if let Err(e) = setuid(user_struct.uid) {
                            eprintln!("Failed to switch to user '{}': {}", username, e);
                            exit(1);
                        }
                        println!("Switched to user: {}", username)
                    }
                    None => {
                        eprintln!("User {} not found", username);
                        exit(1);
                    }
                }
            }
            None => {
                if let Err(e) = setuid(Uid::from_raw(0)) {
                    eprintln!("Privileges escalation to root failed: {}", e);
                    exit(1);
                }
                println!("Privileges escalated to root.");
            }
        }

        // Check config before running command
        let config = Config::load("/etc/nexus.conf").expect("Failed to load config");



        // Step 4: Execute the command
        match run_command(command, &args) {
            Ok(status) => {
                if !status.success() {
                    println!("Command failed with status {}", status);
                    exit(1);
                }
            },
            Err(e) => {
                println!("Error executing command: {}", e);
                exit(1);
            }
        }
    } else {
        println!("Authentication failed");
    }
}

fn verify_password(password: &str) -> bool {
    let mut client = Client::with_password("login").expect("Failed to create PAM client");

    let username = whoami::username();

    client.conversation_mut().set_credentials(&username, password);

    match client.authenticate() {
        Ok(_) => {
            println!("PAM: Authentication complete for user {}", username);
            true
        }
        Err(e) => {
            eprintln!("PAM: Authentication failed {}", e);
            false
        }
    }
}

fn run_command(cmd: &str, args: &[&str]) -> Result<ExitStatus, std::io::Error> {
    ProcessCommand::new(cmd)
        .args(args)
        .status()
}
