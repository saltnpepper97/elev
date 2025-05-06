use clap::{Arg, Command};
use nix::unistd::{setuid, User};
use pam::client::Client;
use rpassword::read_password;
use std::io::{self, Write};
use std::process::{exit, Command as ProcessCommand, ExitStatus};

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
    let target_user = matches.get_one::<String>("user").map(|s| s.as_str()).unwrap_or("root");

    // Step 1: Load and check config
    let config = Config::load("/etc/nexus.conf").expect("Failed to load config");

    let current_user = whoami::username();
    let groups = get_user_groups(&current_user);

    let full_cmd = command.to_string();

    if !config.is_permitted(&current_user, &groups, target_user, &full_cmd) {
        eprintln!("Nexus: Permission denied for '{}'", current_user);
        exit(1);
    }

    // Step 2: Prompt for password
    print!("Password: ");
    io::stdout().flush().unwrap();
    let password = read_password().expect("failed to read password");

    // Step 3: Authenticate with PAM
    if !verify_password(&password) {
        println!("Authentication failed");
        exit(1);
    }

    println!("Access granted.");
    println!("Running command: {}", command);

    // Step 4: Set UID
    if target_user != current_user {
        match User::from_name(target_user).unwrap_or(None) {
            Some(user_struct) => {
                if let Err(e) = setuid(user_struct.uid) {
                    eprintln!("Failed to switch to user '{}': {}", target_user, e);
                    exit(1);
                }
                println!("Switched to user: {}", target_user);
            }
            None => {
                eprintln!("User '{}' not found", target_user);
                exit(1);
            }
        }
    }

    // Step 5: Execute command
    match run_command(command, &args) {
        Ok(status) => {
            if !status.success() {
                println!("Command failed with status {}", status);
                exit(1);
            }
        }
        Err(e) => {
            println!("Error executing command: {}", e);
            exit(1);
        }
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
            eprintln!("PAM: Authentication failed: {}", e);
            false
        }
    }
}

fn run_command(cmd: &str, args: &[&str]) -> Result<ExitStatus, std::io::Error> {
    ProcessCommand::new(cmd).args(args).status()
}

fn get_user_groups(user: &str) -> Vec<String> {
    let output = std::process::Command::new("id")
        .arg("-Gn")
        .arg(user)
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let group_str = String::from_utf8_lossy(&out.stdout);
            group_str.split_whitespace().map(|s| s.to_string()).collect()
        }
        _ => vec![],
    }
}
