mod config;
mod auth;
mod exec;
mod util;

use clap::{Arg, Command};
use config::Config;
use std::process::exit;
use util::get_user_groups;
use auth::{verify_password, prompt_password, AuthState};

fn main() {
    let matches = Command::new("nexus")
        .arg(
            Arg::new("user")
                .short('u')
                .long("user")
                .help("Target user to run command as")
                .value_name("USER")
                .value_parser(clap::value_parser!(String))
                .default_value("root"),
        )
        .arg(
            Arg::new("command")
                .required(true)
                .num_args(1..)
                .value_name("COMMAND")
                .help("Command to execute"),
        )
        .get_matches();

    let target_user = matches.get_one::<String>("user").map(String::as_str).unwrap_or("root");

    let command_and_args = matches
        .get_many::<String>("command")
        .expect("Command is required")
        .collect::<Vec<_>>();

    let command = command_and_args[0].as_str();
    let args: Vec<&str> = command_and_args[1..].iter().map(|s| s.as_str()).collect();

    let current_user = whoami::username();
    let groups = get_user_groups(&current_user);

    // Load the config
    let config = Config::load("/etc/nexus.conf").unwrap_or_else(|e| {
        eprintln!("Failed to load config: {}", e);
        exit(1);
    });

    // Initialize authentication state
    let mut auth_state = AuthState::new(config.timeout, current_user.clone(), groups.clone());

    // Use instance method for checking permission
    if !config.is_permitted(&current_user, &groups, target_user, command) {
        eprintln!("Nexus: Permission denied for '{}'", current_user);
        exit(1);
    }

    // Prompt for password and verify if timeout is reached
    if !auth_state.check_timeout() {
        let password = prompt_password().unwrap_or_default();
        if !verify_password(&password, &current_user, &mut auth_state) {
            eprintln!("Authentication failed");
            exit(1);
        }
    }
    
    // Switch to target user if needed
    if target_user != current_user {
        exec::switch_user(target_user).unwrap_or_else(|e| {
            eprintln!("Failed to switch user: {}", e);
            exit(1);
        });
    }

    // Run the command with timeout and permission checks
    exec::run_command(&config, &mut auth_state, command, &args).unwrap_or_else(|e| {
        eprintln!("Command failed: {}", e);
        exit(1);
    });
}
