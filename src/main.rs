mod config;
mod auth;
mod exec;
mod util;

use clap::{Arg, ArgAction, Command}; // Assuming you're using clap
use config::Config;
use std::process::exit;
use util::get_user_groups;

fn main() {
    let matches = Command::new("nexus")
        .arg(
            Arg::new("user")
                .short('u')
                .long("user")
                .help("Target user to run command as")
                .takes_value(true),
        )
        .arg(
            Arg::new("command")
                .required(true)
                .multiple_values(true)
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

    // Use instance method, not config::is_permitted
    if !config.is_permitted(&current_user, &groups, target_user, command) {
        eprintln!("Nexus: Permission denied for '{}'", current_user);
        exit(1);
    }

    let password = auth::prompt_password().unwrap_or_default();
    if !auth::verify_password(&password, &current_user) {
        eprintln!("Authentication failed");
        exit(1);
    }

    if target_user != current_user {
        exec::switch_user(target_user).unwrap_or_else(|e| {
            eprintln!("Failed to switch user: {}", e);
            exit(1);
        });
    }

    exec::run_command(command, &args).unwrap_or_else(|e| {
        eprintln!("Command failed: {}", e);
        exit(1);
    });
}
