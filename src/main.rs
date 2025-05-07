mod config;
mod auth;
mod exec;
mod util;
mod logs;

use clap::{Arg, Command};
use config::Config;
use std::process::exit;
use util::get_user_groups;
use auth::{verify_password, prompt_password, AuthState};
use logs::{init_logger, log_info, log_warn, log_error};
use nix::unistd::{getuid, geteuid}; // NEW

fn main() {
    // Initialize logging
    init_logger();

    // Check for correct usage
    let uid = getuid().as_raw();
    let euid = geteuid().as_raw();

    if uid == 0 {
        println!("Do not run 'elev' directly as root.");
        exit(1);
    }

    if euid != 0 {
        log_error("Error: 'elev' must be installed as setuid-root.");
        exit(1);
    }

    let matches = Command::new("elev")
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
                .allow_hyphen_values(true)
                .trailing_var_arg(true)
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

    log_info(&format!(
        "elev invoked by '{}' to run '{}' as '{}'",
        current_user,
        command,
        target_user
    ));

    let config = Config::load("/etc/elev.conf").unwrap_or_else(|e| {
        log_error(&format!("Failed to load config: {}", e));
        exit(1);
    });

    let mut auth_state = AuthState::new(config.timeout, current_user.clone(), groups.clone());

    // Check permissions, including the target group for proper validation
    if !config.is_permitted(&current_user, &groups, target_user, None, command, &allowed_roles) {
        log_error(&format!("elev: Permission denied for '{}'", current_user));
        exit(1);
    }

    if !auth_state.check_timeout() {
        log_warn("Authentication timeout expired, re-enter password.");
        let password = prompt_password().unwrap_or_default();
        if !verify_password(&password, &current_user, &mut auth_state) {
            log_error("Authentication failed");
            exit(1);
        }
    }

    exec::run_command(&config, &mut auth_state, command, &args).unwrap_or_else(|e| {
        log_error(&format!("Command failed: {}", e));
        exit(1);
    });
}
