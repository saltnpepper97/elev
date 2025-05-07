use nix::unistd::{setuid, User};
use std::process::{Command, ExitStatus};
use crate::config::Config;
use crate::auth::AuthState;
use crate::logs::{log_info, log_warn, log_error};  // Import the log functions

pub fn switch_user(target_user: &str) -> Result<(), String> {
    match User::from_name(target_user).map_err(|e| e.to_string())? {
        Some(user_struct) => {
            log_info(&format!("Switching to user '{}'", target_user));  // Log the user switch action
            setuid(user_struct.uid).map_err(|e| e.to_string())
        },
        None => {
            log_error(&format!("User '{}' not found", target_user));  // Log error if user not found
            Err(format!("User '{}' not found", target_user))
        },
    }
}

pub fn run_command(config: &Config, auth_state: &mut AuthState, cmd: &str, args: &[&str]) -> Result<ExitStatus, std::io::Error> {
    let target_group = auth_state.groups.first();

    // Ensure the user has permission to run the command
    if !config.is_permitted(&auth_state.username, &auth_state.groups, "root", target_group.as_deref().map(|x| x.as_str()), cmd) {
        log_error(&format!("Permission denied for user '{}' to run command '{}'", auth_state.username, cmd));
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied"));
    }

    // Check for timeout expiry
    if !auth_state.check_timeout() {
        log_warn(&format!("Authentication timeout expired for user '{}'", auth_state.username));
        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Authentication timeout expired"));
    }

    // Set environment variables
    let mut command = Command::new(cmd);
    command.args(args);

    // Update the PATH to ensure /usr/sbin is included
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");

    // Set HOME for root user
    command.env("HOME", "/root");

    // For apt commands, set the DEBIAN_FRONTEND to non-interactive to avoid prompts
    command.env("DEBIAN_FRONTEND", "noninteractive");

    // Optionally set the APT_CONFIG variable
    command.env("APT_CONFIG", "/etc/apt/apt.conf");

    // Log the command and environment variables being executed
    log_info(&format!("Running command '{}' with arguments {:?}", cmd, args));
    log_info(&format!("Environment variables: {:?}", command.envs()));

    // Execute the command and return the result
    command.status()
}
