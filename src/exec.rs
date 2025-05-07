use nix::unistd::{setuid, User, getgroups}; // Add this to get groups for a user
use std::process::{Command, ExitStatus};
use crate::config::Config;
use crate::auth::AuthState;
use crate::logs::{log_info, log_warn, log_error};

pub fn switch_user(target_user: &str) -> Result<(), String> {
    match User::from_name(target_user).map_err(|e| e.to_string())? {
        Some(user_struct) => {
            log_info(&format!("Switching to user '{}'", target_user));  // Log the user switch action
            setuid(user_struct.uid).map_err(|e| e.to_string())  // Switch user
        },
        None => {
            log_error(&format!("User '{}' not found", target_user));  // Log error if user not found
            Err(format!("User '{}' not found", target_user))
        },
    }
}

pub fn check_group_permission(user: &str, required_group: &str) -> bool {
    if let Ok(groups) = getgroups() {
        for group in groups {
            let group_name = match group.to_group_name() {
                Ok(name) => name,
                Err(_) => continue, // Skip if group name retrieval fails
            };
            if group_name == required_group {
                return true; // User is in the required group
            }
        }
    }
    false // User is not in the required group
}

pub fn run_command(
    config: &Config,
    auth_state: &mut AuthState,
    target_user: &str,
    cmd: &str,
    args: &[&str],
    required_group: &str, // Adding the group check
) -> Result<ExitStatus, std::io::Error> {

    // Handle timeout check
    if !auth_state.check_timeout() {
        log_warn(&format!(
            "Authentication timeout expired for user '{}'",
            auth_state.username
        ));
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Authentication timeout expired",
        ));
    }

    // Check if the user is permitted based on their group
    if !check_group_permission(auth_state.username.as_str(), required_group) {
        log_warn(&format!(
            "User '{}' does not have permission to execute commands as '{}'",
            auth_state.username, target_user
        ));
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "User is not authorized to execute this command",
        ));
    }

    // Switch user before running the command
    if let Err(e) = switch_user(target_user) {
        log_error(&e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "User switch failed",
        ));
    }

    // Now execute the command with all arguments
    let mut command = Command::new(cmd);
    command.args(args);  // Pass the arguments here

    // Setup environment if necessary (e.g., for root commands)
    let path = "/usr/bin:/bin:/usr/sbin:/sbin";
    command.env("PATH", path);

    // Log command and environment for debugging
    log_info(&format!("Running command: '{} {}'", cmd, args.join(" ")));

    // Execute the command
    command.status()
}
