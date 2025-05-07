use nix::unistd::{setuid, User};
use std::process::{Command, ExitStatus};
use crate::config::Config;
use crate::auth::AuthState; 

pub fn switch_user(target_user: &str) -> Result<(), String> {
    match User::from_name(target_user).map_err(|e| e.to_string())? {
        Some(user_struct) => setuid(user_struct.uid).map_err(|e| e.to_string()),
        None => Err(format!("User '{}' not found", target_user)),
    }
}

pub fn run_command(config: &Config, auth_state: &mut AuthState, cmd: &str, args: &[&str]) -> Result<ExitStatus, std::io::Error> {
    // Ensure the user has permission to run the command
    if !config.is_permitted(&auth_state.username, &auth_state.groups, "root", cmd) {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, "Permission denied"));
    }

    // Check for timeout expiry
    if !auth_state.check_timeout() {
        return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "Authentication timeout expired"));
    }
    
    Command::new(cmd).args(args).status()
}
