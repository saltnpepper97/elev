use nix::unistd::{setuid, User};
use std::process::{Command, ExitStatus};

pub fn switch_user(target_user: &str) -> Result<(), String> {
    match User::from_name(target_user).map_err(|e| e.to_string())? {
        Some(user_struct) => setuid(user_struct.uid).map_err(|e| e.to_string()),
        None => Err(format!("User '{}' not found", target_user)),
    }
}

pub fn run_command(cmd: &str, args: &[&str]) -> Result<ExitStatus, std::io::Error> {
    Command::new(cmd).args(args).status()
}
