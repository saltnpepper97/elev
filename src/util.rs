use std::fs::{read_to_string, create_dir_all, write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use nix::unistd::{setuid, User};
use std::process::{Command, ExitStatus};
use crate::logs::{log_info, log_warn, log_error};
use crate::{Config, AuthState};

/// Retrieves the groups of a user by calling the `id` command.
pub fn get_user_groups(user: &str) -> Vec<String> {
    match std::process::Command::new("id").arg("-Gn").arg(user).output() {
        Ok(out) if out.status.success() => {
            let group_str = String::from_utf8_lossy(&out.stdout);
            group_str.split_whitespace().map(|s| s.to_string()).collect()
        }
        _ => Vec::new(),
    }
}

/// Returns the file path for storing the authentication timestamp for the given user.
pub fn auth_timestamp_path(user: &str) -> PathBuf {
    Path::new("/run/elev").join(format!("auth-{}.ts", user))
}

/// Loads the last authentication timestamp for the user.
pub fn load_last_auth(user: &str) -> Option<Instant> {
    let path = auth_timestamp_path(user);
    read_to_string(path)
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(|secs| UNIX_EPOCH + Duration::from_secs(secs))
        .and_then(|then| SystemTime::now().duration_since(then).ok())
        .map(|elapsed| Instant::now() - elapsed)
}

/// Stores the current timestamp for the user authentication.
pub fn store_auth_timestamp(user: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let path = auth_timestamp_path(user);
    if let Err(e) = create_dir_all("/run/elev") {
        log_error(&format!("Failed to create directory: {}", e));
        return;
    }
    if let Err(e) = write(path, now.to_string()) {
        log_error(&format!("Failed to write timestamp: {}", e));
    }
}

/// Switches the current user context to the specified target user.
pub fn switch_user(target_user: &str) -> Result<(), String> {
    match User::from_name(target_user).map_err(|e| e.to_string())? {
        Some(user_struct) => {
            log_info(&format!("Switching to user '{}'", target_user));
            setuid(user_struct.uid).map_err(|e| e.to_string())
        }
        None => {
            log_error(&format!("User '{}' not found", target_user));
            Err(format!("User '{}' not found", target_user))
        }
    }
}

/// Executes a command with the provided arguments and target user.
pub fn run_command(
    cmd: &str,
    args: &[&str],
    target_user: &str,
    config: &Config,
    auth_state: &mut AuthState,
) -> Result<ExitStatus, std::io::Error> {
    // Ensure user has permission to run the command
    if !config.is_permitted(
        &auth_state.username,
        &auth_state.groups,
        target_user,
        cmd,
        &auth_state.roles,
    ) {
        log_error(&format!(
            "Permission denied for user '{}' to run command '{}'",
            auth_state.username, cmd
        ));
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied",
        ));
    }

    // Handle timeout check
    if !auth_state.check_timeout() {
        log_warn(&format!(
            "Authentication timeout expired for user '{}'", auth_state.username
        ));
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Authentication timeout expired",
        ));
    }

    // Switch user before running the command
    switch_user(target_user).map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

    // Now execute the command with all arguments
    let mut command = Command::new(cmd);
    command.args(args);
    command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");

    log_info(&format!("Running command: '{} {}'", cmd, args.join(" ")));

    command.status()
}

pub fn get_roles_for_user(username: &str, config: &Config) -> Vec<String> {
    config.roles.iter()
        .filter_map(|(role, (users, _time_range))| {
            if users.contains(&username.to_string()) {
                Some(role.clone())
            } else {
                None
            }
        })
        .collect()
}

