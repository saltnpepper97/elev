// auth.rs

use pam_client2::{Context, Flag};
use pam_client2::conv_cli::Conversation;
use std::fs::{read_to_string, write, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::logs::{log_info, log_warn, log_error, log_debug};
use crate::Config;

pub struct AuthState {
    pub last_authenticated: Option<Instant>,
    pub timeout: Duration,
    pub username: String,
    pub groups: Vec<String>,
    pub failed_attempts: u32,
    pub lockout_time: Option<Instant>,
    pub roles: Vec<String>,
}

impl AuthState {
    /* … your existing new(), check_timeout(), etc. … */
}

fn auth_timestamp_path(user: &str) -> PathBuf { /* … */ }
fn load_last_auth(user: &str) -> Option<Instant> { /* … */ }
fn store_auth_timestamp(user: &str) { /* … */ }
fn get_roles_for_user(username: &str) -> Vec<String> { /* … */ }

/// Reads one line from /dev/tty with a “Password: ” prompt.
pub fn prompt_password(config: &Config) -> Option<String> {
    if config.password_required {
        log_info("Password is required for authentication.");
        if let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
            use std::io::{BufRead, BufReader};
            let mut reader = BufReader::new(tty.try_clone().ok()?);
            let mut writer = tty;
            write!(writer, "Password: ").ok()?;
            writer.flush().ok()?;
            let mut pw = String::new();
            reader.read_line(&mut pw).ok()?;
            return Some(pw.trim_end().to_string());
        }
        log_error("Could not open /dev/tty for password prompt.");
        eprintln!("Error: elev must be run in a terminal.");
        std::process::exit(1);
    }
    None
}

/// Returns true if auth succeeded (and updates state), false otherwise.
pub fn verify_password(user: &str, auth_state: &mut AuthState, config: &Config) -> bool {
    log_debug(&format!("Starting password verification for '{}'", user));

    if !config.password_required {
        log_info("Password auth skipped.");
        return true;
    }
    if auth_state.check_lockout() {
        eprintln!("Account temporarily locked due to too many failures.");
        return false;
    }

    const MAX_ATTEMPTS: u32 = 3;
    let mut attempts = 0;

    while attempts < MAX_ATTEMPTS {
        let password = match prompt_password(config) {
            Some(p) if !p.is_empty() => p,
            _ => {
                eprintln!("No password entered. Aborting.");
                return false;
            }
        };

        // Create a PAM Context with CLI conversation
        let mut ctx = match Context::new(
            "elev",                      // matches /etc/pam.d/elev
            Some(user.to_string()),      // the target username
            Conversation::new(),         // uses /dev/tty under the hood
        ) {
            Ok(c) => c,
            Err(e) => {
                log_error(&format!("PAM init failed: {}", e));
                return false;
            }
        };

        // Authenticate (this prompts exactly once via Conversation)
        if let Err(e) = ctx.authenticate(Flag::NONE) {
            attempts += 1;
            auth_state.increment_failed_attempts();
            eprintln!("Failed login attempt #{}", attempts);
            if attempts < MAX_ATTEMPTS {
                eprintln!("Incorrect password. {} attempt(s) left.", MAX_ATTEMPTS - attempts);
            }
            continue;
        }

        // Optionally check account validity
        if let Err(e) = ctx.acct_mgmt(Flag::NONE) {
            eprintln!("Account check failed: {}", e);
            return false;
        }

        // Success
        auth_state.update_last_authenticated();
        log_info(&format!("Successful login for user: {}", user));
        return true;
    }

    eprintln!("User '{}' failed to authenticate after {} attempts.", user, MAX_ATTEMPTS);
    false
}
