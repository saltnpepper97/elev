// src/auth.rs

use pam_client2::{Context, Flag};
use pam_client2::conv_cli::Conversation;
use std::fs::{read_to_string, write, create_dir_all};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::logs::{log_debug, log_error, log_info};
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
    pub fn new(timeout: Duration, username: String, groups: Vec<String>) -> Self {
        let last_authenticated = load_last_auth(&username);
        let roles = get_roles_for_user(&username);
        log_debug(&format!(
            "Initializing AuthState for user '{}'. Timeout: {:?}, Groups: {:?}, Roles: {:?}",
            username, timeout, groups, roles
        ));
        AuthState {
            last_authenticated,
            timeout,
            username,
            groups,
            roles,
            failed_attempts: 0,
            lockout_time: None,
        }
    }

    pub fn check_timeout(&self) -> bool {
        self.last_authenticated
            .map(|t| t.elapsed() < self.timeout)
            .unwrap_or(false)
    }

    pub fn update_last_authenticated(&mut self) {
        self.last_authenticated = Some(Instant::now());
        store_auth_timestamp(&self.username);
        self.failed_attempts = 0;
    }

    pub fn check_lockout(&self) -> bool {
        self.lockout_time
            .map(|t| t.elapsed() < Duration::from_secs(900))
            .unwrap_or(false)
    }

    pub fn increment_failed_attempts(&mut self) {
        self.failed_attempts += 1;
        if self.failed_attempts >= 5 {
            self.lockout_time = Some(Instant::now());
        }
    }
}

fn auth_timestamp_path(user: &str) -> PathBuf {
    PathBuf::from(format!("/run/elev/auth-{}.ts", user))
}

fn load_last_auth(user: &str) -> Option<Instant> {
    let path = auth_timestamp_path(user);
    let content = read_to_string(&path).ok()?;
    let secs = content.trim().parse::<u64>().ok()?;
    let then = UNIX_EPOCH + Duration::from_secs(secs);
    let elapsed = SystemTime::now().duration_since(then).ok()?;
    Some(Instant::now() - elapsed)
}

fn store_auth_timestamp(user: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let path = auth_timestamp_path(user);
    if let Err(e) = create_dir_all("/run/elev") {
        log_error(&format!("Failed to create /run/elev: {}", e));
        return;
    }
    if let Err(e) = write(path, now.to_string()) {
        log_error(&format!("Failed to write auth timestamp: {}", e));
    }
}

fn get_roles_for_user(username: &str) -> Vec<String> {
    // TODO: replace with real lookup
    match username {
        "admin" => vec!["admin".into(), "developer".into()],
        "user1" => vec!["user".into()],
        _ => vec![],
    }
}

/// Perform PAM-based password verification, applying timeout and lockout logic.
pub fn verify_password(user: &str, auth_state: &mut AuthState, config: &Config) -> bool {
    log_debug(&format!("Starting password verification for user '{}'", user));

    if !config.password_required {
        log_info("Password authentication skipped.");
        return true;
    }
    if auth_state.check_lockout() {
        eprintln!("Account temporarily locked due to too many failures.");
        return false;
    }

    const MAX_ATTEMPTS: u32 = 3;
    let mut attempts = 0;

    while attempts < MAX_ATTEMPTS {
        // Initialize a new PAM context (uses /etc/pam.d/elev)
        let mut ctx = match Context::new("elev", Some(user), Conversation::new()) {
            Ok(c) => c,
            Err(e) => {
                log_error(&format!("PAM init failed: {}", e));
                return false;
            }
        };

        // Authenticate (prompts for password via Conversation)
        if let Err(e) = ctx.authenticate(Flag::NONE) {
            log_error(&format!("PAM authentication failed: {}", e));
            attempts += 1;
            auth_state.increment_failed_attempts();
            eprintln!("Failed login attempt #{}", attempts);
            if attempts < MAX_ATTEMPTS {
                eprintln!("Incorrect password. {} attempt(s) left.", MAX_ATTEMPTS - attempts);
            }
            continue;
        }

        // Account management checks (e.g., expired, locked)
        if let Err(e) = ctx.acct_mgmt(Flag::NONE) {
            eprintln!("Account validation failed: {}", e);
            return false;
        }

        // Optional: open a session
        let _ = ctx.open_session(Flag::NONE);

        // Success
        auth_state.update_last_authenticated();
        log_info(&format!("Successful login for user: {}", user));
    }

    eprintln!("User '{}' failed to authenticate after {} attempt(s).", user, MAX_ATTEMPTS);
    false
}

