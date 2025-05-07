use pam::client::Client;
use rpassword::read_password;
use std::fs::{read_to_string, write, create_dir_all};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::logs::{log_info, log_warn, log_error};  // Add the log imports

pub struct AuthState {
    pub last_authenticated: Option<Instant>,
    pub timeout: Duration,
    pub username: String,
    pub groups: Vec<String>,
    pub failed_attempts: u32,
    pub lockout_time: Option<Instant>,
}

impl AuthState {
    pub fn new(timeout: Duration, username: String, groups: Vec<String>) -> Self {
        let last_authenticated = load_last_auth(&username);
        AuthState {
            last_authenticated,
            timeout,
            username,
            groups,
            failed_attempts: 0,
            lockout_time: None,
        }
    }

    pub fn check_timeout(&self) -> bool {
        if let Some(last) = self.last_authenticated {
            let elapsed = last.elapsed();
            elapsed < self.timeout
        } else {
            false // No previous record found. (require authentication)
        }
    }

    pub fn update_last_authenticated(&mut self) {
        self.last_authenticated = Some(Instant::now());
        store_auth_timestamp(&self.username);
        self.failed_attempts = 0; // Reset failed attempts on success
    }

    pub fn check_lockout(&self) -> bool {
        if let Some(lockout_time) = self.lockout_time {
            let lockout_duration = Duration::from_secs(900); // Lockout for 15 minutes
            if lockout_time.elapsed() < lockout_duration {
                return true; // Account is locked
            }
        }
        false
    }

    pub fn increment_failed_attempts(&mut self) {
        self.failed_attempts += 1;
        if self.failed_attempts >= 5 { // Lock after 5 failed attempts
            self.lockout_time = Some(Instant::now());
        }
    }
}

fn auth_timestamp_path(user: &str) -> PathBuf {
    PathBuf::from(format!("/run/nexus/auth-{}.ts", user))
}

fn load_last_auth(user: &str) -> Option<Instant> {
    let path = auth_timestamp_path(user);
    if let Ok(content) = read_to_string(path) {
        if let Ok(epoch_secs) = content.trim().parse::<u64>() {
            let then = UNIX_EPOCH + Duration::from_secs(epoch_secs);
            if let Ok(duration_since_then) = SystemTime::now().duration_since(then) {
                return Some(Instant::now() - duration_since_then);
            }
        }
    }
    None
}

fn store_auth_timestamp(user: &str) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let path = auth_timestamp_path(user);
    let _ = create_dir_all("/run/nexus");
    let _ = write(path, format!("{}", now));
}

pub fn prompt_password() -> Option<String> {
    print!("Password: ");
    io::stdout().flush().ok()?;
    read_password().ok()
}

pub fn verify_password(password: &str, user: &str, auth_state: &mut AuthState) -> bool {
    if auth_state.check_lockout() {
        log_warn(&format!("Account is temporarily locked due to too many failed login attempts for user: {}", user));
        return false;
    }

    let mut client = Client::with_password("nexus").ok().expect("Failed to create client");
    client.conversation_mut().set_credentials(user, password);

    if client.authenticate().is_ok() {
        auth_state.update_last_authenticated();
        log_info(&format!("Successful login for user: {}", user));  // Log successful login
        return true;
    }

    auth_state.increment_failed_attempts();
    log_error(&format!("Failed login attempt for user: {}", user));  // Log failed login attempt
    false
}
