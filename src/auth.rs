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
    pub fn new(timeout: Duration, username: String, groups: Vec<String>) -> Self {
        let last_authenticated = load_last_auth(&username);
        let roles = get_roles_for_user(&username);
        log_debug(&format!(
            "Initializing AuthState for user '{}'. Timeout: {:?}, Groups: {:?}, Roles: {:?}",
            username, timeout, groups, roles
        ));
        AuthState { last_authenticated, timeout, username, groups, roles, failed_attempts: 0, lockout_time: None }
    }

    pub fn check_timeout(&self) -> bool {
        self.last_authenticated
            .map(|last| last.elapsed() < self.timeout)
            .unwrap_or(false)
    }

    pub fn update_last_authenticated(&mut self) {
        self.last_authenticated = Some(Instant::now());
        store_auth_timestamp(&self.username);
        self.failed_attempts = 0;
    }

    pub fn check_lockout(&self) -> bool {
        if let Some(lock_time) = self.lockout_time {
            lock_time.elapsed() < Duration::from_secs(900)
        } else {
            false
        }
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
    let content = read_to_string(path).ok()?;
    let secs = content.trim().parse::<u64>().ok()?;
    let then = UNIX_EPOCH + Duration::from_secs(secs);
    let elapsed = SystemTime::now().duration_since(then).ok()?;
    Some(Instant::now() - elapsed)
}

fn store_auth_timestamp(user: &str) {
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    let path = auth_timestamp_path(user);
    let _ = create_dir_all("/run/elev");
    let _ = write(path, now.to_string());
}

fn get_roles_for_user(username: &str) -> Vec<String> {
    match username {
        "admin" => vec!["admin".into(), "developer".into()],
        "user1" => vec!["user".into()],
        _ => vec![],
    }
}

pub fn prompt_password(config: &Config) -> Option<String> {
    if config.password_required {
        log_info("Password is required for authentication.");
        let tty = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty")
            .unwrap_or_else(|_| { eprintln!("Error: elev must be run in a terminal."); std::process::exit(1) });
        use std::io::{BufRead, BufReader};
        let mut reader = BufReader::new(tty.try_clone().ok()?);
        let mut writer = tty;
        write!(writer, "Password: ").ok()?;
        writer.flush().ok()?;
        let mut pw = String::new();
        reader.read_line(&mut pw).ok()?;
        return Some(pw.trim_end().to_string());
    }
    None
}

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
        let password = match prompt_password(config) {
            Some(p) if !p.is_empty() => p,
            _ => { eprintln!("No password entered. Aborting."); return false; }
        };

        // Build PAM context using cli conversation (handles echo-off, TTY, etc.)
        let mut ctx = match Context::new(
            "elev",                   // PAM service name → /etc/pam.d/elev
            Some(user),               // pass &str here, not String
            Conversation::new(),      // the TTY-based conversation handler
        ) {
            Ok(c) => c,
            Err(e) => {
                log_error(&format!("PAM init failed: {}", e));
                return false;
            }
        };

        // Supply the password to PAM and authenticate
        ctx.get_handler().set_password(&password);
        if let Err(e) = ctx.authenticate(Flag::NONE) {
            attempts += 1;
            auth_state.increment_failed_attempts();
            eprintln!("Failed login attempt #{}", attempts);
            if attempts < MAX_ATTEMPTS {
                eprintln!("Incorrect password. {} attempt(s) left.", MAX_ATTEMPTS - attempts);
            }
            continue;
        }

        // Post-auth account checks (e.g., expired, locked)
        if let Err(e) = ctx.acct_mgmt(Flag::NONE) {
            eprintln!("Account validation failed: {}", e);
            return false;
        }

        // Success
        auth_state.update_last_authenticated();
        log_info(&format!("Successful login for user: {}", user));
        return true;
    }

    eprintln!("User '{}' failed to authenticate after {} attempt(s).", user, MAX_ATTEMPTS);
    false
}

