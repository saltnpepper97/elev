use pam::Authenticator;  // Add this import to use Authenticator
use std::fs::{read_to_string, write, create_dir_all};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use crate::logs::{log_info, log_warn, log_error, log_debug};
use crate::Config; // Import Config

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
    PathBuf::from(format!("/run/elev/auth-{}.ts", user))
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
    let _ = create_dir_all("/run/elev");
    let _ = write(path, format!("{}", now));
}

fn get_roles_for_user(username: &str) -> Vec<String> {
    match username {
        "admin" => vec!["admin".to_string(), "developer".to_string()],
        "user1" => vec!["user".to_string()],
        _ => vec![],  // Default case for unknown users
    }
}

pub fn prompt_password(config: &Config) -> Option<String> {
    if config.password_required {
        log_info("Password is required for authentication.");

        // Try to read from /dev/tty
        if let Ok(tty) = std::fs::OpenOptions::new().read(true).write(true).open("/dev/tty") {
            use std::io::{BufRead, BufReader};

            let mut tty_reader = BufReader::new(tty.try_clone().ok()?);
            let mut tty_writer = tty;

            write!(tty_writer, "Password: ").ok()?;
            tty_writer.flush().ok()?;

            let mut password = String::new();
            tty_reader.read_line(&mut password).ok()?;

            return Some(password.trim().to_string());
        } else {
            log_error("Could not open /dev/tty for password prompt.");
            eprintln!("Error: elev must be run in a terminal (not via pipe or redirect).");
            std::process::exit(1);
        }
    }

    log_info("Password not required for authentication.");
    None
}

pub fn verify_password(user: &str, auth_state: &mut AuthState, config: &Config) -> bool {
    log_debug(&format!("Starting password verification for user '{}'", user));

    if config.password_required {
        if auth_state.check_lockout() {
            log_warn(&format!("Account is temporarily locked due to too many failed login attempts for user: {}", user));
            return false;
        }

        const MAX_ATTEMPTS: u32 = 3;
        let mut attempts = 0;

        while attempts < MAX_ATTEMPTS {
            // Prompt for password
            let password = prompt_password(config);

            // Check if password is empty or canceled (user didn't enter a password)
            if let Some(password) = password {
                // Use pam::Authenticator for handling password-based authentication
                let mut auth = Authenticator::with_password("elev")
                    .expect("Failed to create PAM Authenticator");

                auth.get_handler().set_credentials(user, &password);

                if auth.authenticate().is_ok() {
                    auth_state.update_last_authenticated();
                    log_info(&format!("Successful login for user: {}", user));  // Log successful login
                    return true;
                }

                attempts += 1;
                auth_state.increment_failed_attempts();

                // Output the failure message and remaining attempts to the terminal
                eprintln!("Failed login attempt #{} for user: {}", attempts, user);
                if attempts < MAX_ATTEMPTS {
                    eprintln!("Incorrect password. You have {} more attempt(s).", MAX_ATTEMPTS - attempts);
                }
            } else {
                // User canceled or entered no password
                eprintln!("No password entered. Authentication failed.");
                break;
            }
        }

        eprintln!("User '{}' failed to authenticate after {} attempt(s).", user, MAX_ATTEMPTS);
        return false;
    }

    log_info("Password authentication skipped.");
    true // If password is not required, consider it successful
}

