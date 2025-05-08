use pam_client2::{Context, Flag, ConversationHandler, ErrorCode};
use std::ffi::{CStr, CString};
use std::io::Write;
use std::time::{Instant, Duration};
use crate::logs::{log_debug, log_info, log_error};
use crate::Config;
use crate::util::{store_auth_timestamp, load_last_auth, auth_timestamp_path, get_roles_for_user};

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
    pub fn new(timeout: Duration, username: String, groups: Vec<String>, config: &Config) -> Self {
        let last_authenticated = load_last_auth(&username);
        let roles = get_roles_for_user(&username, config);
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
    
    pub fn invalidate(&mut self) {
        self.last_authenticated = None;
        let path = auth_timestamp_path(&self.username);
        if path.exists() {
            match std::fs::remove_file(&path) {
                Ok(_) => log_info(&format!("Cleared auth cache for '{}'", self.username)),
                Err(e) => log_error(&format!("Failed to clear auth cache for '{}': {}", self.username, e)),
            }
        } else {
            log_debug(&format!("No auth cache found for '{}'", self.username));
        }
        self.failed_attempts = 0;
        self.lockout_time = None;
    }
}

pub struct CustomConversation {
    pub prompt: String,
}

impl ConversationHandler for CustomConversation {
    fn prompt_echo_on(&mut self, _msg: &CStr) -> Result<CString, ErrorCode> {
        print!("{}", self.prompt);
        std::io::stdout().flush().ok();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(|_| ErrorCode::CONV_ERR)?;
        Ok(CString::new(input.trim()).unwrap())
    }
    
    fn prompt_echo_off(&mut self, _msg: &CStr) -> Result<CString, ErrorCode> {
        print!("{}", self.prompt);
        std::io::stdout().flush().ok();
        let input = rpassword::read_password().map_err(|_| ErrorCode::CONV_ERR)?;
        Ok(CString::new(input.trim()).unwrap())
    }

    fn text_info(&mut self, msg: &CStr) {
        println!("{}", msg.to_string_lossy());
    }

    fn error_msg(&mut self, msg: &CStr) {
        eprintln!("{}", msg.to_string_lossy());
    }
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
        let mut ctx = match Context::new("elev", Some(user), CustomConversation {
            prompt: format!("[ elev ] Please enter password for {}: ", user),
        }) {
            Ok(c) => c,
            Err(e) => {
                log_error(&format!("PAM init failed: {}", e));
                return false;
            }
        };

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

        if let Err(e) = ctx.acct_mgmt(Flag::NONE) {
            eprintln!("Account validation failed: {}", e);
            return false;
        }

        let _ = ctx.open_session(Flag::NONE);

        auth_state.update_last_authenticated();
        log_info(&format!("Successful login for user: {}", user));
        return true;
    }

    eprintln!("User '{}' failed to authenticate after {} attempt(s).", user, MAX_ATTEMPTS);
    false
}
