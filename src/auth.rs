use pam::client::Client;
use rpassword::read_password;
use std::fs::{read_to_string, write, create_dir_all};
use std::io::{self, Write};
use std::path::PathBuf;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub struct AuthState {
    pub last_authenticated: Option<Instant>,
    pub timeout: Duration,
    pub username: String,
    pub groups: Vec<String>,
}

impl AuthState {
    pub fn new(timeout: Duration, username: String, groups: Vec<String>) -> Self {
        let last_authenticated = load_last_auth(&username);
        AuthState {
            last_authenticated,
            timeout,
            username,
            groups,
        }
    }

    pub fn check_timeout(&self) -> bool {
        if let Some(last) = self.last_authenticated {
            let elapsed = last.elapsed();
            println!("Time since last authentication: {:?}", elapsed); // Debug line
            elapsed < self.timeout
        } else {
            true // No previous authentication, allow for first time
        }
    }

    pub fn update_last_authenticated(&mut self) {
        self.last_authenticated = Some(Instant::now());
        store_auth_timestamp(&self.username);
        println!("Updated last_authenticated: {:?}", self.last_authenticated); // Debug line
    }
}

fn auth_timestamp_path(user: &str) -> PathBuf {
    PathBuf::from(format!("/run/nexus/auth-{}.ts", user))
}

fn load_last_auth(user: &str) -> Option<Instant> {
    let path = auth_timestamp_path(user);
    println!("Loading auth timestamp from: {}", path.display()); // Debug line
    if let Ok(content) = read_to_string(path) {
        println!("Read timestamp file content: {}", content); // Debug line
        if let Ok(epoch_secs) = content.trim().parse::<u64>() {
            let then = UNIX_EPOCH + Duration::from_secs(epoch_secs);
            println!("Loaded timestamp: {:?}", then); // Debug line
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
    let _ = create_dir_all("/run/nexus"); // Ensure directory exists
    let _ = write(path, format!("{}", now));
    println!("Stored timestamp at: {}", path.display()); // Debug line
}

pub fn prompt_password() -> Option<String> {
    print!("Password: ");
    io::stdout().flush().ok()?;
    read_password().ok()
}

pub fn verify_password(password: &str, user: &str, auth_state: &mut AuthState) -> bool {
    // First, check if the user is within the allowed timeout window
    if !auth_state.check_timeout() {
        println!("Authentication failed: timeout expired"); // Debug line
        return false;
    }

    let mut client = Client::with_password("login").ok().expect("Failed to create client");
    client.conversation_mut().set_credentials(user, password);

    if client.authenticate().is_ok() {
        println!("Password correct, updating last authentication time."); // Debug line
        auth_state.update_last_authenticated(); // Update + persist timestamp
        return true;
    }

    println!("Password incorrect."); // Debug line
    false // Authentication failed
}

