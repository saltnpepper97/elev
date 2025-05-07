use pam::client::Client;
use rpassword::read_password;
use std::io::{self, Write};
use chrono::{Local, NaiveTime};
use std::time::{Duration, Instant};

pub struct AuthState {
    pub last_authenticated: Option<Instant>,
    pub timeout: Duration,
}

impl AuthState {
    pub fn new(timeout: Duration) -> Self {
        AuthState {
            last_authenticated: None,
            timeout,
        }
    }

    pub fn check_timeout(&self) -> bool {
        if let Some(last) = self.last_authenticated {
            last.elapsed() < self.timeout
        } else {
            true // No previous authentication, allow for first time
        }
    }

    pub fn update_last_authenticated(&mut self) {
        self.last_authenticated = Some(Instant::now());
    }
}

pub fn prompt_password() -> Option<String> {
    print!("Password: ");
    io::stdout().flush().ok()?;
    read_password().ok()
}

pub fn verify_password(password: &str, user: &str, auth_state: &mut AuthState) -> bool {
    // First, check if the user is within the allowed timeout window
    if !auth_state.check_timeout() {
        println!("Authentication failed: timeout expired");
        return false; // Timeout expired, deny access
    }

    let mut client = Client::with_password("login").ok().expect("Failed to create client");
    client.conversation_mut().set_credentials(user, password);
    
    if client.authenticate().is_ok() {
        auth_state.update_last_authenticated(); // Update the last authenticated time
        return true;
    }

    false // Authentication failed
}
