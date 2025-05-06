use pam::client::Client;
use rpassword::read_password;
use std::io::{self, Write};

pub fn prompt_password() -> Option<String> {
    print!("Password: ");
    io::stdout().flush().ok()?;
    read_password().ok();
}

pub fn verify_password(password: &str, user: &str) -> bool {
    let mut client = Client::with_password("login").ok()?;
    client.conversation_mut().set_credentials(user, password);
    client.authenticate().is_ok()
}
