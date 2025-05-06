mod config;
mod auth;
mod exec;
mod util;

use config::Config;
use util::get_user_groups;

fn main() {
    // CLI parsing...

    let current_user = whoami::username();
    let groups = get_user_groups(&current_user);

    if !config.is_permitted(&current_user, &groups, target_user, command) {
        eprintln!("Nexus: Permission denied for '{}'", current_user);
        exit(1);
    }

    let password = auth::prompt_password().unwrap_or_default();
    if !auth::verify_password(&password, &current_user) {
        eprintln!("Authentication failed");
        exit(1);
    }

    if target_user != current_user {
        exec::switch_user(target_user).unwrap_or_else(|e| {
            eprintln!("Failed to switch user: {}", e);
            exit(1);
        });
    }

    exec::run_command(command, &args).unwrap();
}
