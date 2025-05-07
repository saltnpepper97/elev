pub fn run_command(
    config: &Config,
    auth_state: &mut AuthState,
    cmd: &str,
    args: &[&str],
) -> Result<ExitStatus, std::io::Error> {
    let target_user = &auth_state.username;
    let target_group = auth_state.groups.first();

    // Ensure user has permission to run the command
    if !config.is_permitted(
        &auth_state.username,
        &auth_state.groups,
        "root",
        target_group.as_deref().map(|x| x.as_str()),
        cmd,
    ) {
        log_error(&format!(
            "Permission denied for user '{}' to run command '{}'",
            auth_state.username, cmd
        ));
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Permission denied",
        ));
    }

    // Handle timeout check
    if !auth_state.check_timeout() {
        log_warn(&format!(
            "Authentication timeout expired for user '{}'",
            auth_state.username
        ));
        return Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "Authentication timeout expired",
        ));
    }

    // Switch user before running the command
    if let Err(e) = switch_user(target_user) {
        log_error(&e);
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "User switch failed",
        ));
    }

    // Now execute the command with all arguments
    let mut command = Command::new(cmd);
    command.args(args);  // Pass the arguments here

    // Setup environment if necessary (e.g., for root commands)
    let path = "/usr/bin:/bin:/usr/sbin:/sbin";
    command.env("PATH", path);

    // Log command and environment for debugging
    log_info(&format!("Running command: '{} {}'", cmd, args.join(" ")));

    // Execute the command
    command.status()
}
