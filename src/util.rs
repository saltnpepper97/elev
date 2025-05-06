pub fn get_user_groups(user: &str) -> Vec<String> {
    let output = std::process::Command::new("id")
        .arg("-Gn")
        .arg(user)
        .output();

    match output {
        Ok(out) if out.status.success() => {
            let group_str = String::from_utf8_lossy(&out.stdout);
            group_str.split_whitespace().map(|s| s.to_string()).collect()
        }
        _ => vec![],
    }
}
