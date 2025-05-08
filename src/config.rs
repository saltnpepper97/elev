use std::fs::File;
use std::io::{BufRead, BufReader};
use regex::Regex;
use std::time::Duration;
use std::collections::HashMap;
use crate::logs::{log_info, log_warn, log_error};

#[derive(Clone, Debug)]
pub struct Rule {
    pub user: Option<String>,
    pub group: Option<String>,
    pub as_user: Option<String>,
    pub cmd_regex: Option<Regex>,
    pub priority: u8,
    pub allowed_roles: Option<Vec<String>>,
    pub deny: bool,
    pub time_range: Option<(chrono::NaiveTime, chrono::NaiveTime)>,
}

#[derive(Debug)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub timeout: Duration,
    pub password_required: bool,
    pub roles: HashMap<String, Vec<String>>,
}

impl Config {
    pub fn load(filename: &str) -> Result<Self, std::io::Error> {
        log_info(&format!("Loading configuration from file: {}", filename));  // Log configuration load
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let mut rules = Vec::new();
        let mut timeout = Duration::from_secs(60);
        let mut password_required = true;
        let mut roles: HashMap<String, Vec<String>> = HashMap::new();
        let mut raw_lines = Vec::new();

        for line in reader.lines() {
            let line = line?.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
        
            if let Some(role_def) = line.strip_prefix("role ") {
                let mut parts = role_def.splitn(2, ' ');
                if let Some(role_name) = parts.next() {
                    if let Some(users_str) = parts.next() {
                        let users: Vec<String> = users_str
                            .split(',')
                            .map(|s| s.trim().to_string())
                            .collect();
                        roles.insert(role_name.to_string(), users.clone());
                        log_info(&format!("Defined role '{}' with members {:?}", role_name, users));
                    }
                }
            } else {
                raw_lines.push(line);
            }
        }
        
        // Second pass: parse rules and global settings
        for line in &raw_lines {
            if let Some(rule) = parse_rule(&line, &roles) {
                rules.push(rule);
            }
        
            if let Some(timeout_str) = line.strip_prefix("timeout ") {
                if let Ok(timeout_value) = timeout_str.trim().parse::<u64>() {
                    timeout = Duration::from_secs(timeout_value);
                    log_info(&format!("Loaded timeout value from config: {} seconds", timeout_value));
                }
            }
        
            if let Some(password_str) = line.strip_prefix("password_required ") {
                if let Ok(pass_req) = password_str.trim().parse::<bool>() {
                    password_required = pass_req;
                    log_info(&format!("Loaded password_required value from config: {}", password_required));
                }
            }
        }

        log_info(&format!("Loaded {} rules from configuration", rules.len()));  // Log the number of rules loaded

        Ok(Config {
            rules,
            timeout,
            password_required,
            roles,
        })
    }

    pub fn is_permitted(
        &self,
        user: &str,
        groups: &[String],
        target_user: &str,
        command: &str,
        user_roles: &[String],
    ) -> bool {
        log_info(&format!("Checking permission for user '{}' to run command '{}'", user, command));  // Log permission check
        let mut rules = self.rules.clone();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in &rules {
            if rule.deny && rule.matches(user, groups, target_user, command, user_roles) {
                log_warn(&format!("Permission denied for user '{}' to run command '{}'", user, command));  // Log deny rule match
                return false;
            }
        }

        for rule in &rules {
            if !rule.deny && rule.matches(user, groups, target_user, command, user_roles) {
                log_info(&format!("Permission granted for user '{}' to run command '{}'", user, command));  // Log allow rule match
                return true;
            }
        }

        log_error(&format!("Permission check failed for user '{}' to run command '{}'", user, command));  // Log permission failure
        false
    }
}

impl Rule {
    fn matches(
        &self,
        user: &str,
        groups: &[String],
        target_user: &str,
        command: &str,
        user_roles: &[String],
    ) -> bool {
        let user_ok = match &self.user {
            Some(u) if u != "*" => u == user,
            _ => true,
        };

        let group_ok = match &self.group {
            Some(g) if g != "*" => groups.iter().any(|gr| gr == g),
            _ => true,
        };

        if !user_ok && !group_ok {
            return false;
        }
        
        if let Some(allowed_roles) = &self.allowed_roles {
            if !user_roles.iter().any(|role| allowed_roles.contains(role)) {
                return false; // Role does not match
            }
        }

        if let Some(as_u) = &self.as_user {
            if as_u != target_user {
                return false;
            }
        }

        if let Some(re) = &self.cmd_regex {
            if !re.is_match(command) {
                return false;
            }
        }

        if let Some((start_time, end_time)) = &self.time_range {
            let current_time = chrono::Local::now().naive_local().time();
            if current_time < *start_time || current_time > *end_time {
                return false; // Time is outside the allowed range
            }
        }
        true
    }
}

fn wildcard_to_regex(pattern: &str) -> String {
    let mut regex = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            _ => regex.push_str(&regex::escape(&ch.to_string())),
        }
    }
    regex.push('$');
    regex
}

fn parse_rule(line: &str, roles_map: &HashMap<String, Vec<String>>) -> Option<Rule> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    let mut deny = false;
    let mut i = 0;
    match tokens[i] {
        "deny" => { deny = true; i += 1; }
        "allow" => { i += 1; }
        _ => return None,
    }

    let mut user = None;
    let mut group = None;
    if i < tokens.len() {
        let t = tokens[i];
        if t.starts_with(':') {
            group = Some(t[1..].to_string());
        } else {
            user = Some(t.to_string());
        }
        i += 1;
    }

    let mut as_user = None;
    let mut command_pat = None;
    let mut priority = 0;
    let mut allowed_roles = None;
    while i < tokens.len() {
        match tokens[i] {
            "as" if i + 1 < tokens.len() => {
                as_user = Some(tokens[i + 1].to_string());
                i += 2;
            }
            "cmd" if i + 1 < tokens.len() => {
                command_pat = Some(tokens[i + 1].to_string());
                i += 2;
            }
            "priority" if i + 1 < tokens.len() => {
                priority = tokens[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "roles" if i + 1 < tokens.len() => {
                let parsed_roles: Vec<String> = tokens[i + 1].split(',').map(|s| s.to_string()).collect();
            
                // Validate roles exist in the map
                for role in &parsed_roles {
                    if !roles_map.contains_key(role) {
                        log_warn(&format!("Rule references undefined role: '{}'", role));
                    }
                }
            
                allowed_roles = Some(parsed_roles);
                i += 2;
            }
            "timing" if i + 1 < tokens.len() => {
                let time_range_str = tokens[i + 1];
                let times: Vec<&str> = time_range_str.split('-').collect();
                if times.len() == 2 {
                    let start_time = chrono::NaiveTime::parse_from_str(times[0], "%H:%M").unwrap();
                    let end_time = chrono::NaiveTime::parse_from_str(times[1], "%H:%M").unwrap();
                    time_range = Some((start_time, end_time));
                }
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    let cmd_regex = command_pat.map(|pat| {
        let re_str = if pat.contains('*') || pat.contains('?') {
            wildcard_to_regex(&pat)
        } else if pat == "*" {
            String::from("^.*$")
        } else {
            format!("^{pat}$")
        };
        Regex::new(&re_str).unwrap_or_else(|_| Regex::new("^$").unwrap())
    });

    Some(Rule { user, group, as_user, cmd_regex, priority, allowed_roles, deny })
}
