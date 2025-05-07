use std::fs::File;
use std::io::{BufRead, BufReader};
use regex::Regex;
use std::time::Duration;
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
}

#[derive(Debug)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub timeout: Duration,
}

impl Config {
    pub fn load(filename: &str) -> Result<Self, std::io::Error> {
        log_info(&format!("Loading configuration from file: {}", filename));  // Log configuration load
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let mut rules = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Some(rule) = parse_rule(&line) {
                rules.push(rule);
            }
        }

        log_info(&format!("Loaded {} rules from configuration", rules.len()));  // Log the number of rules loaded

        Ok(Config {
            rules,
            timeout: Duration::from_secs(60),
        })
    }

    pub fn is_permitted(
        &self,
        user: &str,
        groups: &[String],
        target_user: &str,
        target_group: Option<&str>,
        command: &str,
        user_roles: &[String],
    ) -> bool {
        log_info(&format!("Checking permission for user '{}' to run command '{}'", user, command));  // Log permission check
        let mut rules = self.rules.clone();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        for rule in &rules {
            if rule.deny && rule.matches(user, groups, target_user, target_group, command, user_roles) {
                log_warn(&format!("Permission denied for user '{}' to run command '{}'", user, command));  // Log deny rule match
                return false;
            }
        }

        for rule in &rules {
            if !rule.deny && rule.matches(user, groups, target_user, target_group, command, user_roles) {
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
        target_group: Option<&str>,
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

fn parse_rule(line: &str) -> Option<Rule> {
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
    let mut allowed_roles = None;  // Added roles parsing
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
            "roles" if i + 1 < tokens.len() => {  // Roles handling
                allowed_roles = Some(tokens[i + 1].split(',').map(String::from).collect());
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

