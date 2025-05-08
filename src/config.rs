use std::fs::File;
use std::io::{BufRead, BufReader};
use regex::Regex;
use std::time::Duration;
use std::collections::HashMap;
use crate::logs::{log_info, log_warn};

#[derive(Clone, Debug)]
pub struct Rule {
    pub user: Option<String>,
    pub group: Option<String>,
    pub as_user: Option<String>,
    pub cmd_regex: Option<Regex>,
    pub priority: u8,
    pub allowed_roles: Option<Vec<String>>,
    pub deny: bool,
    pub password_required: Option<bool>, // per-rule override
}

#[derive(Debug)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub timeout: Duration,
    pub password_required: bool, // global default
    pub roles: HashMap<String, (Vec<String>, Option<(chrono::NaiveTime, chrono::NaiveTime)>)>,
}

impl Config {
    pub fn load(filename: &str) -> Result<Self, std::io::Error> {
        log_info(&format!("Loading configuration from file: {}", filename));
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let mut rules = Vec::new();
        let mut timeout = Duration::from_secs(60);
        let mut password_required = true; // default until overridden
        let mut roles: HashMap<String, (Vec<String>, Option<(chrono::NaiveTime, chrono::NaiveTime)>)> = HashMap::new();
        let mut raw_lines = Vec::new();

        // First pass: collect roles and raw lines
        for line in reader.lines() {
            let line = line?.trim().to_string();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            if let Some(role_def) = line.strip_prefix("role ") {
                let mut parts = role_def.splitn(3, ' ');
                if let Some(role_name) = parts.next() {
                    let users: Vec<String> = parts
                        .next()
                        .unwrap_or("")
                        .split(',')
                        .map(str::trim)
                        .filter(|s| !s.is_empty())
                        .map(String::from)
                        .collect();
                    let time_range = parts.next().and_then(|timing_str| {
                        let times: Vec<&str> = timing_str.split('-').collect();
                        if times.len() == 2 {
                            Some((
                                chrono::NaiveTime::parse_from_str(times[0], "%H:%M").unwrap(),
                                chrono::NaiveTime::parse_from_str(times[1], "%H:%M").unwrap(),
                            ))
                        } else {
                            None
                        }
                    });
                    roles.insert(role_name.to_string(), (users.clone(), time_range));
                    log_info(&format!(
                        "Defined role '{}' with members {:?} and timing {:?}",
                        role_name, users, time_range
                    ));
                }
            } else {
                raw_lines.push(line);
            }
        }

        // Second pass: parse rules and global settings
        for line in &raw_lines {
            if let Some(rule) = parse_rule(line, &roles) {
                rules.push(rule);
            }

            if let Some(timeout_str) = line.strip_prefix("timeout ") {
                if let Ok(sec) = timeout_str.trim().parse::<u64>() {
                    timeout = Duration::from_secs(sec);
                    log_info(&format!("Loaded timeout: {}s", sec));
                }
            }

            if let Some(pass_str) = line.strip_prefix("password_required ") {
                if let Ok(req) = pass_str.trim().parse::<bool>() {
                    password_required = req;
                    log_info(&format!("Loaded global password_required: {}", req));
                }
            }
        }

        // sort rules by descending priority
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        log_info(&format!("Loaded {} rules", rules.len()));

        Ok(Config {
            rules,
            timeout,
            password_required,
            roles,
        })
    }

    /// Check if a specific rule or global requires password
    pub fn requires_password_for_rule(&self, rule: &Rule) -> bool {
        rule.password_required.unwrap_or(self.password_required)
    }

    pub fn is_permitted(
        &self,
        username: &str,
        groups: &[String],
        target_user: &str,
        command: &str,
        user_roles: &[String],
    ) -> bool {
        for rule in &self.rules {
            if rule.matches(username, groups, target_user, command, user_roles) {
                return !rule.deny;
            }
        }
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
        // user or group match
        let user_ok = self.user.as_deref().map_or(true, |u| u == "*" || u == user);
        let group_ok = self.group.as_deref().map_or(true, |g| g == "*" || groups.iter().any(|gr| gr == g));
        if !(user_ok || group_ok) {
            return false;
        }

        // role match
        if let Some(allowed) = &self.allowed_roles {
            if !user_roles.iter().any(|r| allowed.contains(r)) {
                return false;
            }
        }

        // as_user match
        if let Some(as_u) = &self.as_user {
            if as_u != target_user {
                return false;
            }
        }

        // command regex
        if let Some(re) = &self.cmd_regex {
            if !re.is_match(command) {
                return false;
            }
        }

        true
    }
}

fn wildcard_to_regex(pattern: &str) -> String {
    let mut re = String::from("^");
    for ch in pattern.chars() {
        match ch {
            '*' => re.push_str(".*"),
            '?' => re.push('.'),
            c => re.push_str(&regex::escape(&c.to_string())),
        }
    }
    re.push('$');
    re
}

fn parse_rule(
    line: &str,
    roles_map: &HashMap<String, (Vec<String>, Option<(chrono::NaiveTime, chrono::NaiveTime)>)>,
) -> Option<Rule> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    let mut deny = false;
    let mut i = 0;
    match tokens[0] {
        "deny" => { deny = true; i = 1; }
        "allow" => { i = 1; }
        _ => return None,
    }

    // subject
    let mut user = None;
    let mut group = None;
    if i < tokens.len() {
        if let Some(rest) = tokens.get(i) {
            if rest.starts_with(':') {
                group = Some(rest[1..].to_string());
            } else {
                user = Some(rest.to_string());
            }
        }
        i += 1;
    }

    let mut as_user = None;
    let mut cmd_regex = None;
    let mut priority = 0;
    let mut allowed_roles = None;
    let mut password_required = None;

    while i < tokens.len() {
        match tokens[i] {
            "as" if i+1 < tokens.len() => { as_user = Some(tokens[i+1].to_string()); i += 2; }
            "cmd" if i+1 < tokens.len() => {
                let pat = tokens[i+1];
                let re_str = if pat.contains('*') || pat.contains('?') {
                    wildcard_to_regex(pat)
                } else if pat == "*" {
                    String::from("^.*$")
                } else {
                    format!(r"(^|.*/){}$", regex::escape(pat))
                };
                cmd_regex = Some(Regex::new(&re_str).unwrap());
                i += 2;
            }
            "cmd_regex" if i+1 < tokens.len() => {
                cmd_regex = Some(Regex::new(tokens[i+1]).unwrap());
                i += 2;
            }
            "priority" if i+1 < tokens.len() => {
                priority = tokens[i+1].parse().unwrap_or(0);
                i += 2;
            }
            "roles" if i+1 < tokens.len() => {
                let parsed = tokens[i+1].split(',').map(str::to_string).collect::<Vec<_>>();
                for r in &parsed {
                    if !roles_map.contains_key(r) {
                        log_warn(&format!("Rule references undefined role '{}'", r));
                    }
                }
                allowed_roles = Some(parsed);
                i += 2;
            }
            "password_required" if i+1 < tokens.len() => {
                password_required = tokens[i+1].parse().ok();
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    Some(Rule {
        user,
        group,
        as_user,
        cmd_regex,
        priority,
        allowed_roles,
        deny,
        password_required,
    })
}
