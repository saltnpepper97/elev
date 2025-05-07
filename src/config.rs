use std::fs::File;
use std::io::{BufRead, BufReader};
use regex::Regex;
use chrono::{NaiveTime, Local, Timelike, Duration};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Represents a single permission rule from the config.
#[derive(Clone, Debug)]
pub struct Rule {
    pub user: Option<String>,
    pub group: Option<String>,
    pub as_user: Option<String>,
    pub command: Option<String>,
    pub priority: Option<u8>,
    pub start_time: Option<NaiveTime>,
    pub end_time: Option<NaiveTime>,
}

/// Represents the full config file.
#[derive(Debug)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub last_authenticated: HashMap<String, u64>,
    pub timeout: u64,
}

impl Config {
    pub fn load(path: &str, timeout: u64) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut rules = Vec::new();
        let mut last_authenticated = HashMap::new();

        for line in reader.lines() {
            let line = line?;
            let trimmed = line.trim();

            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue; // Skip comments and empty lines
            }

            if let Some(rule) = parse_rule(trimmed) {
                rules.push(rule);
            }
        }

        Ok(Config {
            rules,
            last_authenticated,
            timeout,
        })
    }

    pub fn is_permitted(&mut self, user: &str, groups: &[String], target_user: &str, command: &str) -> bool {
        // First, check if the user has authenticated recently
        if let Some(last_auth_time) = self.last_authenticated.get(user) {
            let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
            if current_time - last_auth_time > self.timeout {
                return false; // If the last authentication was too long ago, deny access
            }
        } else {
            return false; // If no authentication timestamp exists, deny access
        }

        // Sort the rules by priority (descending order)
        let mut sorted_rules = self.rules.clone();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));
    
        let current_time = Local::now().time();
    
        for rule in sorted_rules {
            let user_match = match (&rule.user, &rule.group) {
                (Some(u), _) if u == user => true,
                (_, Some(g)) if groups.contains(g) => true,
                _ => false,
            };
    
            if !user_match {
                continue;
            }
    
            if let Some(as_user) = &rule.as_user {
                if as_user != target_user {
                    continue;
                }
            }
    
            // Handle the wildcard '*' for commands
            if let Some(cmd_pattern) = &rule.command {
                // If the command is a wildcard ('*'), allow any command
                if cmd_pattern == "*" || command == cmd_pattern {
                    // If the pattern matches the command or it's a wildcard, allow
                } else {
                    // If it's a regex pattern, match using regex
                    let regex = Regex::new(cmd_pattern).unwrap(); 
                    if !regex.is_match(command) {
                        continue;
                    }
                }
            }
    
            // Check time-based access
            if let (Some(start), Some(end)) = (rule.start_time, rule.end_time) {
                if current_time < start || current_time > end {
                    continue;
                }
            }
    
            return true;
        }
    
        false
    }

    pub fn authenticate(&mut self, user: &str) -> bool {
        // Update the last authenticated time for the user
        let current_time = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        self.last_authenticated.insert(user.to_string(), current_time);

        true
    }
}

fn parse_rule(line: &str) -> Option<Rule> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() || tokens[0] != "permit" {
        return None;
    }

    let mut user = None;
    let mut group = None;
    let mut as_user = None;
    let mut command = None;
    let mut priority = None;
    let mut start_time = None;
    let mut end_time = None;
    let mut i = 1;

    if i < tokens.len() {
        if tokens[i].starts_with(':') {
            group = Some(tokens[i][1..].to_string());
        } else {
            user = Some(tokens[i].to_string());
        }
        i += 1;
    }

    while i < tokens.len() {
        match tokens[i] {
            "as" => {
                i += 1;
                if i < tokens.len() {
                    as_user = Some(tokens[i].to_string());
                }
            }
            "cmd" => {
                i += 1;
                if i < tokens.len() {
                    command = Some(tokens[i].to_string());
                }
            }
            "priority" => {
                i += 1;
                if i < tokens.len() {
                    priority = Some(tokens[i].parse().unwrap_or(0)); // Default priority 0
                }
            }
            "time" => {
                i += 1;
                if i < tokens.len() {
                    let times: Vec<&str> = tokens[i].split('-').collect();
                    if times.len() == 2 {
                        start_time = Some(NaiveTime::parse_from_str(times[0], "%H:%M").unwrap());
                        end_time = Some(NaiveTime::parse_from_str(times[1], "%H:%M").unwrap());
                    }
                }
            }
            _ => {}
        }
        i += 1;
    }

    Some(Rule {
        user,
        group,
        as_user,
        command,
        priority,
        start_time,
        end_time,
    })
}
