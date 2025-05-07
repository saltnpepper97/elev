use std::fs::File;
use std::io::{BufRead, BufReader};
use regex::Regex;
use chrono::{Local, NaiveTime};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Rule {
    pub user: Option<String>,      // Some("root"), Some("*"), or None for wildcard
    pub group: Option<String>,     // Some("wheel"), Some("*"), or None for wildcard
    pub as_user: Option<String>,   // target user
    pub command: Option<String>,   // command string or regex
    pub priority: u8,              // default 0 if unset
    pub start_time: Option<NaiveTime>,
    pub end_time: Option<NaiveTime>,
    pub deny: bool,
}

#[derive(Debug)]
pub struct Config {
    pub rules: Vec<Rule>,
    pub timeout: Duration,
}

impl Config {
    pub fn load(filename: &str) -> Result<Self, std::io::Error> {
        let file = File::open(filename)?;
        let reader = BufReader::new(file);
        let mut rules = Vec::new();

        for line in reader.lines() {
            let line = line?;
            if let Some(rule) = parse_rule(&line) {
                rules.push(rule);
            }
        }

        Ok(Config {
            rules,
            timeout: Duration::from_secs(60), // default timeout
        })
    }

    pub fn is_permitted(
        &self,
        user: &str,
        groups: &[String],
        target_user: &str,
        command: &str,
    ) -> bool {
        // Sort rules by descending priority
        let mut rules = self.rules.clone();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        let now = Local::now().time();

        // Deny rules take absolute precedence
        for rule in &rules {
            if rule.deny && rule.matches(user, groups, target_user, command, now) {
                return false;
            }
        }

        // Then allow rules
        for rule in &rules {
            if !rule.deny && rule.matches(user, groups, target_user, command, now) {
                return true;
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
        now: NaiveTime,
    ) -> bool {
        // User or group match (None or "*" => wildcard)
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

        // 'as' (target user) match
        if let Some(ref as_u) = self.as_user {
            if as_u != target_user {
                return false;
            }
        }

        // Command match ("*" => wildcard, or regex)
        if let Some(ref cmd_pattern) = self.command {
            if cmd_pattern != "*" {
                let re = Regex::new(cmd_pattern).unwrap();
                if !re.is_match(command) {
                    return false;
                }
            }
        }

        // Time window match
        if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
            if now < start || now > end {
                return false;
            }
        }

        true
    }
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
    let mut command = None;
    let mut priority = 0;
    let mut start_time = None;
    let mut end_time = None;

    while i < tokens.len() {
        match tokens[i] {
            "as" if i + 1 < tokens.len() => {
                as_user = Some(tokens[i + 1].to_string());
                i += 2;
            }
            "cmd" if i + 1 < tokens.len() => {
                command = Some(tokens[i + 1].to_string());
                i += 2;
            }
            "priority" if i + 1 < tokens.len() => {
                priority = tokens[i + 1].parse().unwrap_or(0);
                i += 2;
            }
            "time" if i + 1 < tokens.len() => {
                let times: Vec<&str> = tokens[i + 1].split('-').collect();
                if times.len() == 2 {
                    start_time = NaiveTime::parse_from_str(times[0], "%H:%M").ok();
                    end_time = NaiveTime::parse_from_str(times[1], "%H:%M").ok();
                }
                i += 2;
            }
            _ => { i += 1; }
        }
    }

    Some(Rule { user, group, as_user, command, priority, start_time, end_time, deny })
}
