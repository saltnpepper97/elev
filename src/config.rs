use std::fs::File;
use std::io::{BufRead, BufReader};

/// Represents a single permission rule from the config.
#[derive(Debug)]
pub struct Rule {
    pub user: Option<String>,
    pub group: Option<String>,
    pub as_user: Option<String>,
    pub command: Option<String>,
}

/// Represents the full config file
#[derive(Debug)]
pub struct Config {
    pub rules: Vec<Rule>,
}

impl Config {
    pub fn load(path: &str) -> std::io::Result<Self> {
        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut rules = Vec::new();

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

        Ok(Config { rules })
    }

    pub fn is_permitted(&self, user: &str, groups: &[String], target_user: &str, command: &str) -> bool {
        for rule in &self.rules {
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

            if let Some(cmd) = &rule.command {
                if cmd != command {
                    continue;
                }
            }

            return true;
        }

        false
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
            _ => {}
        }
        i += 1;
    }

    Some(Rule {
        user,
        group,
        as_user,
        command,
    })
}
