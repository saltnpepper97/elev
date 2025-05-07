use std::fs::File;
use std::io::{BufRead, BufReader};
use regex::Regex;
use chrono::{NaiveTime, Local};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Rule {
    pub user: Option<String>,
    pub group: Option<String>,
    pub as_user: Option<String>,
    pub command: Option<String>,
    pub priority: Option<u8>,
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
    pub fn is_permitted(&self, user: &str, groups: &[String], target_user: &str, command: &str) -> bool {
        let mut sorted_rules = self.rules.clone();
        sorted_rules.sort_by(|a, b| b.priority.cmp(&a.priority));

        let current_time = Local::now().time();

        // First, check for deny rules and immediately return false if any are matched
        for rule in &sorted_rules {
            if rule.deny {
                let user_match = match (&rule.user, &rule.group) {
                    (Some(u), _) if u == user => true,
                    (_, Some(g)) if groups.contains(g) => true,
                    _ => false,
                };

                if user_match {
                    if let Some(as_user) = &rule.as_user {
                        if as_user != target_user {
                            continue;
                        }
                    }

                    if let Some(cmd_pattern) = &rule.command {
                        if cmd_pattern == "*" || command == cmd_pattern {
                        } else {
                            let regex = Regex::new(cmd_pattern).unwrap();
                            if !regex.is_match(command) {
                                continue;
                            }
                        }
                    }

                    if let (Some(start), Some(end)) = (rule.start_time, rule.end_time) {
                        if current_time < start || current_time > end {
                            continue;
                        }
                    }

                    return false; // Deny access if the deny rule matches
                }
            }
        }

        // Then, check for allow rules, but only if no deny rule was matched
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

            if let Some(cmd_pattern) = &rule.command {
                if cmd_pattern == "*" || command == cmd_pattern {
                } else {
                    let regex = Regex::new(cmd_pattern).unwrap();
                    if !regex.is_match(command) {
                        continue;
                    }
                }
            }

            if let (Some(start), Some(end)) = (rule.start_time, rule.end_time) {
                if current_time < start || current_time > end {
                    continue;
                }
            }

            return true;  // Allow access if the allow rule matches
        }

        false
    }
}

fn parse_rule(line: &str) -> Option<Rule> {
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.is_empty() {
        return None;
    }

    let mut user = None;
    let mut group = None;
    let mut as_user = None;
    let mut command = None;
    let mut priority = None;
    let mut start_time = None;
    let mut end_time = None;
    let mut deny = false;
    let mut i = 0;

    // Check for deny or allow
    if tokens[i] == "deny" {
        deny = true;
        i += 1;
    } else if tokens[i] != "allow" {
        return None;
    } else {
        i += 1;
    }

    // Parse other parts of the rule
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
                    priority = Some(tokens[i].parse().unwrap_or(0)); 
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
        deny,
    })
}
