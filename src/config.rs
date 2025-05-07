use std::fs::File;
use std::io::{BufRead, BufReader};
use regex::Regex;
use chrono::{Local, NaiveTime, Weekday};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct Rule {
    pub user: Option<String>,
    pub group: Option<String>,
    pub as_user: Option<String>,
    pub cmd_regex: Option<Regex>,
    pub priority: u8,
    pub start_time: Option<NaiveTime>,
    pub end_time: Option<NaiveTime>,
    pub days: Option<Vec<Weekday>>,
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
            timeout: Duration::from_secs(60),
        })
    }

    pub fn is_permitted(
        &self,
        user: &str,
        groups: &[String],
        target_user: &str,
        command: &str,
    ) -> bool {
        let mut rules = self.rules.clone();
        rules.sort_by(|a, b| b.priority.cmp(&a.priority));
        let now = Local::now();
        let current_time = now.time();
        let current_weekday = now.weekday();

        for rule in &rules {
            if rule.deny && rule.matches(user, groups, target_user, command, current_time, current_weekday) {
                return false;
            }
        }

        for rule in &rules {
            if !rule.deny && rule.matches(user, groups, target_user, command, current_time, current_weekday) {
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
        weekday: Weekday,
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

        if let (Some(start), Some(end)) = (self.start_time, self.end_time) {
            if now < start || now > end {
                return false;
            }
        }

        if let Some(days) = &self.days {
            if !days.contains(&weekday) {
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
    let mut start_time = None;
    let mut end_time = None;
    let mut days = None;

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
            "time" if i + 1 < tokens.len() => {
                let parts: Vec<&str> = tokens[i + 1].split('-').collect();
                if parts.len() == 2 {
                    start_time = NaiveTime::parse_from_str(parts[0], "%H:%M").ok();
                    end_time = NaiveTime::parse_from_str(parts[1], "%H:%M").ok();
                }
                i += 2;
            }
            "days" if i + 1 < tokens.len() => {
                let day_str = tokens[i + 1];
                if day_str == "*" || day_str.eq_ignore_ascii_case("all") {
                    days = Some(vec![
                        Weekday::Mon,
                        Weekday::Tue,
                        Weekday::Wed,
                        Weekday::Thu,
                        Weekday::Fri,
                        Weekday::Sat,
                        Weekday::Sun,
                    ]);
                } else {
                    let parsed_days = day_str
                        .split(',')
                        .filter_map(|d| match d.to_lowercase().as_str() {
                            "mon" => Some(Weekday::Mon),
                            "tue" => Some(Weekday::Tue),
                            "wed" => Some(Weekday::Wed),
                            "thu" => Some(Weekday::Thu),
                            "fri" => Some(Weekday::Fri),
                            "sat" => Some(Weekday::Sat),
                            "sun" => Some(Weekday::Sun),
                            _ => None,
                        })
                        .collect::<Vec<_>>();
                    if !parsed_days.is_empty() {
                        days = Some(parsed_days);
                    }
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

    Some(Rule { user, group, as_user, cmd_regex, priority, start_time, end_time, days, deny })
}
