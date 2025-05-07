use syslog::{Facility, Formatter3164, Severity};
use std::sync::Once;

static INIT: Once = Once::new();

pub fn init_logger() {
    INIT.call_once(|| {
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "nexus".into(),
            pid: std::process::id(),
        };

        if let Err(e) = syslog::unix(formatter) {
            eprintln!("Failed to connect to syslog: {}", e);
        }
    });
}

pub fn log_info(message: &str) {
    let _ = syslog::log(Severity::Info, message);
}

pub fn log_warn(message: &str) {
    let _ = syslog::log(Severity::Warning, message);
}

pub fn log_error(message: &str) {
    let _ = syslog::log(Severity::Err, message);
}
