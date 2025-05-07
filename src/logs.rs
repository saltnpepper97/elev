use log::{LevelFilter, info, warn, debug, error};
use syslog::{BasicLogger, Facility, Formatter3164};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Once;

static VERBOSE: AtomicBool = AtomicBool::new(false);
static INIT: Once = Once::new();

pub fn init_logger(verbose: bool) {
    INIT.call_once(|| {
        VERBOSE.store(verbose, Ordering::Relaxed);

        if verbose {
            // Connect to syslog for verbose logging
            let formatter = Formatter3164 {
                facility: Facility::LOG_AUTH,
                hostname: None,
                process: "elev".into(),
                pid: std::process::id(),
            };

            if let Ok(writer) = syslog::unix(formatter) {
                let logger = BasicLogger::new(writer);
                let _ = log::set_boxed_logger(Box::new(logger)).map(|()| log::set_max_level(LevelFilter::Debug));
            }

            // Also log to console
            let _ = log::set_boxed_logger(Box::new(ConsoleLogger)).map(|()| log::set_max_level(LevelFilter::Debug));
        } else {
            // Info level only
            let _ = log::set_boxed_logger(Box::new(ConsoleLogger)).map(|()| log::set_max_level(LevelFilter::Info));
        }
    });
}

pub struct ConsoleLogger;

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let log_msg = format!("{} - {}: {}", record.level(), record.target(), record.args());
            if record.level() == log::Level::Error {
                eprintln!("{}", log_msg); // Error messages to stderr
            } else {
                println!("{}", log_msg); // Info and debug to stdout
            }
        }
    }

    fn flush(&self) {}
}

pub fn log_info(message: &str) {
    info!("{}", message);
}

pub fn log_warn(message: &str) {
    warn!("{}", message);
}

pub fn log_error(message: &str) {
    error!("{}", message);
}

pub fn log_debug(message: &str) {
    if VERBOSE.load(Ordering::Relaxed) {
        debug!("{}", message);
    }
}
