use log::{info, warn, error, debug, LevelFilter};

#[cfg(not(debug_assertions))]
use syslog::{BasicLogger, Facility, Formatter3164};

#[cfg(debug_assertions)]
use env_logger;

pub fn init_logger(verbose: bool) {
    let level = if verbose { LevelFilter::Debug } else { LevelFilter::Info };

    // In development, use env_logger or stderr
    #[cfg(debug_assertions)]
    {
        env_logger::Builder::new()
            .filter_level(level)
            .init();
    }

    // In production, use syslog or stderr if syslog is unavailable
    #[cfg(not(debug_assertions))]
    {
        // Try to initialize syslog
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "elev".into(),
            pid: std::process::id(),
        };

        match syslog::unix(formatter) {
            Ok(writer) => {
                let logger = BasicLogger::new(writer);
                let _ = log::set_boxed_logger(Box::new(logger)).map(|()| log::set_max_level(level));
            }
            Err(e) => {
                eprintln!("Failed to connect to syslog: {}", e); // Fallback to stderr if syslog fails
                eprintln!("Switching to console logging.");
                let _ = log::set_boxed_logger(Box::new(ConsoleLogger)).map(|()| log::set_max_level(level));
            }
        }
    }
}

// Simple console logger to fall back on when syslog isn't available
struct ConsoleLogger;

impl log::Log for ConsoleLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= log::Level::Debug
    }

    fn log(&self, record: &log::Record) {
        let log_msg = format!("{} - {}: {}", record.level(), record.target(), record.args());
        if record.level() == log::Level::Error {
            eprintln!("{}", log_msg); // Error messages to stderr
        } else {
            println!("{}", log_msg); // Info and debug messages to stdout
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
    debug!("{}", message);
}

