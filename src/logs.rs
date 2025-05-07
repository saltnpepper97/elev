use log::{LevelFilter, info, debug, error};
use syslog::{BasicLogger, Facility, Formatter3164};

pub fn init_logger(verbose: bool) {
    if verbose {
        // When verbose is true, show debug-level logs
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "elev".into(),
            pid: std::process::id(),
        };

        match syslog::unix(formatter) {
            Ok(writer) => {
                let logger = BasicLogger::new(writer);
                // Set log level to Debug so that debug logs are shown
                let _ = log::set_boxed_logger(Box::new(logger)).map(|()| log::set_max_level(LevelFilter::Debug));
            }
            Err(e) => {
                eprintln!("Failed to connect to syslog: {}", e);
            }
        }
    } else {
        // When verbose is false, only show info-level and higher logs
        log::set_max_level(LevelFilter::Info);
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

