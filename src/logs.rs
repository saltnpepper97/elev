use log::{LevelFilter, Log, Metadata, Record, info, warn, debug, error};
use syslog::{BasicLogger, Facility, Formatter3164};
use std::sync::{Mutex, Once};

static INIT: Once = Once::new();

/// Initialize a global logger that writes to both syslog (if available)
/// and the console. If `verbose` is true, debug-level logs are enabled.
pub fn init_logger(verbose: bool) {
    INIT.call_once(|| {
        // Prepare syslog backend
        let formatter = Formatter3164 {
            facility: Facility::LOG_AUTH,
            hostname: None,
            process: "elev".into(),
            pid: std::process::id(),
        };
        let syslogger = match syslog::unix(formatter) {
            Ok(writer) => Some(BasicLogger::new(writer)),
            Err(e) => {
                eprintln!("Failed to connect to syslog: {}", e);
                None
            }
        };

        // Build our combined logger
        let combined = CombinedLogger { syslog: syslogger, console: ConsoleLogger, verbose };
        let max_level = if verbose { LevelFilter::Debug } else { LevelFilter::Info };

        // Install it
        let _ = log::set_boxed_logger(Box::new(Mutex::new(combined)))
            .map(|()| log::set_max_level(max_level));
    });
}

/// A logger that fans each record out to syslog (if configured)
/// and to stderr/stdout via a simple console logger.
struct CombinedLogger {
    syslog: Option<BasicLogger>,
    console: ConsoleLogger,
    verbose: bool,
}

impl Log for Mutex<CombinedLogger> {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let lvl = if self.lock().unwrap().verbose {
            LevelFilter::Debug
        } else {
            LevelFilter::Info
        };
        metadata.level() <= lvl
    }

    fn log(&self, record: &Record) {
        let guard = self.lock().unwrap();
        if guard.enabled(record.metadata()) {
            // send to syslog first
            if let Some(ref syslogger) = guard.syslog {
                let _ = syslogger.log(record);
            }
            // then console
            guard.console.log(record);
        }
    }

    fn flush(&self) {
        let guard = self.lock().unwrap();
        if let Some(ref syslogger) = guard.syslog {
            let _ = syslogger.flush();
        }
        guard.console.flush();
    }
}

/// A minimal console logger that prints to stdout/stderr.
pub struct ConsoleLogger;

impl Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // console always allows debug (actual gating in CombinedLogger)
        metadata.level() <= LevelFilter::Debug
    }

    fn log(&self, record: &Record) {
        let msg = format!("{} - {}: {}", record.level(), record.target(), record.args());
        if record.level() == log::Level::Error {
            eprintln!("{}", msg);
        } else {
            println!("{}", msg);
        }
    }

    fn flush(&self) {}
}

// Convenience wrappers so you can keep using log_info, etc.

/// Logs at INFO level.
pub fn log_info(message: &str) {
    info!("{}", message);
}

/// Logs at WARN level.
pub fn log_warn(message: &str) {
    warn!("{}", message);
}

/// Logs at ERROR level.
pub fn log_error(message: &str) {
    error!("{}", message);
}

/// Logs at DEBUG level (only emitted if `--verbose` was set).
pub fn log_debug(message: &str) {
    debug!("{}", message);
}
