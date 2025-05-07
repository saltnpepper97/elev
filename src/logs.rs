use log::{LevelFilter, Log, Metadata, Record, info, warn, debug, error};
use syslog::{BasicLogger, Facility, Formatter3164};
use std::sync::Once;

static INIT: Once = Once::new();

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
        let combined = CombinedLogger {
            syslog: syslogger,
            console: ConsoleLogger,
            verbose,
        };
        let max_level = if verbose { LevelFilter::Debug } else { LevelFilter::Info };

        // Install it
        let _ = log::set_boxed_logger(Box::new(combined))
            .map(|()| log::set_max_level(max_level));
    });
}

struct CombinedLogger {
    syslog: Option<BasicLogger>,
    console: ConsoleLogger,
    verbose: bool,
}

impl Log for CombinedLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let level = if self.verbose { LevelFilter::Debug } else { LevelFilter::Info };
        metadata.level() <= level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // send to syslog first
            if let Some(ref syslogger) = self.syslog {
                let _ = syslogger.log(record);
            }
            // then console
            self.console.log(record);
        }
    }

    fn flush(&self) {
        if let Some(ref syslogger) = self.syslog {
            let _ = syslogger.flush();
        }
        self.console.flush();
    }
}

pub struct ConsoleLogger;

impl Log for ConsoleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // console allows debug; gating in CombinedLogger
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
