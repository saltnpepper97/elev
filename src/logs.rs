use syslog::{BasicLogger, Facility, Formatter3164};
use log::{info, warn, error, debug, LevelFilter};

pub fn init_logger(verbose: bool) {
    let formatter = Formatter3164 {
        facility: Facility::LOG_AUTH,
        hostname: None,
        process: "elev".into(),
        pid: std::process::id(),
    };

    match syslog::unix(formatter) {
        Ok(writer) => {
            let logger = BasicLogger::new(writer);
            let level = if verbose { LevelFilter::Debug } else { LevelFilter::Info };
            let _ = log::set_boxed_logger(Box::new(logger)).map(|()| log::set_max_level(level));
        }
        Err(e) => {
            eprintln!("Failed to connect to syslog: {}", e);
        }
    }
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
