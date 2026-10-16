//! The log: a file (or stderr) with UTC timestamps and levels, rotated by
//! size so it can't fill the disk.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use log::{Level, LevelFilter, Log, Metadata, Record};

use crate::config::Config;

/// Starts logging as [config] says: `LOG_FILE` (`-` for stderr),
/// `LOG_LEVEL`, `LOG_MAX_MB`, `LOG_KEEP`. Panics are logged too.
pub fn init(config: &Config) -> Result<(), String> {
    let out = if config.log_file == "-" {
        Output::Stderr
    } else {
        let max_size = config.log_max_mb.saturating_mul(1024 * 1024);
        let file = LogFile::open(PathBuf::from(&config.log_file), max_size, config.log_keep)
            .map_err(|e| format!("can't open the log file {}: {e}", config.log_file))?;
        Output::File(file)
    };
    let logger = Logger { level: config.log_level, out: Mutex::new(out) };
    log::set_boxed_logger(Box::new(logger)).map_err(|e| e.to_string())?;
    log::set_max_level(config.log_level);

    // Into the log, and to stderr as before, so the service manager also
    // shows why the bridge stopped.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let msg = payload
            .downcast_ref::<&str>()
            .copied()
            .or_else(|| payload.downcast_ref::<String>().map(String::as_str))
            .unwrap_or("(no message)");
        match info.location() {
            Some(at) => log::error!("Panic at {at}: {msg}"),
            None => log::error!("Panic: {msg}"),
        }
        default_hook(info);
    }));
    Ok(())
}

struct Logger {
    level: LevelFilter,
    out: Mutex<Output>,
}

enum Output {
    Stderr,
    File(LogFile),
}

impl Log for Logger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // Other crates (ureq, hyper, ...) only for warnings and errors.
        metadata.level() <= self.level
            && (metadata.level() <= Level::Warn || metadata.target().starts_with("pivx_bridge"))
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let line = format!("{} {:<5} {}\n", utc(d.as_secs(), d.subsec_millis()), record.level(), record.args());
        match &mut *self.out.lock().unwrap_or_else(|e| e.into_inner()) {
            Output::Stderr => {
                let _ = std::io::stderr().write_all(line.as_bytes());
            }
            Output::File(file) => file.write(line.as_bytes()),
        }
    }

    fn flush(&self) {}
}

struct LogFile {
    path: PathBuf,
    file: File,
    size: u64,
    /// 0: never rotate.
    max_size: u64,
    /// Rotated files kept: pivx-bridge.log.1 (newest) to .{keep}.
    keep: u32,
}

impl LogFile {
    fn open(path: PathBuf, max_size: u64, keep: u32) -> std::io::Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Self { path, file, size, max_size, keep })
    }

    fn write(&mut self, line: &[u8]) {
        if self.max_size > 0 && self.size > 0 && self.size + line.len() as u64 > self.max_size {
            if let Err(e) = self.rotate() {
                eprintln!("pivx-bridge: rotating {} failed: {e}", self.path.display());
            }
        }
        // Unbuffered: a line written is in the file even if the bridge dies.
        if self.file.write_all(line).is_ok() {
            self.size += line.len() as u64;
        }
    }

    /// pivx-bridge.log becomes .1, .1 becomes .2 and so on; the oldest
    /// past [keep] goes. With keep 0 the log just starts over.
    fn rotate(&mut self) -> std::io::Result<()> {
        if self.keep == 0 {
            self.file.set_len(0)?;
            self.size = 0;
            return Ok(());
        }
        let rotated = |n: u32| {
            let mut p = self.path.clone().into_os_string();
            p.push(format!(".{n}"));
            PathBuf::from(p)
        };
        let _ = std::fs::remove_file(rotated(self.keep));
        for n in (1..self.keep).rev() {
            let _ = std::fs::rename(rotated(n), rotated(n + 1));
        }
        std::fs::rename(&self.path, rotated(1))?;
        self.file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        self.size = 0;
        Ok(())
    }
}

/// `2026-10-16 13:53:29.123Z` for [secs] since 1970 (UTC).
fn utc(secs: u64, millis: u32) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem / 60 % 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0, 0), "1970-01-01 00:00:00.000Z");
        assert_eq!(utc(951_782_400, 5), "2000-02-29 00:00:00.005Z");
        assert_eq!(utc(1_792_157_609, 123), "2026-10-16 13:33:29.123Z");
        assert_eq!(utc(4_107_542_399, 999), "2100-02-28 23:59:59.999Z");
    }

    #[test]
    fn rotates_and_keeps_the_newest() {
        let dir = std::env::temp_dir().join(format!("pivx-bridge-log-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("b.log");
        let mut log = LogFile::open(path.clone(), 10, 2).unwrap();
        for line in ["aaaaaa\n", "bbbbbb\n", "cccccc\n", "dddddd\n"] {
            log.write(line.as_bytes());
        }
        let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap_or_default();
        assert_eq!(read("b.log"), "dddddd\n");
        assert_eq!(read("b.log.1"), "cccccc\n");
        assert_eq!(read("b.log.2"), "bbbbbb\n");
        assert!(!dir.join("b.log.3").exists());

        // Reopened, it carries on with the size already there.
        drop(log);
        let mut log = LogFile::open(path, 10, 0).unwrap();
        log.write(b"eeeeee\n");
        assert_eq!(read("b.log"), "eeeeee\n");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
