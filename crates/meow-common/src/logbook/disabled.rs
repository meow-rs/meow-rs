//! The store when built without the `logbook` feature (the `minimal`
//! bundle): a logbook cannot be opened, so none is ever installed and
//! recording does nothing.

use super::{Event, Level, Options, Page, Query, Stop};
use std::io;
use std::path::Path;
use std::time::SystemTime;

/// Never constructed.
pub enum Logbook {}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "built without the logbook feature",
    )
}

pub fn read(_dir: &Path, _query: &Query) -> io::Result<Page> {
    Err(unsupported())
}

impl Logbook {
    pub fn open(_dir: &Path, _options: Options) -> io::Result<Self> {
        Err(unsupported())
    }

    pub fn dir(&self) -> &Path {
        match *self {}
    }

    pub fn record(&self, _event: Event) {
        match *self {}
    }

    pub fn query(&self, _query: &Query) -> io::Result<Page> {
        match *self {}
    }

    pub fn clear(&self) {
        match *self {}
    }

    pub fn flush(&self) {
        match *self {}
    }

    pub fn latest_level(&self, _kind: &str, _subject: &str) -> Option<Level> {
        match *self {}
    }

    pub fn track_run(&self, _started: SystemTime, _now: SystemTime) {
        match *self {}
    }

    pub fn untrack_run(&self) {
        match *self {}
    }

    pub fn engine_started(&self, _config: &str, _now: SystemTime) {
        match *self {}
    }

    pub fn engine_stopped(&self, _stop: Stop<'_>, _now: SystemTime) {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use crate::logbook::{self, kind, Level, Options, Query, Stop};
    use std::io;

    #[test]
    fn nothing_is_recorded_without_the_feature() {
        let dir = std::env::temp_dir().join(format!("meow-logbook-off-{}", std::process::id()));
        let error = logbook::install(&dir, Options::default()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(!dir.exists(), "opening must not create the directory");
        logbook::apply(true);
        assert!(!logbook::enabled());
        logbook::event(kind::CONFIG_RELOAD, Level::Info, "Reloaded").record();
        assert!(logbook::query(&Query::default()).is_none());
        assert!(!logbook::failing(kind::CONFIG_RELOAD, ""));
        let error = logbook::read(&dir, &Query::default()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        logbook::clear();
        logbook::engine_started("config.yaml");
        logbook::engine_stopped(Stop::Requested("test"));
        logbook::uninstall();
    }
}
