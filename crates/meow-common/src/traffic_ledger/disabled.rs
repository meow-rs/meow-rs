//! The store when built without the `traffic-ledger` feature (the `minimal`
//! bundle): a ledger cannot be opened, so none is ever installed and
//! nothing is recorded.

use super::{Query, Report};
use std::io;
use std::path::Path;

/// Never constructed.
pub enum Ledger {}

fn unsupported() -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        "built without the traffic-ledger feature",
    )
}

pub fn read(_dir: &Path, _query: &Query) -> io::Result<Report> {
    Err(unsupported())
}

pub fn clear_at(_dir: &Path) -> io::Result<()> {
    Err(unsupported())
}

impl Ledger {
    pub fn open(_dir: &Path) -> io::Result<Self> {
        Err(unsupported())
    }

    pub fn dir(&self) -> &Path {
        match *self {}
    }

    pub fn flush(&self) {
        match *self {}
    }

    pub fn query(&self, _query: &Query) -> io::Result<Report> {
        match *self {}
    }

    pub fn nudge(&self) {
        match *self {}
    }

    pub fn clear(&self) -> io::Result<()> {
        match *self {}
    }
}

#[cfg(test)]
mod tests {
    use crate::traffic_ledger::{self, Options, Query};
    use std::io;

    #[test]
    fn nothing_is_recorded_without_the_feature() {
        let dir = std::env::temp_dir().join(format!("meow-traffic-off-{}", std::process::id()));
        let error = traffic_ledger::install(&dir, Options::default()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(!dir.exists(), "opening must not create the directory");
        assert!(!traffic_ledger::enabled());
        assert!(traffic_ledger::query(&Query::default()).is_none());
        let error = traffic_ledger::read(&dir, &Query::default()).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        traffic_ledger::clear().unwrap();
        traffic_ledger::flush();
        traffic_ledger::uninstall();
    }
}
