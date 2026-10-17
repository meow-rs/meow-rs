//! Per-connection notes: a short, timestamped account of how the tunnel
//! handled one connection — the fake-IP reversal, each DNS lookup a rule
//! needed, the rule that matched, the dial, and how the relay ended.
//!
//! Notes answer "why did this connection take that route" for one flow,
//! without raising the process-wide log level or correlating log lines by
//! address. They are off by default: the tunnel creates a [`ConnNotes`] only
//! when its owner enables them, so the default path allocates nothing and
//! each note site costs one task-local probe.
//!
//! Recording goes through a task-local scope instead of parameters. The
//! tunnel runs a connection under [`ConnNotes::scope`], and code in other
//! crates — the DNS resolver, proxy adapters — adds notes with
//! [`conn_note!`](crate::conn_note) without threading a handle through its
//! signatures. The scope follows the connection's task: work spawned onto
//! another task does not inherit it, and a lookup that joins another
//! connection's in-flight query records only that it waited.

use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::time::SystemTime;

use parking_lot::Mutex;
use serde::ser::{SerializeMap, SerializeSeq, Serializer};
use serde::Serialize;

/// Most notes one connection keeps. Once full, each new note overwrites the
/// last slot, so the outcome (dial result, close reason) always survives;
/// the overwritten notes are counted and reported as omitted.
pub const MAX_NOTES: usize = 48;

/// Longest note text in bytes. Longer text is cut at a char boundary.
pub const MAX_NOTE_LEN: usize = 512;

/// What part of the connection's handling a note describes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NoteKind {
    /// The inbound flow: where it came from, the app that owns it, closing.
    Connection,
    /// Fake-IP reversal, hosts, cache and upstream lookups.
    Dns,
    /// Rule evaluation and the policy the flow ends up on.
    Rule,
    /// The outbound dial.
    Dial,
    /// The data phase after the dial.
    Relay,
}

impl NoteKind {
    /// Stable lower-case name used in the JSON `kind` field.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Connection => "connection",
            Self::Dns => "dns",
            Self::Rule => "rule",
            Self::Dial => "dial",
            Self::Relay => "relay",
        }
    }
}

struct Note {
    time: SystemTime,
    kind: NoteKind,
    text: Box<str>,
}

#[derive(Default)]
struct NoteLog {
    notes: Vec<Note>,
    omitted: u32,
}

/// Shared, bounded note log of one connection. Clones share the log: the
/// connection task appends while the API serializes it.
#[derive(Clone, Default)]
pub struct ConnNotes(Arc<Mutex<NoteLog>>);

tokio::task_local! {
    static CURRENT: ConnNotes;
}

impl ConnNotes {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append a note stamped with the current time.
    pub fn push(&self, kind: NoteKind, args: fmt::Arguments<'_>) {
        let time = SystemTime::now();
        // Format before locking: a reader serializing the log must not wait
        // on this connection's `Display` impls.
        let mut text = fmt::format(args);
        truncate_at_char_boundary(&mut text, MAX_NOTE_LEN);
        let note = Note {
            time,
            kind,
            text: text.into_boxed_str(),
        };
        let mut log = self.0.lock();
        if log.notes.len() < MAX_NOTES {
            log.notes.push(note);
        } else if let Some(last) = log.notes.last_mut() {
            *last = note;
            log.omitted += 1;
        }
    }

    /// Number of notes held, not counting omitted ones.
    pub fn len(&self) -> usize {
        self.0.lock().notes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The note texts in order, for tests and plain-text dumps.
    pub fn texts(&self) -> Vec<String> {
        self.0
            .lock()
            .notes
            .iter()
            .map(|note| note.text.to_string())
            .collect()
    }

    /// The notes of the connection running on this task, if it records any.
    /// An inbound that wants to note something before handing the flow to
    /// the tunnel opens the scope itself; the tunnel then keeps appending to
    /// that log instead of starting a new one.
    pub fn current() -> Option<Self> {
        CURRENT.try_with(Clone::clone).ok()
    }

    /// Run `fut` with `notes` as the current connection's notes. `None` runs
    /// it unchanged, so a disabled connection pays nothing per poll.
    pub async fn scope<F: Future>(notes: Option<Self>, fut: F) -> F::Output {
        match notes {
            Some(notes) => CURRENT.scope(notes, fut).await,
            None => fut.await,
        }
    }
}

impl fmt::Debug for ConnNotes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let log = self.0.lock();
        f.debug_struct("ConnNotes")
            .field("notes", &log.notes.len())
            .field("omitted", &log.omitted)
            .finish()
    }
}

/// Serializes as `[{"time", "kind", "text"}, …]`, `time` in RFC 3339 UTC
/// with microseconds. Omitted notes appear as one `connection` note just
/// before the last, which is the one that overwrote them.
impl Serialize for ConnNotes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let log = self.0.lock();
        let total = log.notes.len() + usize::from(log.omitted > 0);
        let mut seq = serializer.serialize_seq(Some(total))?;
        let last = log.notes.len().saturating_sub(1);
        for (i, note) in log.notes.iter().enumerate() {
            if i == last && log.omitted > 0 {
                let text = format!("{} more notes omitted", log.omitted);
                seq.serialize_element(&NoteJson {
                    time: note.time,
                    kind: NoteKind::Connection,
                    text: &text,
                })?;
            }
            seq.serialize_element(&NoteJson {
                time: note.time,
                kind: note.kind,
                text: &note.text,
            })?;
        }
        seq.end()
    }
}

struct NoteJson<'a> {
    time: SystemTime,
    kind: NoteKind,
    text: &'a str,
}

impl Serialize for NoteJson<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use time::format_description::well_known::Rfc3339;

        let time = time::OffsetDateTime::from(self.time);
        let time = time
            .replace_nanosecond(time.nanosecond() / 1_000 * 1_000)
            .unwrap_or(time);
        let time = time
            .format(&Rfc3339)
            .unwrap_or_else(|_| String::from("1970-01-01T00:00:00Z"));
        let mut map = serializer.serialize_map(Some(3))?;
        map.serialize_entry("time", &time)?;
        map.serialize_entry("kind", self.kind.as_str())?;
        map.serialize_entry("text", self.text)?;
        map.end()
    }
}

/// Whether this task is recording notes. Check it before computing an
/// expensive argument; [`conn_note!`](crate::conn_note) needs no guard.
pub fn recording() -> bool {
    CURRENT.try_with(|_| ()).is_ok()
}

/// Run `f` on the current connection's notes, if this task records any.
/// Prefer [`conn_note!`](crate::conn_note), which formats lazily.
pub fn with_current(f: impl FnOnce(&ConnNotes)) {
    let _ = CURRENT.try_with(f);
}

/// Add a note to the connection running on this task; a no-op when the task
/// records none. The arguments are evaluated only when it does.
///
/// ```ignore
/// meow_common::conn_note!(Dns, "{host} → {ip} in {} ms", elapsed.as_millis());
/// ```
#[macro_export]
macro_rules! conn_note {
    ($kind:ident, $($arg:tt)+) => {
        $crate::conn_notes::with_current(|notes| {
            notes.push(
                $crate::conn_notes::NoteKind::$kind,
                ::core::format_args!($($arg)+),
            )
        })
    };
}

fn truncate_at_char_boundary(text: &mut String, max: usize) {
    if text.len() <= max {
        return;
    }
    let mut end = max;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text.push('…');
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn notes_go_to_the_scoped_log_only() {
        let notes = ConnNotes::new();
        conn_note!(Dns, "outside any scope");
        ConnNotes::scope(Some(notes.clone()), async {
            assert!(recording());
            conn_note!(Rule, "matched {}", "MATCH");
        })
        .await;
        ConnNotes::scope(None, async {
            assert!(!recording());
            conn_note!(Rule, "disabled");
        })
        .await;
        assert_eq!(notes.texts(), ["matched MATCH"]);
    }

    #[tokio::test]
    async fn arguments_are_not_evaluated_without_a_scope() {
        let mut evaluated = false;
        let mut probe = || {
            evaluated = true;
            1
        };
        conn_note!(Dns, "{}", probe());
        assert!(!evaluated);
    }

    #[test]
    fn a_full_log_keeps_the_newest_note_and_counts_the_rest() {
        let notes = ConnNotes::new();
        for i in 0..MAX_NOTES + 3 {
            notes.push(NoteKind::Dns, format_args!("note {i}"));
        }
        let texts = notes.texts();
        assert_eq!(texts.len(), MAX_NOTES);
        assert_eq!(texts[MAX_NOTES - 2], format!("note {}", MAX_NOTES - 2));
        assert_eq!(texts[MAX_NOTES - 1], format!("note {}", MAX_NOTES + 2));

        let json = serde_json::to_value(&notes).unwrap();
        let array = json.as_array().unwrap();
        assert_eq!(array.len(), MAX_NOTES + 1);
        assert_eq!(array[MAX_NOTES - 1]["text"], "3 more notes omitted");
        assert_eq!(array[MAX_NOTES]["text"], format!("note {}", MAX_NOTES + 2));
    }

    #[test]
    fn serializes_kind_text_and_a_microsecond_utc_time() {
        let notes = ConnNotes::new();
        notes.push(NoteKind::Dial, format_args!("connected"));
        let json = serde_json::to_value(&notes).unwrap();
        let note = &json[0];
        assert_eq!(note["kind"], "dial");
        assert_eq!(note["text"], "connected");
        let time = note["time"].as_str().unwrap();
        assert!(time.ends_with('Z'), "{time}");
        if let Some((_, fraction)) = time.split_once('.') {
            assert!(fraction.len() <= "000000Z".len(), "{time}");
        }
    }

    #[test]
    fn long_text_is_cut_at_a_char_boundary() {
        let notes = ConnNotes::new();
        let long = "é".repeat(MAX_NOTE_LEN);
        notes.push(NoteKind::Dns, format_args!("{long}"));
        let text = &notes.texts()[0];
        assert!(text.len() <= MAX_NOTE_LEN + '…'.len_utf8());
        assert!(text.ends_with('…'));
    }
}
