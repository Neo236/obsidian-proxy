//! Append-only history of what the proxy did.
//!
//! The database used to hold topology, which put it in competition with the
//! configuration file. It now holds only what happened: health transitions,
//! wakes, reloads. Nothing here is a source of truth, so losing a row costs
//! nothing.
//!
//! That property is what lets recording be free on the hot path. Producers hand
//! events to a bounded channel with a non-blocking send and move on; a dedicated
//! thread owns the connection and does the writing. A player's login never waits
//! on a disk.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{SyncSender, TrySendError, sync_channel};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// How many events may be queued before new ones are dropped.
const QUEUE_DEPTH: usize = 1024;

/// Events older than this are removed when the log is opened.
pub const RETENTION_DAYS: i64 = 30;

#[derive(Debug, thiserror::Error)]
pub enum EventError {
    #[error("Event database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("Event reader thread is unavailable")]
    Unavailable,
}

/// What happened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A backend started answering probes.
    BackendUp,
    /// A backend stopped answering probes.
    BackendDown,
    /// A wake command was run.
    WakeRequested,
    /// Configuration was reloaded or rewritten.
    ConfigApplied,
    /// A player was turned away.
    PlayerRefused,
}

impl EventKind {
    fn as_str(self) -> &'static str {
        match self {
            EventKind::BackendUp => "backend_up",
            EventKind::BackendDown => "backend_down",
            EventKind::WakeRequested => "wake_requested",
            EventKind::ConfigApplied => "config_applied",
            EventKind::PlayerRefused => "player_refused",
        }
    }

    fn from_str(value: &str) -> Option<Self> {
        Some(match value {
            "backend_up" => EventKind::BackendUp,
            "backend_down" => EventKind::BackendDown,
            "wake_requested" => EventKind::WakeRequested,
            "config_applied" => EventKind::ConfigApplied,
            "player_refused" => EventKind::PlayerRefused,
            _ => return None,
        })
    }
}

/// One recorded event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Event {
    /// Unix seconds.
    pub at: i64,
    /// Backend this concerns, if any. Proxy-wide events leave it unset.
    pub backend: Option<String>,
    pub kind: EventKind,
    pub detail: Option<String>,
}

impl Event {
    pub fn new(kind: EventKind) -> Self {
        Self {
            at: now_seconds(),
            backend: None,
            kind,
            detail: None,
        }
    }

    pub fn for_backend(kind: EventKind, backend: impl Into<String>) -> Self {
        Self {
            backend: Some(backend.into()),
            ..Self::new(kind)
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }
}

fn now_seconds() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// Handle producers use to record events.
///
/// Recording never blocks and never fails loudly: if the writer is behind, the
/// event is dropped and counted. History is worth less than latency.
#[derive(Debug, Clone)]
pub struct EventSink {
    tx: Option<SyncSender<Event>>,
    dropped: Arc<AtomicU64>,
}

impl EventSink {
    /// A sink that discards everything, for tests and for running without a
    /// database.
    pub fn disabled() -> Self {
        Self {
            tx: None,
            dropped: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn record(&self, event: Event) {
        let Some(tx) = &self.tx else { return };

        match tx.try_send(event) {
            Ok(()) => {}
            Err(TrySendError::Full(dropped)) => {
                let total = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
                // Only mention it occasionally: a flood of drops should not
                // become a flood of log lines.
                if total % 100 == 0 {
                    warn!(
                        "Event log is behind; dropped {} events (latest: {:?})",
                        total, dropped.kind
                    );
                }
            }
            Err(TrySendError::Disconnected(_)) => {
                self.dropped.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Number of events dropped because the writer could not keep up.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }
}

/// Owns the database: one connection on a writer thread, one for reads.
///
/// Two connections is what makes WAL mode meaningful. The previous single
/// connection behind a mutex serialised readers against writers, so the mode was
/// enabled but bought nothing.
pub struct EventLog {
    sink: EventSink,
    reader: std::sync::Mutex<Connection>,
}

impl EventLog {
    /// Opens the database, applies the schema, prunes old rows and starts the
    /// writer thread.
    pub fn open(path: &str) -> Result<Self, EventError> {
        let writer = Connection::open(path)?;
        writer.pragma_update(None, "journal_mode", "WAL")?;
        writer.pragma_update(None, "synchronous", "NORMAL")?;
        writer.execute(
            "CREATE TABLE IF NOT EXISTS events (
                id      INTEGER PRIMARY KEY,
                at      INTEGER NOT NULL,
                backend TEXT,
                kind    TEXT NOT NULL,
                detail  TEXT
            )",
            [],
        )?;
        writer.execute(
            "CREATE INDEX IF NOT EXISTS events_at ON events (at DESC)",
            [],
        )?;

        let cutoff = now_seconds() - RETENTION_DAYS * 86_400;
        let pruned = writer.execute("DELETE FROM events WHERE at < ?1", [cutoff])?;
        if pruned > 0 {
            debug!(
                "Pruned {} event(s) older than {} days",
                pruned, RETENTION_DAYS
            );
        }

        let reader = Connection::open(path)?;
        reader.pragma_update(None, "journal_mode", "WAL")?;

        let (tx, rx) = sync_channel::<Event>(QUEUE_DEPTH);

        // A plain thread, not a runtime task: this blocks on the channel and on
        // disk, and neither belongs on an async worker.
        std::thread::Builder::new()
            .name("obsidian-events".to_string())
            .spawn(move || {
                while let Ok(event) = rx.recv() {
                    if let Err(err) = writer.execute(
                        "INSERT INTO events (at, backend, kind, detail) VALUES (?1, ?2, ?3, ?4)",
                        rusqlite::params![
                            event.at,
                            event.backend,
                            event.kind.as_str(),
                            event.detail
                        ],
                    ) {
                        warn!("Could not record event: {}", err);
                    }
                }
                debug!("Event writer stopped");
            })
            .map_err(|_| EventError::Unavailable)?;

        Ok(Self {
            sink: EventSink {
                tx: Some(tx),
                dropped: Arc::new(AtomicU64::new(0)),
            },
            reader: std::sync::Mutex::new(reader),
        })
    }

    /// A handle producers can clone freely.
    pub fn sink(&self) -> EventSink {
        self.sink.clone()
    }

    /// The most recent events, newest first.
    pub fn recent(&self, limit: usize) -> Result<Vec<Event>, EventError> {
        let reader = self
            .reader
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        let mut statement = reader.prepare(
            "SELECT at, backend, kind, detail FROM events ORDER BY at DESC, id DESC LIMIT ?1",
        )?;

        let rows = statement.query_map([limit as i64], |row| {
            let kind: String = row.get(2)?;
            Ok(Event {
                at: row.get(0)?,
                backend: row.get(1)?,
                kind: EventKind::from_str(&kind).unwrap_or(EventKind::ConfigApplied),
                detail: row.get(3)?,
            })
        })?;

        rows.collect::<Result<Vec<_>, _>>()
            .map_err(EventError::from)
    }
}

impl std::fmt::Debug for EventLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EventLog").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicU32;

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn scratch_db() -> String {
        let dir = std::env::temp_dir().join(format!(
            "obsidian-events-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("events.db").display().to_string()
    }

    fn wait_for(log: &EventLog, count: usize) -> Vec<Event> {
        for _ in 0..200 {
            let events = log.recent(100).unwrap();
            if events.len() >= count {
                return events;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        panic!("expected {count} event(s), never arrived");
    }

    #[test]
    fn test_recorded_events_come_back_newest_first() {
        let log = EventLog::open(&scratch_db()).unwrap();
        let sink = log.sink();

        sink.record(Event::for_backend(EventKind::BackendDown, "survival"));
        sink.record(
            Event::for_backend(EventKind::WakeRequested, "survival").with_detail("docker start mc"),
        );

        let events = wait_for(&log, 2);
        assert_eq!(events[0].kind, EventKind::WakeRequested);
        assert_eq!(events[0].detail.as_deref(), Some("docker start mc"));
        assert_eq!(events[1].kind, EventKind::BackendDown);
        assert_eq!(events[1].backend.as_deref(), Some("survival"));
    }

    #[test]
    fn test_proxy_wide_events_have_no_backend() {
        let log = EventLog::open(&scratch_db()).unwrap();
        log.sink()
            .record(Event::new(EventKind::ConfigApplied).with_detail("2 backends"));

        let events = wait_for(&log, 1);
        assert!(events[0].backend.is_none());
        assert_eq!(events[0].detail.as_deref(), Some("2 backends"));
    }

    /// Recording must never block a caller, so a full queue drops. History is
    /// worth less than a player's latency.
    #[test]
    fn test_a_full_queue_drops_instead_of_blocking() {
        let sink = EventSink {
            tx: Some(sync_channel(1).0),
            dropped: Arc::new(AtomicU64::new(0)),
        };

        // Nothing is receiving, so everything past the buffer is dropped. The
        // point is that this returns rather than parking the thread.
        for _ in 0..50 {
            sink.record(Event::new(EventKind::BackendUp));
        }

        assert!(sink.dropped() >= 48, "dropped {}", sink.dropped());
    }

    #[test]
    fn test_a_disabled_sink_accepts_and_discards() {
        let sink = EventSink::disabled();
        sink.record(Event::new(EventKind::BackendUp));
        assert_eq!(sink.dropped(), 0);
    }

    #[test]
    fn test_history_survives_reopening() {
        let path = scratch_db();

        {
            let log = EventLog::open(&path).unwrap();
            log.sink()
                .record(Event::for_backend(EventKind::BackendUp, "survival"));
            wait_for(&log, 1);
        }

        let reopened = EventLog::open(&path).unwrap();
        let events = reopened.recent(10).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].backend.as_deref(), Some("survival"));
    }

    #[test]
    fn test_rows_past_the_retention_window_are_pruned_on_open() {
        let path = scratch_db();

        {
            let connection = Connection::open(&path).unwrap();
            connection
                .execute(
                    "CREATE TABLE IF NOT EXISTS events (
                        id      INTEGER PRIMARY KEY,
                        at      INTEGER NOT NULL,
                        backend TEXT,
                        kind    TEXT NOT NULL,
                        detail  TEXT
                    )",
                    [],
                )
                .unwrap();

            let ancient = now_seconds() - (RETENTION_DAYS + 1) * 86_400;
            connection
                .execute(
                    "INSERT INTO events (at, backend, kind, detail) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![ancient, "old", "backend_up", None::<String>],
                )
                .unwrap();
            connection
                .execute(
                    "INSERT INTO events (at, backend, kind, detail) VALUES (?1, ?2, ?3, ?4)",
                    rusqlite::params![now_seconds(), "fresh", "backend_up", None::<String>],
                )
                .unwrap();
        }

        let log = EventLog::open(&path).unwrap();
        let events = log.recent(10).unwrap();

        assert_eq!(events.len(), 1);
        assert_eq!(events[0].backend.as_deref(), Some("fresh"));
    }

    #[test]
    fn test_limit_is_honoured() {
        let log = EventLog::open(&scratch_db()).unwrap();
        for _ in 0..10 {
            log.sink().record(Event::new(EventKind::BackendUp));
        }
        wait_for(&log, 10);

        assert_eq!(log.recent(3).unwrap().len(), 3);
    }
}
