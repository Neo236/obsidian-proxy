//! Starting hibernating backends, and deciding what the player sees meanwhile.
//!
//! Scope note: the waiting strategies target clients that have the
//! Configuration state and the Transfer packet, which means 1.20.2 and newer.
//! Older clients fall through to a message or a refusal until that path has been
//! verified against a real client.

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::process::{Child, Command};
use tracing::{info, warn};

use crate::config::WaitingStrategy;
use crate::events::{Event, EventKind, EventSink};
use crate::routing::{BackendEntry, Health, RoutingTable};

/// First protocol version with the Configuration state, which is what makes
/// holding a player with keep-alives possible. Minecraft 1.20.2.
pub const PROTOCOL_CONFIGURATION: i32 = 764;

/// First protocol version with the Transfer packet, which lets a player leave
/// limbo without being kicked. Minecraft 1.20.5.
pub const PROTOCOL_TRANSFER: i32 = 766;

/// How a player would get out of limbo once the target backend is up.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimboExit {
    /// The client is told to reconnect and does so on its own.
    Transfer,
    /// The client is disconnected with a message asking it to reconnect.
    Kick,
}

/// What to do with a player whose backend is not accepting connections.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WaitingDecision {
    /// Route to a waiting-room backend while the target starts.
    Limbo { backend: String, exit: LimboExit },
    /// Hold in the Configuration state until the target answers.
    Hold,
    /// Refuse, saying the server is starting and roughly how long that takes.
    Starting { eta: Duration },
    /// Refuse, saying the server is unavailable.
    ///
    /// The floor, not a strategy: it is what happens when nothing else applies,
    /// and the only honest answer for a backend nothing is starting.
    Unavailable,
}

/// Chooses what a player sees while `target` is unavailable.
///
/// Pure, so the whole matrix of client version, configuration and limbo health
/// can be exercised without a network.
pub fn decide(
    table: &RoutingTable,
    target: &BackendEntry,
    protocol_version: i32,
) -> WaitingDecision {
    // Nothing is starting this backend, so nothing is going to change by
    // waiting. Saying "starting, try again" would be a lie.
    if !target.wakes_on_connect() {
        return WaitingDecision::Unavailable;
    }

    for strategy in &target.waiting {
        match strategy {
            WaitingStrategy::Limbo => {
                let Some(name) = &target.limbo else { continue };
                // A limbo that is itself down is no waiting room at all.
                let Some(entry) = table.entry_by_name(name) else {
                    continue;
                };
                if entry.health.get() != Health::Up {
                    continue;
                }

                return WaitingDecision::Limbo {
                    backend: name.clone(),
                    exit: if protocol_version >= PROTOCOL_TRANSFER {
                        LimboExit::Transfer
                    } else {
                        LimboExit::Kick
                    },
                };
            }
            WaitingStrategy::Hold => {
                if protocol_version >= PROTOCOL_CONFIGURATION {
                    return WaitingDecision::Hold;
                }
            }
            WaitingStrategy::Message => {
                return WaitingDecision::Starting {
                    eta: target
                        .wake
                        .as_ref()
                        .map(|wake| wake.ready_timeout())
                        .unwrap_or(Duration::from_secs(60)),
                };
            }
        }
    }

    WaitingDecision::Unavailable
}

/// Outcome of asking for a backend to be started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WakeOutcome {
    /// The command was spawned.
    Started,
    /// A wake for this backend is already in flight.
    AlreadyStarting,
    /// This backend declares no wake command.
    NoCommand,
    /// The command could not be spawned.
    Failed(String),
}

/// Tracks one wake per backend.
///
/// The previous manager held a single global flag, so waking one backend
/// blocked waking any other, and it dropped the child handle as soon as it
/// returned it - the process was never waited on.
pub struct WakeSupervisor {
    inner: Mutex<HashMap<String, InFlight>>,
    events: EventSink,
}

struct InFlight {
    child: Option<Child>,
    since: Instant,
    /// How long to keep considering this wake in flight before allowing a retry.
    patience: Duration,
}

impl WakeSupervisor {
    pub fn new(events: EventSink) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            events,
        }
    }

    /// Number of wakes currently considered in flight.
    pub fn in_flight(&self) -> usize {
        self.lock().len()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, InFlight>> {
        self.inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Starts `entry`'s backend unless a wake is already in flight for it.
    ///
    /// Marks the backend as `Starting` so the health monitor does not report it
    /// dead while it boots.
    pub fn wake(&self, entry: &BackendEntry) -> WakeOutcome {
        let Some(command) = &entry.wake else {
            return WakeOutcome::NoCommand;
        };

        {
            let mut in_flight = self.lock();

            if let Some(existing) = in_flight.get_mut(&entry.name) {
                // Reap first: a command that exited is no longer in flight, so a
                // failed start does not block retries until patience runs out.
                let finished = existing
                    .child
                    .as_mut()
                    .is_some_and(|child| matches!(child.try_wait(), Ok(Some(_)) | Err(_)));

                if !finished && existing.since.elapsed() < existing.patience {
                    return WakeOutcome::AlreadyStarting;
                }
                in_flight.remove(&entry.name);
            }
        }

        info!(
            "Waking backend {} with `{} {}`",
            entry.name,
            command.command,
            command.args.join(" ")
        );

        let spawned = Command::new(&command.command)
            .args(&command.args)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(false)
            .spawn();

        match spawned {
            Ok(child) => {
                entry.health.set(Health::Starting);
                self.lock().insert(
                    entry.name.clone(),
                    InFlight {
                        child: Some(child),
                        since: Instant::now(),
                        patience: command.ready_timeout(),
                    },
                );
                self.events.record(
                    Event::for_backend(EventKind::WakeRequested, &entry.name).with_detail(format!(
                        "{} {}",
                        command.command,
                        command.args.join(" ")
                    )),
                );
                WakeOutcome::Started
            }
            Err(err) => {
                warn!("Could not start backend {}: {}", entry.name, err);
                WakeOutcome::Failed(err.to_string())
            }
        }
    }

    /// Forgets a backend's in-flight wake, so the next request starts fresh.
    pub fn clear(&self, backend: &str) {
        self.lock().remove(backend);
    }
}

impl std::fmt::Debug for WakeSupervisor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WakeSupervisor")
            .field("in_flight", &self.in_flight())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Backend, Config, WakeCommand};
    use crate::routing::RoutingTable;

    fn wake_command() -> WakeCommand {
        WakeCommand {
            // A command that exists on both platforms we build for and exits at
            // once, so the supervisor has something real to reap.
            command: if cfg!(windows) { "cmd" } else { "true" }.to_string(),
            args: if cfg!(windows) {
                vec!["/C".to_string(), "exit".to_string()]
            } else {
                Vec::new()
            },
            ready_timeout_secs: 90,
        }
    }

    /// survival hibernates and names lobby as its limbo; lobby is a plain
    /// backend that is up.
    fn table_with(waiting: Vec<WaitingStrategy>, wake_on_connect: bool) -> RoutingTable {
        let mut survival = Backend::new("survival", "127.0.0.1:25566");
        survival.default = true;
        survival.wake = Some("start".to_string());
        survival.wake_on_connect = wake_on_connect;
        survival.waiting = waiting;
        survival.limbo = Some("lobby".to_string());

        let lobby = Backend::new("lobby", "127.0.0.1:25599");

        let mut config = Config {
            backends: vec![survival, lobby],
            ..Default::default()
        };
        config.wake.insert("start".to_string(), wake_command());

        let table = RoutingTable::from_config(&config, None);
        table.entry_by_name("lobby").unwrap().health.set(Health::Up);
        table
    }

    fn target(table: &RoutingTable) -> &BackendEntry {
        table.entry_by_name("survival").unwrap()
    }

    #[test]
    fn test_limbo_wins_when_it_is_up() {
        let table = table_with(Backend::new("", "").waiting, true);
        assert_eq!(
            decide(&table, target(&table), PROTOCOL_TRANSFER),
            WaitingDecision::Limbo {
                backend: "lobby".to_string(),
                exit: LimboExit::Transfer,
            }
        );
    }

    /// Leaving limbo is a kick on clients without the Transfer packet, which is
    /// the whole reason the order is configurable.
    #[test]
    fn test_limbo_exit_depends_on_the_client_version() {
        let table = table_with(Backend::new("", "").waiting, true);
        assert_eq!(
            decide(&table, target(&table), PROTOCOL_CONFIGURATION),
            WaitingDecision::Limbo {
                backend: "lobby".to_string(),
                exit: LimboExit::Kick,
            }
        );
    }

    /// A waiting room that is itself down is no waiting room.
    #[test]
    fn test_a_down_limbo_is_skipped() {
        let table = table_with(Backend::new("", "").waiting, true);
        table
            .entry_by_name("lobby")
            .unwrap()
            .health
            .set(Health::Down);

        assert_eq!(
            decide(&table, target(&table), PROTOCOL_TRANSFER),
            WaitingDecision::Hold
        );
    }

    #[test]
    fn test_hold_is_skipped_for_clients_without_configuration_state() {
        let table = table_with(vec![WaitingStrategy::Hold, WaitingStrategy::Message], true);

        assert_eq!(
            decide(&table, target(&table), PROTOCOL_CONFIGURATION),
            WaitingDecision::Hold
        );
        assert_eq!(
            decide(&table, target(&table), PROTOCOL_CONFIGURATION - 1),
            WaitingDecision::Starting {
                eta: Duration::from_secs(90)
            }
        );
    }

    #[test]
    fn test_an_empty_strategy_list_refuses() {
        let table = table_with(Vec::new(), true);
        assert_eq!(
            decide(&table, target(&table), PROTOCOL_TRANSFER),
            WaitingDecision::Unavailable
        );
    }

    /// A backend something else starts is unavailable, not starting. Telling a
    /// player to retry in thirty seconds when nothing is booting is a lie.
    #[test]
    fn test_a_backend_that_does_not_wake_on_connect_is_unavailable() {
        let table = table_with(Backend::new("", "").waiting, false);
        assert_eq!(
            decide(&table, target(&table), PROTOCOL_TRANSFER),
            WaitingDecision::Unavailable
        );
    }

    #[test]
    fn test_only_message_configured_gives_the_eta_from_the_wake_command() {
        let table = table_with(vec![WaitingStrategy::Message], true);
        assert_eq!(
            decide(&table, target(&table), PROTOCOL_TRANSFER),
            WaitingDecision::Starting {
                eta: Duration::from_secs(90)
            }
        );
    }

    #[tokio::test]
    async fn test_waking_marks_the_backend_as_starting() {
        let table = table_with(Backend::new("", "").waiting, true);
        let supervisor = WakeSupervisor::new(EventSink::disabled());

        assert_eq!(supervisor.wake(target(&table)), WakeOutcome::Started);
        assert_eq!(target(&table).health.get(), Health::Starting);
        assert_eq!(supervisor.in_flight(), 1);
    }

    /// Regression: the old manager held one global flag, so a second backend
    /// could not be woken while the first was starting.
    #[tokio::test]
    async fn test_two_backends_can_be_starting_at_once() {
        let table = table_with(Backend::new("", "").waiting, true);
        let supervisor = WakeSupervisor::new(EventSink::disabled());

        // Give lobby a wake command too, so both are wakeable.
        let mut lobby = Backend::new("lobby", "127.0.0.1:25599");
        lobby.wake = Some("start".to_string());
        let mut config = Config {
            backends: vec![lobby],
            ..Default::default()
        };
        config.wake.insert("start".to_string(), wake_command());
        let other = RoutingTable::from_config(&config, None);

        assert_eq!(supervisor.wake(target(&table)), WakeOutcome::Started);
        assert_eq!(
            supervisor.wake(other.entry_by_name("lobby").unwrap()),
            WakeOutcome::Started
        );
        assert_eq!(supervisor.in_flight(), 2);
    }

    #[tokio::test]
    async fn test_a_backend_without_a_command_is_not_woken() {
        let mut plain = Backend::new("plain", "127.0.0.1:25566");
        plain.default = true;
        let config = Config {
            backends: vec![plain],
            ..Default::default()
        };
        let table = RoutingTable::from_config(&config, None);

        let supervisor = WakeSupervisor::new(EventSink::disabled());
        assert_eq!(
            supervisor.wake(table.entry_by_name("plain").unwrap()),
            WakeOutcome::NoCommand
        );
        assert_eq!(supervisor.in_flight(), 0);
    }

    #[tokio::test]
    async fn test_a_missing_command_reports_failure_without_marking_starting() {
        let mut backend = Backend::new("broken", "127.0.0.1:25566");
        backend.default = true;
        backend.wake = Some("start".to_string());
        let mut config = Config {
            backends: vec![backend],
            ..Default::default()
        };
        config.wake.insert(
            "start".to_string(),
            WakeCommand {
                command: "obsidian-no-such-binary".to_string(),
                args: Vec::new(),
                ready_timeout_secs: 30,
            },
        );
        let table = RoutingTable::from_config(&config, None);
        let entry = table.entry_by_name("broken").unwrap();

        let supervisor = WakeSupervisor::new(EventSink::disabled());
        assert!(matches!(supervisor.wake(entry), WakeOutcome::Failed(_)));
        assert_eq!(entry.health.get(), Health::Unknown);
    }

    #[tokio::test]
    async fn test_clearing_lets_a_wake_be_requested_again() {
        let table = table_with(Backend::new("", "").waiting, true);
        let supervisor = WakeSupervisor::new(EventSink::disabled());

        assert_eq!(supervisor.wake(target(&table)), WakeOutcome::Started);
        supervisor.clear("survival");
        assert_eq!(supervisor.wake(target(&table)), WakeOutcome::Started);
    }
}
