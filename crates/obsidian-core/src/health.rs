//! Per-backend health probing.
//!
//! The previous checker tracked one address and kept the result in a flag that
//! was moved into its own task, so nothing outside could ever read it. The
//! result is now written into the [`HealthCell`] the routing table holds, which
//! is what the router and the status response consult.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::task::JoinHandle;
use tokio::time;
use tracing::{debug, warn};

use crate::events::{Event, EventKind, EventSink};
use crate::routing::{Health, HealthCell, SharedRouting};

/// How often each backend is probed.
pub const DEFAULT_INTERVAL: Duration = Duration::from_secs(10);

/// How long a probe may take before the backend counts as down.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(5);

type ProbeKey = (String, String);

/// Owns one probing task per backend and reconciles them when the routing table changes.
///
/// Dropping the monitor stops the supervisor and every probe task.
#[derive(Debug)]
pub struct HealthMonitor {
    tasks: Arc<Mutex<HashMap<ProbeKey, JoinHandle<()>>>>,
    supervisor: JoinHandle<()>,
}

impl HealthMonitor {
    /// Starts one probe loop per backend in the current routing table and keeps
    /// reconciling against `routing` whenever backends are added, removed, or re-addressed.
    ///
    /// Transitions are recorded, steady state is not: a backend that has been up
    /// for a week should not fill the history with ten thousand identical rows.
    pub fn spawn(routing: &SharedRouting, interval: Duration, events: EventSink) -> Self {
        let tasks: Arc<Mutex<HashMap<ProbeKey, JoinHandle<()>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        reconcile_probes(routing, interval, &events, &tasks);

        let routing_clone = routing.clone();
        let tasks_clone = Arc::clone(&tasks);
        let events_clone = events.clone();
        let supervisor_tick = interval.min(Duration::from_secs(1));
        let supervisor = tokio::spawn(async move {
            let mut ticker = time::interval(supervisor_tick);
            ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
            loop {
                ticker.tick().await;
                reconcile_probes(&routing_clone, interval, &events_clone, &tasks_clone);
            }
        });

        Self { tasks, supervisor }
    }

    /// Number of backends being probed.
    pub fn len(&self) -> usize {
        self.tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn reconcile_probes(
    routing: &SharedRouting,
    interval: Duration,
    events: &EventSink,
    tasks: &Arc<Mutex<HashMap<ProbeKey, JoinHandle<()>>>>,
) {
    let table = routing.load();
    let mut guard = tasks
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    let desired: HashSet<ProbeKey> = table
        .entries()
        .iter()
        .map(|entry| (entry.name.clone(), entry.addr.clone()))
        .collect();

    guard.retain(|key, handle| {
        if desired.contains(key) {
            true
        } else {
            handle.abort();
            false
        }
    });

    for entry in table.entries() {
        let key = (entry.name.clone(), entry.addr.clone());
        guard.entry(key).or_insert_with(|| {
            tokio::spawn(probe_loop(
                entry.name.clone(),
                entry.addr.clone(),
                entry.health.clone(),
                interval,
                events.clone(),
            ))
        });
    }
}

impl Drop for HealthMonitor {
    fn drop(&mut self) {
        self.supervisor.abort();
        let guard = self
            .tasks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for task in guard.values() {
            task.abort();
        }
    }
}

/// Probes one backend until aborted.
///
/// A `Starting` backend is left alone: a wake command set that state, and only
/// a successful probe should clear it. Overwriting it with `Down` on the first
/// failed probe would make a booting server look dead.
async fn probe_loop(
    name: String,
    addr: String,
    cell: HealthCell,
    interval: Duration,
    events: EventSink,
) {
    let mut ticker = time::interval(interval);
    ticker.set_missed_tick_behavior(time::MissedTickBehavior::Delay);

    loop {
        ticker.tick().await;

        let reachable = matches!(
            time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(&addr)).await,
            Ok(Ok(_))
        );

        let previous = cell.get();
        match (reachable, previous) {
            (true, _) => {
                if previous != Health::Up {
                    debug!("Backend {} at {} is up", name, addr);
                    events.record(Event::for_backend(EventKind::BackendUp, &name));
                }
                cell.set(Health::Up);
            }
            (false, Health::Starting) => {
                debug!("Backend {} at {} is still starting", name, addr);
            }
            (false, _) => {
                if previous != Health::Down {
                    warn!("Backend {} at {} is unreachable", name, addr);
                    events.record(
                        Event::for_backend(EventKind::BackendDown, &name).with_detail(&addr),
                    );
                }
                cell.set(Health::Down);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Backend, Config};

    fn config_for(addr: &str) -> Config {
        let mut backend = Backend::new("probe-target", addr);
        backend.default = true;
        Config {
            backends: vec![backend],
            ..Default::default()
        }
    }

    /// Regression: the checker's result used to be unreachable, because the
    /// checker was moved into its own task. It has to land where the router
    /// reads it.
    #[tokio::test]
    async fn test_a_listening_backend_is_marked_up_in_the_routing_table() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });

        let routing = SharedRouting::from_config(&config_for(&addr));
        assert_eq!(
            routing.load().default_entry().health.get(),
            Health::Unknown,
            "nothing is known before the first probe"
        );

        let _monitor =
            HealthMonitor::spawn(&routing, Duration::from_millis(20), EventSink::disabled());

        for _ in 0..100 {
            if routing.load().default_entry().health.get() == Health::Up {
                return;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the backend never came up");
    }

    #[tokio::test]
    async fn test_an_unreachable_backend_is_marked_down() {
        // Port 1 on loopback refuses immediately on every platform we target.
        let routing = SharedRouting::from_config(&config_for("127.0.0.1:1"));
        let _monitor =
            HealthMonitor::spawn(&routing, Duration::from_millis(20), EventSink::disabled());

        for _ in 0..100 {
            if routing.load().default_entry().health.get() == Health::Down {
                return;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        panic!("the backend was never marked down");
    }

    /// A backend that a wake command just started must not be reported dead by
    /// the first probe that lands while it is still booting.
    #[tokio::test]
    async fn test_starting_is_not_overwritten_by_a_failed_probe() {
        let routing = SharedRouting::from_config(&config_for("127.0.0.1:1"));
        routing.load().default_entry().health.set(Health::Starting);

        let _monitor =
            HealthMonitor::spawn(&routing, Duration::from_millis(20), EventSink::disabled());
        time::sleep(Duration::from_millis(150)).await;

        assert_eq!(
            routing.load().default_entry().health.get(),
            Health::Starting
        );
    }

    #[tokio::test]
    async fn test_one_task_is_spawned_per_backend() {
        let mut config = config_for("127.0.0.1:1");
        config.backends.push(Backend::new("second", "127.0.0.1:2"));

        let routing = SharedRouting::from_config(&config);
        let monitor =
            HealthMonitor::spawn(&routing, Duration::from_secs(60), EventSink::disabled());
        assert_eq!(monitor.len(), 2);
    }

    #[tokio::test]
    async fn test_reloaded_backends_are_probed_dynamically() {
        let routing = SharedRouting::from_config(&config_for("127.0.0.1:1"));
        let monitor =
            HealthMonitor::spawn(&routing, Duration::from_millis(20), EventSink::disabled());
        assert_eq!(monitor.len(), 1);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let new_addr = listener.local_addr().unwrap().to_string();
        tokio::spawn(async move { while listener.accept().await.is_ok() {} });

        let mut updated = config_for("127.0.0.1:1");
        updated
            .backends
            .push(Backend::new("added-after-reload", &new_addr));
        routing.reload(&updated);

        for _ in 0..100 {
            let table = routing.load();
            if let Some(entry) = table.entry_by_name("added-after-reload")
                && entry.health.get() == Health::Up
            {
                assert_eq!(monitor.len(), 2);
                return;
            }
            time::sleep(Duration::from_millis(20)).await;
        }
        panic!("newly reloaded backend was never probed to Health::Up");
    }
}
