//! Hostname to backend resolution, swappable at runtime.
//!
//! The table used to be a `HashMap` field behind an `Arc`, which meant the only
//! method that could populate it took `&mut self` and was therefore unreachable
//! once the router was shared. Routing was implemented, tested, and impossible
//! to use.
//!
//! An [`arc_swap::ArcSwap`] fixes that: readers take a cheap atomic load, and a
//! reload publishes a whole new table in one store. Nothing is mutated in place,
//! so there is no lock on the connection path.

use arc_swap::ArcSwap;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use crate::config::{Config, Forwarding, WaitingStrategy, WakeCommand};

/// What the health checker last observed about a backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Health {
    /// Not probed yet.
    Unknown,
    /// Accepting connections.
    Up,
    /// Not accepting connections.
    Down,
    /// A wake command ran and we are waiting for it to come up.
    Starting,
}

impl Health {
    fn as_u8(self) -> u8 {
        match self {
            Health::Unknown => 0,
            Health::Up => 1,
            Health::Down => 2,
            Health::Starting => 3,
        }
    }

    fn from_u8(value: u8) -> Self {
        match value {
            1 => Health::Up,
            2 => Health::Down,
            3 => Health::Starting,
            _ => Health::Unknown,
        }
    }

    /// Whether a player can be routed here right now.
    pub fn accepts_players(self) -> bool {
        matches!(self, Health::Up | Health::Unknown)
    }
}

/// Shared, atomically updated health of one backend.
///
/// Cloning shares the state: the checker task holds one handle and the routing
/// table holds another, so a reload can hand the same cell to a rebuilt table.
#[derive(Debug, Clone)]
pub struct HealthCell(Arc<AtomicU8>);

impl HealthCell {
    pub fn new() -> Self {
        Self(Arc::new(AtomicU8::new(Health::Unknown.as_u8())))
    }

    pub fn get(&self) -> Health {
        Health::from_u8(self.0.load(Ordering::Relaxed))
    }

    pub fn set(&self, health: Health) {
        self.0.store(health.as_u8(), Ordering::Release);
    }
}

impl Default for HealthCell {
    fn default() -> Self {
        Self::new()
    }
}

/// One backend, resolved and ready to route to.
#[derive(Debug, Clone)]
pub struct BackendEntry {
    pub name: String,
    pub addr: String,
    /// Resolved from the `[wake.<name>]` block this backend referenced.
    pub wake: Option<WakeCommand>,
    /// Whether a player arriving is enough to trigger the wake command.
    pub wake_on_connect: bool,
    /// Ordered strategies for what a player sees while this backend starts.
    pub waiting: Vec<WaitingStrategy>,
    /// Waiting-room backend, already resolved against the proxy-wide default.
    pub limbo: Option<String>,
    /// How to tell this backend who the player is.
    pub forwarding: Forwarding,
    /// Whether to prepend an outbound PROXY v2 header when connecting to this backend.
    pub send_proxy_v2: bool,
    pub health: HealthCell,
}

impl BackendEntry {
    pub fn hibernates(&self) -> bool {
        self.wake.is_some()
    }

    /// Whether a player arriving here should trigger a wake.
    pub fn wakes_on_connect(&self) -> bool {
        self.hibernates() && self.wake_on_connect
    }
}

/// An immutable snapshot of the routing configuration.
#[derive(Debug)]
pub struct RoutingTable {
    entries: Vec<BackendEntry>,
    /// Lowercase hostname to index in `entries`.
    by_host: HashMap<String, usize>,
    default: usize,
}

impl RoutingTable {
    /// Builds a table from validated configuration.
    ///
    /// `previous` lets a reload carry health across: a backend whose name and
    /// address are unchanged keeps the cell its checker is already writing to,
    /// so reloading does not blank the panel or make a healthy backend look
    /// unknown until the next probe.
    pub fn from_config(config: &Config, previous: Option<&RoutingTable>) -> Self {
        let default_name = config.default_backend().name.clone();

        let entries: Vec<BackendEntry> = config
            .backends
            .iter()
            .map(|backend| {
                let health = previous
                    .and_then(|table| table.entry_by_name(&backend.name))
                    .filter(|existing| existing.addr == backend.addr)
                    .map(|existing| existing.health.clone())
                    .unwrap_or_default();

                BackendEntry {
                    name: backend.name.clone(),
                    addr: backend.addr.clone(),
                    wake: backend
                        .wake
                        .as_ref()
                        .and_then(|name| config.wake.get(name))
                        .cloned(),
                    wake_on_connect: backend.wake_on_connect,
                    waiting: backend.waiting.clone(),
                    limbo: backend
                        .limbo_for(config.proxy.limbo.as_deref())
                        .map(str::to_string),
                    forwarding: backend.forwarding,
                    send_proxy_v2: backend.send_proxy_v2,
                    health,
                }
            })
            .collect();

        let mut by_host = HashMap::new();
        for (index, backend) in config.backends.iter().enumerate() {
            for hostname in &backend.hostnames {
                by_host.insert(hostname.to_lowercase(), index);
            }
        }

        let default = entries
            .iter()
            .position(|entry| entry.name == default_name)
            .unwrap_or(0);

        Self {
            entries,
            by_host,
            default,
        }
    }

    /// Resolves a handshake hostname to a backend.
    ///
    /// The hostname is matched case-insensitively, and the port suffix a client
    /// may append is ignored. Anything unmatched lands on the default backend.
    pub fn resolve(&self, hostname: &str) -> &BackendEntry {
        let host = hostname
            .split(':')
            .next()
            .unwrap_or(hostname)
            .trim_end_matches('.')
            .to_lowercase();

        self.by_host
            .get(&host)
            .and_then(|index| self.entries.get(*index))
            .unwrap_or(&self.entries[self.default])
    }

    pub fn entry_by_name(&self, name: &str) -> Option<&BackendEntry> {
        self.entries.iter().find(|entry| entry.name == name)
    }

    pub fn entries(&self) -> &[BackendEntry] {
        &self.entries
    }

    pub fn default_entry(&self) -> &BackendEntry {
        &self.entries[self.default]
    }
}

/// The live routing table, replaced wholesale on reload.
#[derive(Debug, Clone)]
pub struct SharedRouting(Arc<ArcSwap<RoutingTable>>);

impl SharedRouting {
    pub fn new(table: RoutingTable) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(table)))
    }

    pub fn from_config(config: &Config) -> Self {
        Self::new(RoutingTable::from_config(config, None))
    }

    /// Takes a snapshot for the duration of one connection decision.
    pub fn load(&self) -> arc_swap::Guard<Arc<RoutingTable>> {
        self.0.load()
    }

    /// Publishes a new table built from `config`, carrying health forward.
    pub fn reload(&self, config: &Config) {
        let next = RoutingTable::from_config(config, Some(&self.0.load()));
        self.0.store(Arc::new(next));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Backend;

    fn config_with(backends: Vec<Backend>) -> Config {
        Config {
            backends,
            ..Default::default()
        }
    }

    fn sample() -> Config {
        let mut survival = Backend::new("survival", "127.0.0.1:25566");
        survival.hostnames = vec!["play.example.com".into(), "Survival.Example.COM".into()];
        survival.default = true;

        let mut creative = Backend::new("creative", "127.0.0.1:25567");
        creative.hostnames = vec!["creative.example.com".into()];

        config_with(vec![survival, creative])
    }

    #[test]
    fn test_hostname_routing_is_case_insensitive() {
        let table = RoutingTable::from_config(&sample(), None);

        assert_eq!(table.resolve("play.example.com").name, "survival");
        assert_eq!(table.resolve("PLAY.EXAMPLE.COM").name, "survival");
        assert_eq!(table.resolve("survival.example.com").name, "survival");
        assert_eq!(table.resolve("creative.example.com").name, "creative");
    }

    /// Clients append the port, and some append a trailing dot for the DNS root.
    #[test]
    fn test_port_suffix_and_trailing_dot_are_ignored() {
        let table = RoutingTable::from_config(&sample(), None);

        assert_eq!(table.resolve("creative.example.com:25565").name, "creative");
        assert_eq!(table.resolve("creative.example.com.").name, "creative");
    }

    #[test]
    fn test_unmatched_hostnames_fall_to_the_default() {
        let table = RoutingTable::from_config(&sample(), None);

        assert_eq!(table.resolve("nobody.example.com").name, "survival");
        assert_eq!(table.resolve("").name, "survival");
    }

    /// Regression: routing existed but could not be populated, because the only
    /// method that filled it took `&mut self` while the router lived behind an
    /// `Arc`. Publishing a new table has to work through a shared handle.
    #[test]
    fn test_a_reload_is_visible_through_a_shared_handle() {
        let routing = SharedRouting::from_config(&sample());
        assert_eq!(
            routing.load().resolve("creative.example.com").name,
            "creative"
        );

        let mut moved = Backend::new("creative", "10.0.0.9:25567");
        moved.hostnames = vec!["creative.example.com".into()];
        let mut kept = Backend::new("survival", "127.0.0.1:25566");
        kept.default = true;

        routing.reload(&config_with(vec![kept, moved]));

        let table = routing.load();
        assert_eq!(table.resolve("creative.example.com").addr, "10.0.0.9:25567");
    }

    /// A reload must not blank the panel: an unchanged backend keeps the cell
    /// its checker is already writing to.
    #[test]
    fn test_health_survives_a_reload_of_an_unchanged_backend() {
        let config = sample();
        let routing = SharedRouting::from_config(&config);
        routing
            .load()
            .entry_by_name("survival")
            .unwrap()
            .health
            .set(Health::Up);

        routing.reload(&config);

        assert_eq!(
            routing
                .load()
                .entry_by_name("survival")
                .unwrap()
                .health
                .get(),
            Health::Up
        );
    }

    /// A backend that moved is a different backend as far as health goes; its
    /// old state says nothing about the new address.
    #[test]
    fn test_health_resets_when_the_address_changes() {
        let routing = SharedRouting::from_config(&sample());
        routing
            .load()
            .entry_by_name("creative")
            .unwrap()
            .health
            .set(Health::Up);

        let mut moved = Backend::new("creative", "10.0.0.9:25567");
        moved.hostnames = vec!["creative.example.com".into()];
        let mut kept = Backend::new("survival", "127.0.0.1:25566");
        kept.default = true;
        routing.reload(&config_with(vec![kept, moved]));

        assert_eq!(
            routing
                .load()
                .entry_by_name("creative")
                .unwrap()
                .health
                .get(),
            Health::Unknown
        );
    }

    #[test]
    fn test_wake_commands_are_resolved_from_their_block() {
        let mut config = sample();
        config.wake.insert(
            "docker".to_string(),
            WakeCommand {
                command: "docker".into(),
                args: vec!["start".into(), "mc".into()],
                ready_timeout_secs: 60,
            },
        );
        config.backends[1].wake = Some("docker".to_string());

        let table = RoutingTable::from_config(&config, None);

        assert!(!table.entry_by_name("survival").unwrap().hibernates());
        let creative = table.entry_by_name("creative").unwrap();
        assert!(creative.hibernates());
        assert_eq!(creative.wake.as_ref().unwrap().command, "docker");
    }

    #[test]
    fn test_unknown_health_still_accepts_players() {
        // Refusing before the first probe would reject every player during the
        // first few seconds after startup.
        assert!(Health::Unknown.accepts_players());
        assert!(Health::Up.accepts_players());
        assert!(!Health::Down.accepts_players());
        assert!(!Health::Starting.accepts_players());
    }
}
