//! Declarative configuration: the single source of truth for topology.
//!
//! Backends, their addresses, the hostnames that route to them and the commands
//! that wake them all live in one TOML file. Nothing else defines them - the
//! admin panel edits this file rather than keeping a parallel copy, so there is
//! never a second answer to "where does `play.example.com` go".
//!
//! Wake commands are deliberately defined in their own `[wake.<name>]` blocks
//! and referenced by name. Backends are editable from the panel; the command
//! definitions are not, which keeps shell commands out of reach of the HTTP API.

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::time::Duration;

/// File consulted when no path is given.
pub const DEFAULT_CONFIG_PATH: &str = "obsidian.toml";

/// Backend used when the file declares none.
pub const DEFAULT_BACKEND_ADDR: &str = "127.0.0.1:25566";

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("Could not read {path}: {source}")]
    Read {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Could not write {path}: {source}")]
    Write {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("{path} is not valid TOML: {source}")]
    Syntax {
        path: String,
        #[source]
        source: Box<toml_edit::TomlError>,
    },

    #[error("{path} does not match the expected shape: {source}")]
    Shape {
        path: String,
        #[source]
        source: Box<toml_edit::de::Error>,
    },

    #[error("No backends are defined")]
    NoBackends,

    #[error("Backend name {name:?} is used more than once")]
    DuplicateBackend { name: String },

    #[error("Hostname {hostname:?} is claimed by both {first:?} and {second:?}")]
    DuplicateHostname {
        hostname: String,
        first: String,
        second: String,
    },

    #[error("Backends {first:?} and {second:?} are both marked default")]
    MultipleDefaults { first: String, second: String },

    #[error("Backend {backend:?} references wake command {wake:?}, which is not defined")]
    UnknownWakeCommand { backend: String, wake: String },

    #[error("Backend {backend:?} has an empty name")]
    EmptyBackendName { backend: String },

    #[error("{path} changed on disk since it was loaded")]
    StaleWrite { path: String },

    #[error("Backend {backend:?} names limbo {limbo:?}, which is not a declared backend")]
    UnknownLimbo { backend: String, limbo: String },

    #[error("Backend {backend:?} names itself as its own limbo")]
    SelfLimbo { backend: String },
}

/// The whole configuration file.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub proxy: ProxySection,

    #[serde(default)]
    pub web: WebSection,

    #[serde(default)]
    pub history: HistorySection,

    /// Written in the file as repeated `[[backend]]` tables.
    #[serde(default, rename = "backend")]
    pub backends: Vec<Backend>,

    /// Named command definitions, referenced by `Backend::wake`.
    #[serde(default)]
    pub wake: HashMap<String, WakeCommand>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxySection {
    /// Address the Java Edition listener binds.
    pub bind: String,
    /// Address the Bedrock RakNet listener binds.
    pub raknet_bind: String,
    /// Text shown in the server list.
    pub motd: String,
    /// Version label reported in the status response.
    pub version_name: String,
    /// Player cap reported in the status response.
    pub max_players: u32,
    /// Seconds a peer may take to finish negotiating before being dropped.
    pub negotiation_timeout_secs: u64,
    /// Backend used as a waiting room when one does not name its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limbo: Option<String>,

    /// How long a player held past login is kept before the proxy gives up.
    ///
    /// Separate from `negotiation_timeout_secs` on purpose: that one bounds a
    /// handshake, and a backend can take far longer to boot than any handshake
    /// should take.
    #[serde(default = "default_hold_budget_secs")]
    pub hold_budget_secs: u64,

    /// Log every relayed packet's direction, id and size.
    ///
    /// Diagnostic only, and noisy: one line per packet. It exists because
    /// packet ids in the Configuration state moved between protocol versions,
    /// and reading them off a real client and a real server is more reliable
    /// than working from a table.
    #[serde(default)]
    pub trace_packets: bool,

    /// Trusted reverse-proxy / edge IPs allowed to prepend a HAProxy PROXY
    /// protocol v1/v2 header. Empty by default so direct clients can never
    /// spoof their source address.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub trusted_proxies: Vec<std::net::IpAddr>,

    /// Maximum simultaneous TCP connections allowed from a single client IP
    /// (evaluated after PROXY protocol header resolution).
    #[serde(default = "default_max_connections_per_ip")]
    pub max_connections_per_ip: u32,

    /// Maximum login attempts allowed from a single client IP within a
    /// rolling 60-second window.
    #[serde(default = "default_max_logins_per_ip_per_minute")]
    pub max_logins_per_ip_per_minute: u32,

    /// Idle timeout in seconds for relayed Play-state connections.
    #[serde(default = "default_play_idle_timeout_secs")]
    pub play_idle_timeout_secs: u64,

    /// Environment variable holding the shared HMAC-SHA256 secret for
    /// `forwarding = "obsidian"`.
    #[serde(default = "default_forwarding_secret_env")]
    pub forwarding_secret_env: String,
}

impl Default for ProxySection {
    fn default() -> Self {
        Self {
            bind: "127.0.0.1:25565".to_string(),
            raknet_bind: "127.0.0.1:19132".to_string(),
            motd: "Obsidian Proxy".to_string(),
            version_name: "Obsidian".to_string(),
            max_players: 100,
            negotiation_timeout_secs: 30,
            limbo: None,
            hold_budget_secs: default_hold_budget_secs(),
            trace_packets: false,
            trusted_proxies: Vec::new(),
            max_connections_per_ip: default_max_connections_per_ip(),
            max_logins_per_ip_per_minute: default_max_logins_per_ip_per_minute(),
            play_idle_timeout_secs: default_play_idle_timeout_secs(),
            forwarding_secret_env: default_forwarding_secret_env(),
        }
    }
}

impl ProxySection {
    pub fn negotiation_timeout(&self) -> Duration {
        Duration::from_secs(self.negotiation_timeout_secs)
    }

    pub fn play_idle_timeout(&self) -> Duration {
        Duration::from_secs(self.play_idle_timeout_secs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WebSection {
    /// Whether the admin panel is served at all.
    pub enabled: bool,
    /// Address the panel binds.
    ///
    /// Loopback by default. The panel authenticates with a bearer token, but it
    /// can also rewrite this configuration file, so reaching it should require
    /// being on the machine unless the operator decides otherwise.
    pub bind: String,
}

impl Default for WebSection {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: "127.0.0.1:3000".to_string(),
        }
    }
}

/// Where the proxy records what it did.
///
/// This is history, never a source of truth: the file above decides topology.
/// Losing a row costs nothing, which is what lets recording stay off the hot
/// path entirely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HistorySection {
    pub enabled: bool,
    pub path: String,
}

impl Default for HistorySection {
    fn default() -> Self {
        Self {
            enabled: true,
            path: "obsidian.db".to_string(),
        }
    }
}

/// One backend server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Backend {
    /// Stable identifier, used in logs, history and the panel.
    pub name: String,
    /// Where the backend listens.
    pub addr: String,
    /// Hostnames routed here, matched case-insensitively.
    #[serde(default)]
    pub hostnames: Vec<String>,
    /// Whether connections with no matching hostname land here.
    #[serde(default)]
    pub default: bool,
    /// Name of a `[wake.<name>]` block, if this backend hibernates.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wake: Option<String>,

    /// Whether a player connecting is enough to trigger the wake command.
    ///
    /// False for backends something else starts - a cron job, another operator,
    /// an orchestrator. Those are woken only from the panel or the API, and a
    /// player arriving is told the server is unavailable rather than starting,
    /// because it is not.
    #[serde(default = "default_wake_on_connect")]
    pub wake_on_connect: bool,

    /// Ordered strategies for what the player sees while this backend starts.
    #[serde(default = "default_waiting")]
    pub waiting: Vec<WaitingStrategy>,

    /// Backend used as a waiting room, overriding `[proxy] limbo`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limbo: Option<String>,

    /// How to tell this backend who the player is.
    #[serde(default)]
    pub forwarding: Forwarding,

    /// Whether to prepend a binary HAProxy PROXY protocol v2 header carrying
    /// the real client SocketAddr when opening a TCP connection to this backend.
    #[serde(default)]
    pub send_proxy_v2: bool,
}

impl Backend {
    pub fn new(name: impl Into<String>, addr: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            addr: addr.into(),
            hostnames: Vec::new(),
            default: false,
            wake: None,
            wake_on_connect: default_wake_on_connect(),
            waiting: default_waiting(),
            limbo: None,
            forwarding: Forwarding::default(),
            send_proxy_v2: false,
        }
    }

    /// The limbo this backend should use, given the proxy-wide default.
    pub fn limbo_for<'a>(&'a self, fallback: Option<&'a str>) -> Option<&'a str> {
        self.limbo.as_deref().or(fallback)
    }
}

/// How the proxy tells a backend who the player really is.
///
/// Forwarding needs both sides configured, so the default is `None`: a backend
/// that was not set up for it should not be sent a payload it will not read.
/// Turning it on is a deliberate pair of changes, here and on the backend.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Forwarding {
    /// Send the hostname the client used and nothing else.
    ///
    /// The only thing vanilla, Forge and NeoForge understand. The backend sees
    /// the proxy's address and gives the player an offline UUID, so it must run
    /// with `online-mode=false` and be reachable only by the proxy.
    #[default]
    None,
    /// BungeeCord's legacy format: the real IP, UUID and profile properties
    /// appended to the hostname, separated by NUL bytes.
    ///
    /// Read by Spigot and Paper when `bungeecord: true` is set in spigot.yml.
    /// Anything else ignores it. It carries no proof it came from this proxy, so
    /// the backend must not be reachable from anywhere else.
    Bungeecord,
    /// Obsidian's self-owned HMAC-SHA256 + timestamp signed forwarding format:
    /// `host\0OBSIDIANv1\0ip\0uuid\0properties\0timestamp_secs\0hmac_hex`.
    Obsidian,
}

/// What a player sees while a hibernating backend starts.
///
/// Strategies are tried in the order declared and the first possible one wins;
/// each skips itself when it cannot apply. When none does, the player is turned
/// away with a plain "unavailable" - that refusal is the floor, not a strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WaitingStrategy {
    /// Send the player to a real waiting-room backend.
    ///
    /// Needs `limbo` to name a backend that is currently up. Leaving limbo costs
    /// a reconnect: seamless on clients new enough for the Transfer packet, a
    /// kick with a message on anything older.
    Limbo,
    /// Hold the player in the Configuration state with keep-alives until the
    /// backend answers, then let them straight in without reconnecting.
    ///
    /// Needs a client that has the Configuration state at all.
    Hold,
    /// Refuse, but say the server is starting and roughly how long it takes.
    Message,
}

impl WaitingStrategy {
    pub fn as_str(self) -> &'static str {
        match self {
            WaitingStrategy::Limbo => "limbo",
            WaitingStrategy::Hold => "hold",
            WaitingStrategy::Message => "message",
        }
    }
}

/// The strategies tried when a backend declares none of its own.
fn default_waiting() -> Vec<WaitingStrategy> {
    vec![
        WaitingStrategy::Limbo,
        WaitingStrategy::Hold,
        WaitingStrategy::Message,
    ]
}

fn default_hold_budget_secs() -> u64 {
    180
}

fn default_max_connections_per_ip() -> u32 {
    16
}

fn default_max_logins_per_ip_per_minute() -> u32 {
    30
}

fn default_play_idle_timeout_secs() -> u64 {
    120
}

fn default_forwarding_secret_env() -> String {
    "OBSIDIAN_FORWARDING_SECRET".to_string()
}

fn default_wake_on_connect() -> bool {
    true
}

/// A command that starts a hibernating backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WakeCommand {
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    /// How long to wait for the backend to become healthy after starting.
    #[serde(default = "default_ready_timeout_secs")]
    pub ready_timeout_secs: u64,
}

fn default_ready_timeout_secs() -> u64 {
    120
}

impl WakeCommand {
    pub fn ready_timeout(&self) -> Duration {
        Duration::from_secs(self.ready_timeout_secs)
    }
}

impl Config {
    /// Loads and validates the file at `path`, or returns a single-backend
    /// default when it does not exist.
    ///
    /// A missing file is not an error: the proxy stays runnable out of the box.
    /// A malformed one is, because silently falling back would hide the mistake.
    pub fn load_or_default(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        match std::fs::read_to_string(path) {
            Ok(text) => Self::parse(&text, &path.display().to_string()),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(Self::single_backend()),
            Err(source) => Err(ConfigError::Read {
                path: path.display().to_string(),
                source,
            }),
        }
    }

    /// The configuration used when no file is present.
    pub fn single_backend() -> Self {
        Self {
            backends: vec![Backend {
                name: "default".to_string(),
                addr: DEFAULT_BACKEND_ADDR.to_string(),
                default: true,
                ..Backend::new("default", DEFAULT_BACKEND_ADDR)
            }],
            ..Default::default()
        }
    }

    /// Parses and validates configuration text.
    pub fn parse(text: &str, path: &str) -> Result<Self, ConfigError> {
        let document =
            text.parse::<toml_edit::DocumentMut>()
                .map_err(|source| ConfigError::Syntax {
                    path: path.to_string(),
                    source: Box::new(source),
                })?;

        let config: Config =
            toml_edit::de::from_document(document).map_err(|source| ConfigError::Shape {
                path: path.to_string(),
                source: Box::new(source),
            })?;

        config.validate()?;
        Ok(config)
    }

    /// Rejects configurations that parse but cannot be served.
    ///
    /// Every check here is one that would otherwise surface as a confusing
    /// runtime behaviour: a hostname silently resolving to whichever backend was
    /// declared first, or a wake command that never runs because its name has a
    /// typo.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.backends.is_empty() {
            return Err(ConfigError::NoBackends);
        }

        let mut names: HashSet<&str> = HashSet::new();
        let mut hostnames: HashMap<String, &str> = HashMap::new();
        let mut default_backend: Option<&str> = None;

        for backend in &self.backends {
            if backend.name.trim().is_empty() {
                return Err(ConfigError::EmptyBackendName {
                    backend: backend.addr.clone(),
                });
            }

            if !names.insert(backend.name.as_str()) {
                return Err(ConfigError::DuplicateBackend {
                    name: backend.name.clone(),
                });
            }

            for hostname in &backend.hostnames {
                let key = hostname.to_lowercase();
                if let Some(first) = hostnames.get(&key) {
                    return Err(ConfigError::DuplicateHostname {
                        hostname: hostname.clone(),
                        first: (*first).to_string(),
                        second: backend.name.clone(),
                    });
                }
                hostnames.insert(key, backend.name.as_str());
            }

            if backend.default {
                if let Some(first) = default_backend {
                    return Err(ConfigError::MultipleDefaults {
                        first: first.to_string(),
                        second: backend.name.clone(),
                    });
                }
                default_backend = Some(backend.name.as_str());
            }

            if let Some(wake) = &backend.wake
                && !self.wake.contains_key(wake)
            {
                return Err(ConfigError::UnknownWakeCommand {
                    backend: backend.name.clone(),
                    wake: wake.clone(),
                });
            }
        }

        // Limbo references are checked after every name is known, so ordering in
        // the file does not matter.
        let declared = |name: &str| self.backends.iter().any(|entry| entry.name == name);

        if let Some(limbo) = &self.proxy.limbo
            && !declared(limbo)
        {
            return Err(ConfigError::UnknownLimbo {
                backend: "[proxy]".to_string(),
                limbo: limbo.clone(),
            });
        }

        for backend in &self.backends {
            let Some(limbo) = &backend.limbo else {
                continue;
            };

            if limbo == &backend.name {
                return Err(ConfigError::SelfLimbo {
                    backend: backend.name.clone(),
                });
            }
            if !declared(limbo) {
                return Err(ConfigError::UnknownLimbo {
                    backend: backend.name.clone(),
                    limbo: limbo.clone(),
                });
            }
        }

        Ok(())
    }

    /// The backend that takes connections with no matching hostname.
    ///
    /// When nothing is marked `default` the first declared backend takes the
    /// role, so a single-backend file needs no ceremony.
    pub fn default_backend(&self) -> &Backend {
        self.backends
            .iter()
            .find(|backend| backend.default)
            .or_else(|| self.backends.first())
            .expect("validate() guarantees at least one backend")
    }

    /// Looks a backend up by name.
    pub fn backend(&self, name: &str) -> Option<&Backend> {
        self.backends.iter().find(|backend| backend.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[proxy]
bind = "0.0.0.0:25565"
raknet_bind = "0.0.0.0:19132"
motd = "Test"
version_name = "Obsidian"
max_players = 42
negotiation_timeout_secs = 15

[web]
enabled = true
bind = "127.0.0.1:3000"

[[backend]]
name = "survival"
addr = "127.0.0.1:25566"
hostnames = ["play.example.com", "Survival.Example.com"]
default = true
wake = "docker-survival"

[[backend]]
name = "creative"
addr = "127.0.0.1:25567"
hostnames = ["creative.example.com"]

[wake.docker-survival]
command = "docker"
args = ["start", "mc-survival"]
ready_timeout_secs = 90
"#;

    #[test]
    fn test_sample_parses_and_validates() {
        let config = Config::parse(SAMPLE, "test.toml").expect("valid");

        assert_eq!(config.proxy.max_players, 42);
        assert_eq!(config.proxy.negotiation_timeout(), Duration::from_secs(15));
        assert_eq!(config.web.bind, "127.0.0.1:3000");
        assert_eq!(config.backends.len(), 2);
        assert_eq!(config.default_backend().name, "survival");

        let wake = config.wake.get("docker-survival").expect("wake block");
        assert_eq!(wake.command, "docker");
        assert_eq!(wake.ready_timeout(), Duration::from_secs(90));
    }

    /// The panel binds loopback unless told otherwise: it can rewrite this file,
    /// so reaching it should require being on the machine.
    #[test]
    fn test_web_defaults_to_loopback() {
        let config = Config::parse("[[backend]]\nname = \"a\"\naddr = \"1.2.3.4:1\"", "t").unwrap();
        assert_eq!(config.web.bind, "127.0.0.1:3000");
    }

    #[test]
    fn test_missing_file_yields_a_usable_single_backend() {
        let config = Config::load_or_default("definitely-not-here.toml").expect("default");
        config.validate().expect("the fallback must be valid");
        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.default_backend().addr, DEFAULT_BACKEND_ADDR);
    }

    #[test]
    fn test_first_backend_is_default_when_none_is_marked() {
        let text = r#"
[[backend]]
name = "a"
addr = "127.0.0.1:1"

[[backend]]
name = "b"
addr = "127.0.0.1:2"
"#;
        assert_eq!(
            Config::parse(text, "t").unwrap().default_backend().name,
            "a"
        );
    }

    #[test]
    fn test_duplicate_backend_names_are_refused() {
        let text = r#"
[[backend]]
name = "a"
addr = "127.0.0.1:1"

[[backend]]
name = "a"
addr = "127.0.0.1:2"
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::DuplicateBackend { .. })
        ));
    }

    /// Two backends claiming one hostname would otherwise resolve to whichever
    /// was declared first, which is a silent misroute.
    #[test]
    fn test_duplicate_hostnames_are_refused_across_case() {
        let text = r#"
[[backend]]
name = "a"
addr = "127.0.0.1:1"
hostnames = ["play.example.com"]

[[backend]]
name = "b"
addr = "127.0.0.1:2"
hostnames = ["PLAY.EXAMPLE.COM"]
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::DuplicateHostname { .. })
        ));
    }

    #[test]
    fn test_two_defaults_are_refused() {
        let text = r#"
[[backend]]
name = "a"
addr = "127.0.0.1:1"
default = true

[[backend]]
name = "b"
addr = "127.0.0.1:2"
default = true
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::MultipleDefaults { .. })
        ));
    }

    /// A typo in a wake reference would otherwise mean the backend simply never
    /// wakes, with nothing said about why.
    #[test]
    fn test_unknown_wake_reference_is_refused() {
        let text = r#"
[[backend]]
name = "a"
addr = "127.0.0.1:1"
wake = "typo"

[wake.correct]
command = "true"
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::UnknownWakeCommand { .. })
        ));
    }

    /// A section may name only the keys it wants to change; the rest come from
    /// the documented defaults. Requiring every key would make the file grow
    /// with settings nobody chose.
    #[test]
    fn test_partial_sections_fall_back_to_defaults() {
        let text = r#"
[proxy]
motd = "Just the motd"

[[backend]]
name = "a"
addr = "127.0.0.1:1"
"#;
        let config = Config::parse(text, "t").expect("valid");
        assert_eq!(config.proxy.motd, "Just the motd");
        assert_eq!(config.proxy.bind, ProxySection::default().bind);
        assert_eq!(
            config.proxy.max_players,
            ProxySection::default().max_players
        );
    }

    #[test]
    fn test_waiting_strategies_parse_and_default() {
        let text = r#"
[proxy]
limbo = "lobby"

[[backend]]
name = "lobby"
addr = "127.0.0.1:25599"

[[backend]]
name = "survival"
addr = "127.0.0.1:25566"
default = true
wake = "start"
wake_on_connect = false
waiting = ["hold", "message"]

[wake.start]
command = "true"
"#;
        let config = Config::parse(text, "t").expect("valid");

        let survival = config.backend("survival").unwrap();
        assert!(!survival.wake_on_connect);
        assert_eq!(
            survival.waiting,
            vec![WaitingStrategy::Hold, WaitingStrategy::Message]
        );

        // Nothing declared, so the documented order applies.
        let lobby = config.backend("lobby").unwrap();
        assert!(lobby.wake_on_connect);
        assert_eq!(lobby.waiting, default_waiting());
    }

    /// A backend falls back to the proxy-wide limbo, and overrides it when it
    /// names its own.
    #[test]
    fn test_limbo_falls_back_to_the_proxy_default() {
        let text = r#"
[proxy]
limbo = "lobby"

[[backend]]
name = "lobby"
addr = "127.0.0.1:25599"

[[backend]]
name = "hub"
addr = "127.0.0.1:25598"

[[backend]]
name = "survival"
addr = "127.0.0.1:25566"
default = true

[[backend]]
name = "creative"
addr = "127.0.0.1:25567"
limbo = "hub"
"#;
        let config = Config::parse(text, "t").expect("valid");
        let fallback = config.proxy.limbo.as_deref();

        assert_eq!(
            config.backend("survival").unwrap().limbo_for(fallback),
            Some("lobby")
        );
        assert_eq!(
            config.backend("creative").unwrap().limbo_for(fallback),
            Some("hub")
        );
    }

    /// A typo here would otherwise mean the waiting room silently never applies.
    #[test]
    fn test_an_unknown_limbo_is_refused() {
        let text = r#"
[[backend]]
name = "survival"
addr = "127.0.0.1:25566"
limbo = "typo"
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::UnknownLimbo { .. })
        ));
    }

    #[test]
    fn test_an_unknown_proxy_limbo_is_refused() {
        let text = r#"
[proxy]
limbo = "nowhere"

[[backend]]
name = "survival"
addr = "127.0.0.1:25566"
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::UnknownLimbo { .. })
        ));
    }

    #[test]
    fn test_a_backend_cannot_be_its_own_limbo() {
        let text = r#"
[[backend]]
name = "survival"
addr = "127.0.0.1:25566"
limbo = "survival"
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::SelfLimbo { .. })
        ));
    }

    #[test]
    fn test_an_unknown_waiting_strategy_is_refused() {
        let text = r#"
[[backend]]
name = "survival"
addr = "127.0.0.1:25566"
waiting = ["teleport"]
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::Shape { .. })
        ));
    }

    /// The shipped example has to stay valid. It is the first thing an operator
    /// copies, and a schema change that leaves it behind is a broken quickstart.
    #[test]
    fn test_the_shipped_example_parses_and_validates() {
        // From crates/obsidian-core to the workspace root.
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("obsidian.example.toml");

        let text = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("could not read {}: {e}", path.display()));

        let config = Config::parse(&text, "obsidian.example.toml")
            .unwrap_or_else(|e| panic!("the example must stay valid: {e}"));

        assert!(config.backends.len() >= 2);
        assert!(
            config.backends.iter().any(|b| b.limbo.is_some()),
            "the example should demonstrate a limbo"
        );
        assert!(
            config.backends.iter().any(|b| !b.wake_on_connect),
            "the example should demonstrate wake_on_connect = false"
        );
    }

    /// Forwarding needs both sides configured, so a backend that says nothing
    /// gets nothing sent. Defaulting it on would mean defaulting to a
    /// half-configured pair.
    #[test]
    fn test_forwarding_defaults_to_none_and_parses() {
        let text = r#"
[[backend]]
name = "vanilla"
addr = "127.0.0.1:25566"
default = true

[[backend]]
name = "paper"
addr = "127.0.0.1:25567"
forwarding = "bungeecord"
"#;
        let config = Config::parse(text, "t").expect("valid");

        assert_eq!(
            config.backend("vanilla").unwrap().forwarding,
            Forwarding::None
        );
        assert_eq!(
            config.backend("paper").unwrap().forwarding,
            Forwarding::Bungeecord
        );
    }

    #[test]
    fn test_an_unknown_forwarding_mode_is_refused() {
        let text = r#"
[[backend]]
name = "a"
addr = "127.0.0.1:1"
forwarding = "velocity"
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::Shape { .. })
        ));
    }

    #[test]
    fn test_a_file_with_no_backends_is_refused() {
        assert!(matches!(
            Config::parse("[proxy]\nmotd = \"x\"", "t"),
            Err(ConfigError::NoBackends)
        ));
    }

    /// Unknown keys are a typo, not something to ignore.
    #[test]
    fn test_unknown_keys_are_refused() {
        let text = r#"
[[backend]]
name = "a"
addr = "127.0.0.1:1"
hostname = ["typo-singular.example.com"]
"#;
        assert!(matches!(
            Config::parse(text, "t"),
            Err(ConfigError::Shape { .. })
        ));
    }

    #[test]
    fn test_malformed_toml_reports_a_syntax_error() {
        assert!(matches!(
            Config::parse("[[backend]\nname =", "t"),
            Err(ConfigError::Syntax { .. })
        ));
    }
}
