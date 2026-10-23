//! Reading and rewriting the configuration file in place.
//!
//! Edits are surgical: the `[[backend]]` array is replaced and everything else
//! in the document - the `[proxy]` and `[web]` sections, the `[wake.*]` blocks,
//! and every comment around them - is carried through untouched. That is why
//! this uses `toml_edit` rather than serialising a [`Config`] back out, which
//! would discard comments and reorder keys.
//!
//! Per-backend comments are the one thing not preserved, since that array is
//! rebuilt from the values given.

use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::config::{Backend, Config, ConfigError};

/// Owns the parsed document and knows what was last on disk.
pub struct ConfigStore {
    path: PathBuf,
    inner: Mutex<StoreState>,
}

struct StoreState {
    document: toml_edit::DocumentMut,
    /// Hash of the file text as last read or written, used to notice edits made
    /// outside this process.
    fingerprint: u64,
}

fn fingerprint(text: &str) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    text.hash(&mut hasher);
    hasher.finish()
}

impl ConfigStore {
    /// Opens the file, returning the store and the configuration it holds.
    ///
    /// A missing file yields the default configuration and an empty document,
    /// so the first edit from the panel creates it.
    pub fn open(path: impl Into<PathBuf>) -> Result<(Self, Config), ConfigError> {
        let path = path.into();
        let display = path.display().to_string();

        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(source) => {
                return Err(ConfigError::Read {
                    path: display,
                    source,
                });
            }
        };

        let document =
            text.parse::<toml_edit::DocumentMut>()
                .map_err(|source| ConfigError::Syntax {
                    path: display.clone(),
                    source: Box::new(source),
                })?;

        let config = if text.trim().is_empty() {
            Config::single_backend()
        } else {
            Config::parse(&text, &display)?
        };

        let store = Self {
            path,
            inner: Mutex::new(StoreState {
                document,
                fingerprint: fingerprint(&text),
            }),
        };

        Ok((store, config))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Re-reads the file from disk, validates it, and updates the stored
    /// document and fingerprint so subsequent panel saves succeed after a
    /// manual edit on disk.
    pub fn reload_from_disk(&self) -> Result<Config, ConfigError> {
        let display = self.path.display().to_string();
        let text = match std::fs::read_to_string(&self.path) {
            Ok(text) => text,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
            Err(source) => {
                return Err(ConfigError::Read {
                    path: display,
                    source,
                });
            }
        };

        let document =
            text.parse::<toml_edit::DocumentMut>()
                .map_err(|source| ConfigError::Syntax {
                    path: display.clone(),
                    source: Box::new(source),
                })?;

        let config = if text.trim().is_empty() {
            Config::single_backend()
        } else {
            Config::parse(&text, &display)?
        };

        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.document = document;
        state.fingerprint = fingerprint(&text);
        Ok(config)
    }

    /// Replaces the declared backends, validating before anything is written.
    ///
    /// Fails with [`ConfigError::StaleWrite`] when the file changed on disk
    /// since it was last read, so an edit from the panel never silently
    /// overwrites one made in an editor.
    pub fn replace_backends(&self, backends: Vec<Backend>) -> Result<Config, ConfigError> {
        let display = self.path.display().to_string();
        let mut state = self
            .inner
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());

        // Compare against what is on disk right now, not what we last wrote.
        match std::fs::read_to_string(&self.path) {
            Ok(current) if fingerprint(&current) != state.fingerprint => {
                return Err(ConfigError::StaleWrite { path: display });
            }
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ConfigError::Read {
                    path: display,
                    source,
                });
            }
        }

        let mut document = state.document.clone();
        document["backend"] = toml_edit::Item::ArrayOfTables(backend_tables(&backends));

        let text = document.to_string();

        // Parse and validate the rendered document before it reaches the disk,
        // so a rejected edit leaves the file exactly as it was.
        let config = Config::parse(&text, &display)?;

        write_atomically(&self.path, &text)?;

        state.fingerprint = fingerprint(&text);
        state.document = document;
        Ok(config)
    }
}

impl std::fmt::Debug for ConfigStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ConfigStore")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn backend_tables(backends: &[Backend]) -> toml_edit::ArrayOfTables {
    use toml_edit::{Array, Table, value};

    let mut tables = toml_edit::ArrayOfTables::new();
    for backend in backends {
        let mut table = Table::new();
        table["name"] = value(backend.name.as_str());
        table["addr"] = value(backend.addr.as_str());

        if !backend.hostnames.is_empty() {
            let mut hostnames = Array::new();
            for hostname in &backend.hostnames {
                hostnames.push(hostname.as_str());
            }
            table["hostnames"] = value(hostnames);
        }
        if backend.default {
            table["default"] = value(true);
        }
        if let Some(wake) = &backend.wake {
            table["wake"] = value(wake.as_str());
        }
        // Only written when they differ from the default, so a file edited
        // through the panel does not fill up with settings nobody chose. They
        // still have to be written at all, or saving would silently reset them.
        if !backend.wake_on_connect {
            table["wake_on_connect"] = value(false);
        }
        if backend.waiting != crate::config::Backend::new("", "").waiting {
            let mut waiting = Array::new();
            for strategy in &backend.waiting {
                waiting.push(strategy.as_str());
            }
            table["waiting"] = value(waiting);
        }
        if let Some(limbo) = &backend.limbo {
            table["limbo"] = value(limbo.as_str());
        }
        if backend.forwarding != crate::config::Forwarding::default() {
            table["forwarding"] = value(match backend.forwarding {
                crate::config::Forwarding::None => "none",
                crate::config::Forwarding::Bungeecord => "bungeecord",
                crate::config::Forwarding::Obsidian => "obsidian",
            });
        }
        if backend.send_proxy_v2 {
            table["send_proxy_v2"] = value(true);
        }

        tables.push(table);
    }
    tables
}

/// Writes through a temporary file in the same directory, then renames.
///
/// A truncating write that fails midway leaves the proxy with a configuration
/// file it cannot parse. A rename either happens or it does not.
fn write_atomically(path: &Path, text: &str) -> Result<(), ConfigError> {
    let display = path.display().to_string();
    let temporary = path.with_extension("toml.tmp");

    std::fs::write(&temporary, text).map_err(|source| ConfigError::Write {
        path: temporary.display().to_string(),
        source,
    })?;

    std::fs::rename(&temporary, path).map_err(|source| ConfigError::Write {
        path: display,
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    static COUNTER: AtomicU32 = AtomicU32::new(0);

    fn scratch_file(label: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "obsidian-config-store-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(format!("{label}.toml"))
    }

    fn with_comments() -> String {
        [
            "# Top of file comment.",
            "",
            "[proxy]",
            "# Which port players connect to.",
            "bind = \"0.0.0.0:25565\"",
            "motd = \"Kept\"",
            "",
            "[[backend]]",
            "name = \"survival\"",
            "addr = \"127.0.0.1:25566\"",
            "default = true",
            "",
            "[wake.docker]",
            "command = \"docker\"",
            "args = [\"start\", \"mc\"]",
            "",
        ]
        .join("\n")
    }

    /// The panel edits one array. Everything an operator wrote around it -
    /// sections, ordering, comments - has to survive.
    #[test]
    fn test_editing_backends_preserves_the_rest_of_the_document() {
        let path = scratch_file("preserve");
        std::fs::write(&path, with_comments()).unwrap();

        let (store, _) = ConfigStore::open(&path).unwrap();
        store
            .replace_backends(vec![
                Backend {
                    hostnames: vec!["play.example.com".into()],
                    default: true,
                    ..Backend::new("survival", "10.0.0.2:25566")
                },
                Backend::new("creative", "10.0.0.3:25567"),
            ])
            .unwrap();

        let written = std::fs::read_to_string(&path).unwrap();

        assert!(written.contains("# Top of file comment."));
        assert!(written.contains("# Which port players connect to."));
        assert!(written.contains("motd = \"Kept\""));
        assert!(written.contains("[wake.docker]"));
        assert!(written.contains("10.0.0.2:25566"));
        assert!(written.contains("creative"));

        let reloaded = Config::parse(&written, "written").unwrap();
        assert_eq!(reloaded.backends.len(), 2);
        assert_eq!(reloaded.proxy.motd, "Kept");
        assert!(reloaded.wake.contains_key("docker"));
    }

    /// An edit made in an editor must not be silently overwritten by the panel.
    #[test]
    fn test_an_outside_edit_makes_the_write_stale() {
        let path = scratch_file("stale");
        std::fs::write(&path, with_comments()).unwrap();

        let (store, _) = ConfigStore::open(&path).unwrap();
        std::fs::write(&path, with_comments().replace("Kept", "Changed by hand")).unwrap();

        let err = store
            .replace_backends(vec![Backend::new("survival", "10.0.0.2:25566")])
            .unwrap_err();
        assert!(matches!(err, ConfigError::StaleWrite { .. }), "{err}");

        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("Changed by hand"),
            "the manual edit must survive"
        );
    }

    /// A rejected edit leaves the file exactly as it was.
    #[test]
    fn test_an_invalid_edit_is_refused_before_touching_the_file() {
        let path = scratch_file("invalid");
        std::fs::write(&path, with_comments()).unwrap();

        let (store, _) = ConfigStore::open(&path).unwrap();

        let err = store
            .replace_backends(vec![
                Backend::new("same", "10.0.0.2:1"),
                Backend::new("same", "10.0.0.3:2"),
            ])
            .unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateBackend { .. }), "{err}");

        assert_eq!(std::fs::read_to_string(&path).unwrap(), with_comments());
    }

    #[test]
    fn test_two_writes_in_a_row_are_accepted() {
        let path = scratch_file("sequential");
        std::fs::write(&path, with_comments()).unwrap();

        let (store, _) = ConfigStore::open(&path).unwrap();
        store
            .replace_backends(vec![Backend::new("a", "10.0.0.1:1")])
            .unwrap();
        let config = store
            .replace_backends(vec![Backend::new("b", "10.0.0.2:2")])
            .unwrap();

        assert_eq!(config.backends.len(), 1);
        assert_eq!(config.backends[0].name, "b");
    }

    #[test]
    fn test_a_missing_file_is_created_by_the_first_edit() {
        let path = scratch_file("created");
        let _ = std::fs::remove_file(&path);

        let (store, config) = ConfigStore::open(&path).unwrap();
        assert_eq!(config.backends.len(), 1, "defaults are usable right away");

        store
            .replace_backends(vec![Backend::new("only", "10.0.0.1:25565")])
            .unwrap();

        assert!(std::fs::read_to_string(&path).unwrap().contains("only"));
    }

    /// A save from the panel must not quietly reset settings it does not show.
    #[test]
    fn test_saving_preserves_waiting_settings() {
        use crate::config::WaitingStrategy;

        let path = scratch_file("waiting");
        std::fs::write(
            &path,
            [
                "[[backend]]",
                "name = \"lobby\"",
                "addr = \"127.0.0.1:25599\"",
                "",
                "[wake.start]",
                "command = \"true\"",
                "",
            ]
            .join(
                "
",
            ),
        )
        .unwrap();

        let (store, _) = ConfigStore::open(&path).unwrap();

        let mut survival = Backend::new("survival", "127.0.0.1:25566");
        survival.default = true;
        survival.wake = Some("start".to_string());
        survival.wake_on_connect = false;
        survival.waiting = vec![WaitingStrategy::Hold, WaitingStrategy::Message];
        survival.limbo = Some("lobby".to_string());
        survival.forwarding = crate::config::Forwarding::Bungeecord;

        let saved = store
            .replace_backends(vec![Backend::new("lobby", "127.0.0.1:25599"), survival])
            .unwrap();

        let stored = saved.backend("survival").unwrap();
        assert_eq!(stored.forwarding, crate::config::Forwarding::Bungeecord);
        assert!(!stored.wake_on_connect);
        assert_eq!(stored.limbo.as_deref(), Some("lobby"));
        assert_eq!(
            stored.waiting,
            vec![WaitingStrategy::Hold, WaitingStrategy::Message]
        );

        // And it survives a fresh read of the file, not just the in-memory copy.
        let reparsed = Config::parse(&std::fs::read_to_string(&path).unwrap(), "t").unwrap();
        assert!(!reparsed.backend("survival").unwrap().wake_on_connect);
    }

    /// Defaults are not written out, so a file edited through the panel does not
    /// fill up with settings nobody chose.
    #[test]
    fn test_default_waiting_settings_are_not_written() {
        let path = scratch_file("defaults");
        std::fs::write(&path, with_comments()).unwrap();

        let (store, _) = ConfigStore::open(&path).unwrap();
        store
            .replace_backends(vec![Backend::new("plain", "127.0.0.1:1")])
            .unwrap();

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(!written.contains("wake_on_connect"), "file: {written}");
        assert!(!written.contains("waiting"), "file: {written}");
        assert!(!written.contains("forwarding"), "file: {written}");
    }

    #[test]
    fn test_no_temporary_file_is_left_behind() {
        let path = scratch_file("clean");
        std::fs::write(&path, with_comments()).unwrap();

        let (store, _) = ConfigStore::open(&path).unwrap();
        store
            .replace_backends(vec![Backend::new("a", "10.0.0.1:1")])
            .unwrap();

        assert!(!path.with_extension("toml.tmp").exists());
    }

    #[test]
    fn test_reload_from_disk_refreshes_fingerprint_after_outside_edit() {
        let path = scratch_file("reload-after-stale");
        std::fs::write(&path, with_comments()).unwrap();

        let (store, _) = ConfigStore::open(&path).unwrap();
        std::fs::write(&path, with_comments().replace("Kept", "Edited externally")).unwrap();

        assert!(matches!(
            store.replace_backends(vec![Backend::new("survival", "10.0.0.2:25566")]),
            Err(ConfigError::StaleWrite { .. })
        ));

        let reloaded = store.reload_from_disk().unwrap();
        assert_eq!(reloaded.proxy.motd, "Edited externally");

        let saved = store
            .replace_backends(vec![Backend::new("survival", "10.0.0.2:25566")])
            .unwrap();
        assert_eq!(saved.backends[0].addr, "10.0.0.2:25566");
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("Edited externally")
        );
    }
}
