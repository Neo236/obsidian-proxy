//! Sandboxed Rhai hooks evaluated during connection setup.
//!
//! Scripts run on the login path, so they are bounded on every axis Rhai
//! exposes and a script that misbehaves denies the connection rather than
//! waving it through.

use rhai::{AST, Engine, EvalAltResult, Scope};
use std::fs;
use std::path::Path;

/// Name of the hook invoked once per connection attempt.
pub const JOIN_HOOK: &str = "on_player_join";

/// Ceiling on interpreted operations per hook invocation. A tight loop hits
/// this in well under a millisecond of CPU; a realistic filter uses a few
/// hundred operations.
pub const MAX_OPERATIONS: u64 = 100_000;

/// Maximum nested function calls, which also bounds runaway recursion.
pub const MAX_CALL_LEVELS: usize = 32;

/// Maximum size of any string a script builds, in bytes.
pub const MAX_STRING_SIZE: usize = 8 * 1024;

/// Maximum number of elements in a script-built array or map.
pub const MAX_CONTAINER_SIZE: usize = 1024;

/// What a plugin decided about a connection.
///
/// There is deliberately no conversion from `bool`: every path that is not an
/// explicit allow has to name why it denied, which is what keeps the failure
/// mode closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum JoinDecision {
    /// Every plugin allowed the connection, or no plugin expressed an opinion.
    Allow,
    /// A plugin refused the connection, or failed while deciding.
    Deny { plugin: String, reason: String },
}

impl JoinDecision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, JoinDecision::Allow)
    }
}

pub struct PluginManager {
    engine: Engine,
    scripts: Vec<(String, AST)>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self::with_dir(Path::new("plugins"))
    }

    pub fn with_dir(plugins_dir: &Path) -> Self {
        let engine = Self::sandboxed_engine();
        let mut scripts = Vec::new();

        if !plugins_dir.exists() {
            let _ = fs::create_dir_all(plugins_dir);
        }

        if let Ok(entries) = fs::read_dir(plugins_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if !path.is_file() || path.extension().and_then(|s| s.to_str()) != Some("rhai") {
                    continue;
                }
                let name = path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("<unnamed>")
                    .to_string();
                match engine.compile_file(path.clone()) {
                    Ok(ast) => scripts.push((name, ast)),
                    Err(err) => {
                        // A script that does not compile is never consulted, so
                        // it cannot deny anything. Say so loudly rather than
                        // leave the operator believing a filter is active.
                        eprintln!("plugin {name:?} failed to compile and will be ignored: {err}");
                    }
                }
            }
        }

        scripts.sort_by(|(a, _), (b, _)| a.cmp(b));
        Self { engine, scripts }
    }

    /// Builds an engine with every documented limit applied and module loading
    /// disabled, so a script cannot pull in code from elsewhere on disk.
    fn sandboxed_engine() -> Engine {
        let mut engine = Engine::new();
        engine.set_max_operations(MAX_OPERATIONS);
        engine.set_max_call_levels(MAX_CALL_LEVELS);
        engine.set_max_string_size(MAX_STRING_SIZE);
        engine.set_max_array_size(MAX_CONTAINER_SIZE);
        engine.set_max_map_size(MAX_CONTAINER_SIZE);
        engine.set_max_expr_depths(64, 32);
        engine.set_module_resolver(rhai::module_resolvers::DummyModuleResolver::new());
        engine
    }

    /// Number of scripts that compiled successfully.
    pub fn loaded_count(&self) -> usize {
        self.scripts.len()
    }

    /// Runs the join hook in every loaded script, stopping at the first denial.
    ///
    /// A script that returns false, exceeds a limit, or fails for any other
    /// reason denies the connection. Only a script with no `on_player_join` at
    /// all is skipped, since that is a script which does not participate in
    /// this hook.
    ///
    /// This is synchronous and CPU-bound. Callers on an async runtime must not
    /// invoke it directly from a task; see the router, which moves it onto a
    /// blocking thread.
    pub fn run_hook_on_join(&self, ip: &str, username: &str) -> JoinDecision {
        for (name, ast) in &self.scripts {
            let mut scope = Scope::new();
            let result: Result<bool, _> = self.engine.call_fn(
                &mut scope,
                ast,
                JOIN_HOOK,
                (ip.to_string(), username.to_string()),
            );

            match result {
                Ok(true) => {}
                Ok(false) => {
                    return JoinDecision::Deny {
                        plugin: name.clone(),
                        reason: format!("{JOIN_HOOK} returned false"),
                    };
                }
                Err(err) if is_missing_join_hook(&err) => continue,
                Err(err) => {
                    return JoinDecision::Deny {
                        plugin: name.clone(),
                        reason: err.to_string(),
                    };
                }
            }
        }

        JoinDecision::Allow
    }
}

/// True when the script simply does not define the join hook, as opposed to
/// defining one that failed while running.
fn is_missing_join_hook(err: &EvalAltResult) -> bool {
    match err {
        EvalAltResult::ErrorFunctionNotFound(signature, _) => signature
            .split_whitespace()
            .next()
            .is_some_and(|name| name == JOIN_HOOK),
        _ => false,
    }
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for PluginManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginManager")
            .field("scripts", &self.scripts.len())
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    fn manager_with(scripts: &[(&str, &str)]) -> (tempfile::TempDir, PluginManager) {
        let dir = tempdir().unwrap();
        for (name, body) in scripts {
            let mut file = fs::File::create(dir.path().join(name)).unwrap();
            write!(file, "{body}").unwrap();
        }
        let manager = PluginManager::with_dir(dir.path());
        (dir, manager)
    }

    #[test]
    fn test_allows_when_every_script_agrees() {
        let (_dir, manager) =
            manager_with(&[("allow.rhai", "fn on_player_join(ip, name) { true }")]);
        assert_eq!(
            manager.run_hook_on_join("127.0.0.1", "TestUser"),
            JoinDecision::Allow
        );
    }

    #[test]
    fn test_denies_when_a_script_returns_false() {
        let (_dir, manager) = manager_with(&[(
            "deny.rhai",
            "fn on_player_join(ip, name) { name != \"BadUser\" }",
        )]);

        assert!(
            manager
                .run_hook_on_join("127.0.0.1", "GoodUser")
                .is_allowed()
        );
        match manager.run_hook_on_join("127.0.0.1", "BadUser") {
            JoinDecision::Deny { plugin, .. } => assert_eq!(plugin, "deny.rhai"),
            other => panic!("expected denial, got {other:?}"),
        }
    }

    #[test]
    fn test_script_without_the_hook_is_skipped() {
        let (_dir, manager) = manager_with(&[("empty.rhai", "let x = 1;")]);
        assert_eq!(
            manager.run_hook_on_join("127.0.0.1", "TestUser"),
            JoinDecision::Allow
        );
    }

    /// A hook that raises denies the connection. Previously any error was logged
    /// and treated as consent, so a broken filter silently stopped filtering.
    #[test]
    fn test_failing_script_denies_rather_than_allows() {
        let (_dir, manager) = manager_with(&[(
            "broken.rhai",
            "fn on_player_join(ip, name) { throw \"boom\" }",
        )]);

        match manager.run_hook_on_join("127.0.0.1", "TestUser") {
            JoinDecision::Deny { plugin, reason } => {
                assert_eq!(plugin, "broken.rhai");
                assert!(reason.contains("boom"), "reason was {reason:?}");
            }
            other => panic!("expected denial, got {other:?}"),
        }
    }

    /// The engine has no operation ceiling by default, so this script would run
    /// forever on the login path and pin a runtime worker.
    #[test]
    fn test_infinite_loop_is_stopped_by_the_operation_limit() {
        let (_dir, manager) =
            manager_with(&[("spin.rhai", "fn on_player_join(ip, name) { loop { } }")]);

        match manager.run_hook_on_join("127.0.0.1", "TestUser") {
            JoinDecision::Deny { plugin, .. } => assert_eq!(plugin, "spin.rhai"),
            other => panic!("expected the operation limit to deny, got {other:?}"),
        }
    }

    /// Unbounded recursion must hit the call-depth limit rather than the stack.
    #[test]
    fn test_runaway_recursion_is_stopped() {
        let (_dir, manager) = manager_with(&[(
            "recurse.rhai",
            "fn spin(n) { spin(n + 1) } fn on_player_join(ip, name) { spin(0) }",
        )]);

        assert!(
            !manager
                .run_hook_on_join("127.0.0.1", "TestUser")
                .is_allowed()
        );
    }

    /// Scripts must not be able to pull in code from elsewhere on disk.
    #[test]
    fn test_module_imports_are_refused() {
        let (_dir, manager) = manager_with(&[(
            "import.rhai",
            "fn on_player_join(ip, name) { import \"other\" as m; true }",
        )]);

        assert!(
            !manager
                .run_hook_on_join("127.0.0.1", "TestUser")
                .is_allowed()
        );
    }

    /// The first denial wins and names the script responsible.
    #[test]
    fn test_first_denial_short_circuits() {
        let (_dir, manager) = manager_with(&[
            ("a_deny.rhai", "fn on_player_join(ip, name) { false }"),
            ("b_allow.rhai", "fn on_player_join(ip, name) { true }"),
        ]);

        assert_eq!(manager.loaded_count(), 2);
        match manager.run_hook_on_join("127.0.0.1", "TestUser") {
            JoinDecision::Deny { plugin, .. } => assert_eq!(plugin, "a_deny.rhai"),
            other => panic!("expected denial, got {other:?}"),
        }
    }

    /// A script that does not compile is ignored, not treated as a denial.
    #[test]
    fn test_uncompilable_script_is_not_loaded() {
        let (_dir, manager) = manager_with(&[("bad.rhai", "fn on_player_join( {{{")]);
        assert_eq!(manager.loaded_count(), 0);
        assert_eq!(
            manager.run_hook_on_join("127.0.0.1", "TestUser"),
            JoinDecision::Allow
        );
    }
}
