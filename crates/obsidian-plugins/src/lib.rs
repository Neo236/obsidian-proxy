use rhai::{Engine, AST, Scope};
use std::fs;
use std::path::Path;

pub struct PluginManager {
    engine: Engine,
    asts: Vec<AST>,
}

impl PluginManager {
    pub fn new() -> Self {
        Self::with_dir(Path::new("plugins"))
    }

    pub fn with_dir(plugins_dir: &Path) -> Self {
        let engine = Engine::new();
        let mut asts = Vec::new();

        if !plugins_dir.exists() {
            let _ = fs::create_dir_all(plugins_dir);
        }

        if let Ok(entries) = fs::read_dir(plugins_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("rhai") {
                    match engine.compile_file(path.clone()) {
                        Ok(ast) => asts.push(ast),
                        Err(err) => eprintln!("Failed to compile plugin {:?}: {}", path, err),
                    }
                }
            }
        }

        Self { engine, asts }
    }

    pub fn run_hook_on_join(&self, ip: &str, username: &str) -> bool {
        for ast in &self.asts {
            let mut scope = Scope::new();
            
            let result: Result<bool, _> = self.engine.call_fn(
                &mut scope,
                ast,
                "on_player_join",
                (ip.to_string(), username.to_string())
            );

            match result {
                Ok(allow) => {
                    if !allow {
                        return false;
                    }
                }
                Err(err) => {
                    if let rhai::EvalAltResult::ErrorFunctionNotFound(..) = *err {
                        continue;
                    } else {
                        eprintln!("Error executing on_player_join: {}", err);
                    }
                }
            }
        }
        true
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
         .field("asts_count", &self.asts.len())
         .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_plugin_manager_allow_join() {
        let dir = tempdir().unwrap();
        let plugin_path = dir.path().join("allow.rhai");
        let mut file = fs::File::create(&plugin_path).unwrap();
        writeln!(file, "fn on_player_join(ip, username) {{ return true; }}").unwrap();

        let manager = PluginManager::with_dir(dir.path());
        assert!(manager.run_hook_on_join("127.0.0.1", "TestUser"));
    }

    #[test]
    fn test_plugin_manager_deny_join() {
        let dir = tempdir().unwrap();
        let plugin_path = dir.path().join("deny.rhai");
        let mut file = fs::File::create(&plugin_path).unwrap();
        writeln!(file, "fn on_player_join(ip, username) {{ if username == \"BadUser\" {{ return false; }} else {{ return true; }} }}").unwrap();

        let manager = PluginManager::with_dir(dir.path());
        assert!(!manager.run_hook_on_join("127.0.0.1", "BadUser"));
        assert!(manager.run_hook_on_join("127.0.0.1", "GoodUser"));
    }

    #[test]
    fn test_plugin_manager_no_function() {
        let dir = tempdir().unwrap();
        let plugin_path = dir.path().join("empty.rhai");
        let mut file = fs::File::create(&plugin_path).unwrap();
        writeln!(file, "let x = 1;").unwrap();

        let manager = PluginManager::with_dir(dir.path());
        // Missing function should not block login
        assert!(manager.run_hook_on_join("127.0.0.1", "TestUser"));
    }
}
