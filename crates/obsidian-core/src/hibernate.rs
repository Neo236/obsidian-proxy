use std::process::Stdio;
use tokio::process::{Child, Command};
use tracing::info;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

/// Manages the hibernation state of backend servers.
#[derive(Clone)]
pub struct HibernateManager {
    is_waking: Arc<AtomicBool>,
}

impl HibernateManager {
    pub fn new() -> Self {
        Self {
            is_waking: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Triggers a server wake up command if it is not already waking.
    /// In a real scenario, this would use a specific shell script or docker command configured by the user.
    pub async fn wake_server_if_needed(&self, start_cmd: &str, args: &[&str]) -> Result<Option<Child>, std::io::Error> {
        if self.is_waking.compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed).is_ok() {
            info!("Server is hibernated. Waking up server with command: {} {:?}", start_cmd, args);
            let child = Command::new(start_cmd)
                .args(args)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?;
            Ok(Some(child))
        } else {
            Ok(None)
        }
    }

    /// Marks the server as online (not waking).
    pub fn mark_online(&self) {
        self.is_waking.store(false, Ordering::Release);
    }
}

impl Default for HibernateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hibernate_manager_state() {
        let manager = HibernateManager::new();
        assert!(!manager.is_waking.load(Ordering::Relaxed));

        manager.mark_online();
        assert!(!manager.is_waking.load(Ordering::Relaxed));
    }
}

