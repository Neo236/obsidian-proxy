use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;
use tracing::{debug, warn};

#[derive(Clone)]
pub struct HealthChecker {
    backend_addr: String,
    interval: Duration,
    healthy: Arc<AtomicBool>,
}

impl HealthChecker {
    pub fn new(backend_addr: impl Into<String>, interval: Duration) -> Self {
        Self {
            backend_addr: backend_addr.into(),
            interval,
            healthy: Arc::new(AtomicBool::new(false)),
        }
    }

    pub fn is_healthy(&self) -> bool {
        self.healthy.load(Ordering::Relaxed)
    }

    pub fn healthy_flag(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.healthy)
    }

    pub async fn run(&self) {
        let mut interval = time::interval(self.interval);
        loop {
            interval.tick().await;
            match tokio::net::TcpStream::connect(&self.backend_addr).await {
                Ok(_) => {
                    self.healthy.store(true, Ordering::Release);
                    debug!("Health check passed for backend {}", self.backend_addr);
                }
                Err(e) => {
                    self.healthy.store(false, Ordering::Release);
                    warn!("Health check failed for backend {}: {}", self.backend_addr, e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn test_health_checker_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let checker = HealthChecker::new(addr.to_string(), Duration::from_millis(50));
        assert!(!checker.is_healthy());

        // Spawn health checker
        let checker_clone = checker.clone();
        let handle = tokio::spawn(async move {
            checker_clone.run().await;
        });

        // Wait a moment for first tick
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert!(checker.is_healthy());

        handle.abort();
    }
}

