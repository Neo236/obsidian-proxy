use std::sync::atomic::AtomicUsize;

#[derive(Debug, Default)]
pub struct ProxyStats {
    pub total_bytes_rx: AtomicUsize,
    pub total_bytes_tx: AtomicUsize,
    pub active_connections: AtomicUsize,
}
