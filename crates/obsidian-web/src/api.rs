use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
};
use obsidian_core::config::{Backend, ConfigError, Forwarding, WaitingStrategy};
use obsidian_core::hibernate::WakeOutcome;
use obsidian_core::routing::Health;
use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::AppState;

/// One backend as the panel sees it: what the file declares, plus what the
/// health monitor has observed.
#[derive(Debug, Serialize)]
pub struct BackendView {
    pub name: String,
    pub addr: String,
    pub hostnames: Vec<String>,
    pub default: bool,
    /// Name of the `[wake.<name>]` block this backend uses, if any.
    pub wake: Option<String>,
    pub wake_on_connect: bool,
    pub waiting: Vec<WaitingStrategy>,
    pub limbo: Option<String>,
    pub forwarding: Forwarding,
    pub send_proxy_v2: bool,
    pub hibernates: bool,
    /// One of `unknown`, `up`, `down`, `starting`.
    pub health: &'static str,
}

fn health_label(health: Health) -> &'static str {
    match health {
        Health::Unknown => "unknown",
        Health::Up => "up",
        Health::Down => "down",
        Health::Starting => "starting",
    }
}

/// What the panel sends when it saves the backend list.
///
/// The whole list is replaced in one request. Per-item endpoints would need
/// their own conflict handling for concurrent edits; replacing the list keeps
/// the file the unit of change.
#[derive(Debug, Deserialize)]
pub struct BackendInput {
    pub name: String,
    pub addr: String,
    #[serde(default)]
    pub hostnames: Vec<String>,
    #[serde(default)]
    pub default: bool,
    /// Must name a `[wake.<name>]` block that already exists. The panel may
    /// point a backend at a command; it may not define one.
    #[serde(default)]
    pub wake: Option<String>,

    // Absent means "leave at the default", which is what a panel that does not
    // yet surface these fields sends. Round-tripping them matters: a save that
    // omitted them would quietly reset an operator's choices.
    #[serde(default = "default_wake_on_connect")]
    pub wake_on_connect: bool,
    #[serde(default)]
    pub waiting: Option<Vec<WaitingStrategy>>,
    #[serde(default)]
    pub limbo: Option<String>,
    #[serde(default)]
    pub forwarding: Forwarding,
    #[serde(default)]
    pub send_proxy_v2: bool,
}

fn default_wake_on_connect() -> bool {
    true
}

impl From<BackendInput> for Backend {
    fn from(input: BackendInput) -> Self {
        let defaults = Backend::new(&input.name, &input.addr);
        Self {
            hostnames: input.hostnames,
            default: input.default,
            wake: input.wake,
            wake_on_connect: input.wake_on_connect,
            waiting: input.waiting.unwrap_or(defaults.waiting),
            limbo: input.limbo,
            forwarding: input.forwarding,
            send_proxy_v2: input.send_proxy_v2,
            ..defaults
        }
    }
}

/// Maps a configuration failure onto a status code the panel can act on.
fn config_error_response(err: ConfigError) -> (StatusCode, Json<serde_json::Value>) {
    let status = match err {
        // Someone edited the file while the panel had it open. The panel should
        // reload and let the operator redo the change on top.
        ConfigError::StaleWrite { .. } => StatusCode::CONFLICT,
        ConfigError::Read { .. } | ConfigError::Write { .. } => StatusCode::INTERNAL_SERVER_ERROR,
        // Everything else is the submitted content being wrong.
        _ => StatusCode::BAD_REQUEST,
    };

    (
        status,
        Json(serde_json::json!({ "error": err.to_string() })),
    )
}

/// Lists the declared backends together with their observed health.
pub async fn list_backends(State(state): State<AppState>) -> impl IntoResponse {
    let table = state.routing.load();

    let views: Vec<BackendView> = state
        .config
        .load()
        .backends
        .iter()
        .map(|backend| {
            let entry = table.entry_by_name(&backend.name);
            BackendView {
                name: backend.name.clone(),
                addr: backend.addr.clone(),
                hostnames: backend.hostnames.clone(),
                default: backend.name == state.config.load().default_backend().name,
                wake: backend.wake.clone(),
                wake_on_connect: backend.wake_on_connect,
                waiting: backend.waiting.clone(),
                limbo: backend.limbo.clone(),
                forwarding: backend.forwarding,
                send_proxy_v2: backend.send_proxy_v2,
                hibernates: entry.map(|entry| entry.hibernates()).unwrap_or(false),
                health: entry
                    .map(|entry| health_label(entry.health.get()))
                    .unwrap_or("unknown"),
            }
        })
        .collect();

    (StatusCode::OK, Json(views)).into_response()
}

/// Replaces the declared backends, writing the file and republishing routing.
pub async fn replace_backends(
    State(state): State<AppState>,
    Json(payload): Json<Vec<BackendInput>>,
) -> impl IntoResponse {
    let backends: Vec<Backend> = payload.into_iter().map(Backend::from).collect();
    let count = backends.len();

    // Writing the file is blocking, and the validation it does is not free.
    let store = state.config_store.clone();
    let written = tokio::task::spawn_blocking(move || store.replace_backends(backends)).await;

    let config = match written {
        Ok(Ok(config)) => config,
        Ok(Err(err)) => {
            warn!("Rejected backend update: {}", err);
            return config_error_response(err).into_response();
        }
        Err(err) => {
            warn!("Backend update task failed: {}", err);
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    state.apply(config);
    info!("Configuration updated from the panel: {} backend(s)", count);

    list_backends(State(state)).await.into_response()
}

/// Re-reads the configuration file and republishes routing.
///
/// This is how an edit made in an editor takes effect without a restart, and
/// how the panel recovers after a conflict.
pub async fn reload(State(state): State<AppState>) -> impl IntoResponse {
    let store = state.config_store.clone();

    let loaded = tokio::task::spawn_blocking(move || store.reload_from_disk()).await;

    match loaded {
        Ok(Ok(config)) => {
            state.apply(config);
            info!("Configuration reloaded from disk");
            list_backends(State(state)).await.into_response()
        }
        Ok(Err(err)) => {
            warn!("Reload refused: {}", err);
            config_error_response(err).into_response()
        }
        Err(err) => {
            warn!("Reload task failed: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

pub async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    use std::sync::atomic::Ordering::Relaxed;

    Json(serde_json::json!({
        "total_bytes_rx": state.stats.total_bytes_rx.load(Relaxed),
        "total_bytes_tx": state.stats.total_bytes_tx.load(Relaxed),
        "active_connections": state.stats.active_connections.load(Relaxed),
    }))
    .into_response()
}

/// Query parameters for the history endpoint.
#[derive(Debug, Deserialize)]
pub struct EventQuery {
    #[serde(default = "default_event_limit")]
    pub limit: usize,
}

fn default_event_limit() -> usize {
    50
}

/// Returns the most recent events, newest first.
///
/// An empty list when history is disabled, rather than an error: the panel is
/// still useful without it.
pub async fn list_events(
    State(state): State<AppState>,
    axum::extract::Query(query): axum::extract::Query<EventQuery>,
) -> impl IntoResponse {
    let Some(log) = state.events.clone() else {
        return (StatusCode::OK, Json(Vec::<obsidian_core::Event>::new())).into_response();
    };

    let limit = query.limit.clamp(1, 500);
    let read = tokio::task::spawn_blocking(move || log.recent(limit)).await;

    match read {
        Ok(Ok(events)) => (StatusCode::OK, Json(events)).into_response(),
        Ok(Err(err)) => {
            warn!("Could not read history: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Err(err) => {
            warn!("History read task failed: {}", err);
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
    }
}

/// Manually triggers a wake command for a hibernating backend.
pub async fn wake_backend(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let table = state.routing.load();
    let Some(entry) = table.entry_by_name(&name) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({ "error": format!("Unknown backend: {name}") })),
        )
            .into_response();
    };

    match state.wakes.wake(entry) {
        WakeOutcome::Started => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "started",
                "health": health_label(entry.health.get()),
            })),
        )
            .into_response(),
        WakeOutcome::AlreadyStarting => (
            StatusCode::OK,
            Json(serde_json::json!({
                "status": "already_starting",
                "health": health_label(entry.health.get()),
            })),
        )
            .into_response(),
        WakeOutcome::NoCommand => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": format!("Backend {name} does not have a wake command configured") })),
        )
            .into_response(),
        WakeOutcome::Failed(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": err })),
        )
            .into_response(),
    }
}
