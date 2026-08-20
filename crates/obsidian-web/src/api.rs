use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use serde::Deserialize;
use crate::AppState;

pub async fn list_servers(
    State(state): State<AppState>,
) -> impl IntoResponse {
    match state.db.get_servers().await {
        Ok(servers) => (StatusCode::OK, Json(servers)).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn wake_server(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match state.db.wake_server(id).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Deserialize)]
pub struct ServerPayload {
    pub name: String,
    pub target_addr: String,
}

pub async fn add_server(
    State(state): State<AppState>,
    Json(payload): Json<ServerPayload>,
) -> impl IntoResponse {
    match state.db.add_server(payload.name, payload.target_addr).await {
        Ok(id) => (StatusCode::CREATED, Json(serde_json::json!({ "id": id }))).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn update_server(
    State(state): State<AppState>,
    Path(id): Path<i64>,
    Json(payload): Json<ServerPayload>,
) -> impl IntoResponse {
    match state.db.update_server(id, payload.name, payload.target_addr).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn delete_server(
    State(state): State<AppState>,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    match state.db.delete_server(id).await {
        Ok(_) => StatusCode::OK.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

pub async fn get_stats(State(state): State<AppState>) -> impl IntoResponse {
    let rx = state.stats.total_bytes_rx.load(std::sync::atomic::Ordering::Relaxed);
    let tx = state.stats.total_bytes_tx.load(std::sync::atomic::Ordering::Relaxed);
    let active = state.stats.active_connections.load(std::sync::atomic::Ordering::Relaxed);

    Json(serde_json::json!({
        "total_bytes_rx": rx,
        "total_bytes_tx": tx,
        "active_connections": active
    })).into_response()
}
