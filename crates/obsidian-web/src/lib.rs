pub mod db;
pub mod api;
pub mod auth;

use axum::{
    routing::{get, post, put},
    Router,
};
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{Any, CorsLayer};
use tower_http::services::ServeDir;
use axum::middleware;

use obsidian_core::stats::ProxyStats;

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<db::Database>,
    pub stats: Arc<ProxyStats>,
}

pub async fn run_web_server(port: u16, stats: Arc<ProxyStats>) -> Result<(), std::io::Error> {
    let db = Arc::new(db::Database::new("obsidian.db").map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))?);
    let state = AppState { db, stats };

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let api_routes = Router::new()
        .route("/servers", get(api::list_servers).post(api::add_server))
        .route("/stats", get(api::get_stats))
        .route("/servers/:id/wake", post(api::wake_server))
        .route("/servers/:id", put(api::update_server).delete(api::delete_server))
        .route_layer(middleware::from_fn(auth::auth_middleware));

    let app = Router::new()
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new("../obsidian-webui/dist"))
        .layer(cors)
        .with_state(state);

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;
    println!("Web UI and API listening on {}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}
