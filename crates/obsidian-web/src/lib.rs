pub mod api;
pub mod auth;

use arc_swap::ArcSwap;
use axum::{
    Router, middleware,
    routing::{get, post},
};
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tower_http::cors::{AllowOrigin, CorsLayer};
use tower_http::services::ServeDir;
use tracing::{info, warn};

use obsidian_core::config::Config;
use obsidian_core::config_store::ConfigStore;
use obsidian_core::events::{Event, EventKind, EventLog, EventSink};
use obsidian_core::hibernate::WakeSupervisor;
use obsidian_core::routing::SharedRouting;
use obsidian_core::stats::ProxyStats;

pub use auth::{AdminToken, TokenSource};

/// Environment variable naming the directory holding the built web UI.
pub const WEBUI_DIR_ENV_VAR: &str = "OBSIDIAN_WEBUI_DIR";

/// Environment variable naming one extra origin allowed to call the API.
///
/// Only needed when the UI is served from somewhere other than this server,
/// such as a Vite dev server on another port. Unset means same-origin only.
pub const ALLOWED_ORIGIN_ENV_VAR: &str = "OBSIDIAN_ALLOWED_ORIGIN";

#[derive(Clone)]
pub struct AppState {
    /// The configuration currently in force. Replaced wholesale on every edit
    /// or reload, so handlers never observe a half-applied change.
    pub config: Arc<ArcSwap<Config>>,
    pub config_store: Arc<ConfigStore>,
    pub routing: SharedRouting,
    pub stats: Arc<ProxyStats>,
    pub admin_token: AdminToken,
    /// Reading history is optional: the panel degrades to live state without it.
    pub events: Option<Arc<EventLog>>,
    pub event_sink: EventSink,
    pub wakes: Arc<WakeSupervisor>,
}

impl AppState {
    /// Publishes a new configuration to both the router and this state.
    ///
    /// Routing goes first: a connection arriving between the two stores should
    /// see the new topology rather than route by the old one.
    pub fn apply(&self, config: Config) {
        let backends = config.backends.len();
        self.routing.reload(&config);
        self.config.store(Arc::new(config));
        self.event_sink.record(
            Event::new(EventKind::ConfigApplied).with_detail(format!("{backends} backend(s)")),
        );
    }
}

/// Locates the built web UI.
///
/// The path used to be hardcoded relative to the current directory, so running
/// the binary from anywhere other than the crate directory served nothing.
fn webui_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(WEBUI_DIR_ENV_VAR) {
        return PathBuf::from(dir);
    }

    for candidate in ["obsidian-webui/dist", "../obsidian-webui/dist"] {
        let path = PathBuf::from(candidate);
        if path.is_dir() {
            return path;
        }
    }

    PathBuf::from("obsidian-webui/dist")
}

/// Builds the CORS layer.
///
/// The API is authenticated by a bearer token and the panel is served from the
/// same origin, so no cross-origin access is granted by default. Previously this
/// allowed any origin, any method and any header, which combined with a
/// compiled-in token meant any web page could drive the API.
fn cors_layer() -> CorsLayer {
    match std::env::var(ALLOWED_ORIGIN_ENV_VAR) {
        Ok(origin) if !origin.trim().is_empty() => match origin.trim().parse() {
            Ok(value) => {
                info!("Allowing cross-origin API requests from {}", origin.trim());
                CorsLayer::new()
                    .allow_origin(AllowOrigin::list([value]))
                    .allow_methods(tower_http::cors::Any)
                    .allow_headers([
                        axum::http::header::AUTHORIZATION,
                        axum::http::header::CONTENT_TYPE,
                    ])
            }
            Err(_) => {
                warn!(
                    "Ignoring invalid {}: {:?}",
                    ALLOWED_ORIGIN_ENV_VAR,
                    origin.trim()
                );
                CorsLayer::new()
            }
        },
        _ => CorsLayer::new(),
    }
}

/// Builds the application router. Exposed for tests.
pub fn app(state: AppState) -> Router {
    let api_routes = Router::new()
        .route(
            "/backends",
            get(api::list_backends).put(api::replace_backends),
        )
        .route("/backends/:name/wake", post(api::wake_backend))
        .route("/reload", post(api::reload))
        .route("/events", get(api::list_events))
        .route("/stats", get(api::get_stats))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ));

    Router::new()
        .nest("/api", api_routes)
        .fallback_service(ServeDir::new(webui_dir()))
        .layer(cors_layer())
        .with_state(state)
}

/// Everything the admin panel needs to run.
pub struct WebServer {
    pub bind: String,
    pub config: Config,
    pub config_store: Arc<ConfigStore>,
    pub routing: SharedRouting,
    pub stats: Arc<ProxyStats>,
    pub admin_token: AdminToken,
    pub events: Option<Arc<EventLog>>,
    pub wakes: Arc<WakeSupervisor>,
}

impl WebServer {
    pub async fn run(self) -> Result<(), std::io::Error> {
        let dir = webui_dir();
        if !dir.is_dir() {
            warn!(
                "Web UI directory {} not found; the panel will 404 until you run `npm run build` in obsidian-webui",
                dir.display()
            );
        }

        let state = AppState {
            config: Arc::new(ArcSwap::from_pointee(self.config)),
            config_store: self.config_store,
            routing: self.routing,
            stats: self.stats,
            admin_token: self.admin_token,
            event_sink: self
                .events
                .as_ref()
                .map(|log| log.sink())
                .unwrap_or_else(EventSink::disabled),
            events: self.events,
            wakes: self.wakes,
        };

        let listener = TcpListener::bind(&self.bind).await?;
        info!("Web UI and API listening on {}", self.bind);
        axum::serve(listener, app(state)).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use std::sync::atomic::{AtomicU32, Ordering};
    use tower::ServiceExt;

    static COUNTER: AtomicU32 = AtomicU32::new(0);
    const TOKEN: &str = "correct-horse-battery-staple";

    fn scratch_config() -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "obsidian-web-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("obsidian.toml");
        std::fs::write(
            &path,
            "[[backend]]\nname = \"survival\"\naddr = \"127.0.0.1:25566\"\ndefault = true\n",
        )
        .unwrap();
        path
    }

    fn test_state(token: &str) -> AppState {
        let (store, config) = ConfigStore::open(scratch_config()).unwrap();
        AppState {
            routing: SharedRouting::from_config(&config),
            config: Arc::new(ArcSwap::from_pointee(config)),
            config_store: Arc::new(store),
            stats: Arc::new(ProxyStats::default()),
            admin_token: AdminToken::new(token),
            events: None,
            event_sink: EventSink::disabled(),
            wakes: Arc::new(WakeSupervisor::new(EventSink::disabled())),
        }
    }

    fn authorised(method: &str, uri: &str, body: Body) -> Request<Body> {
        Request::builder()
            .method(method)
            .uri(uri)
            .header("Authorization", format!("Bearer {TOKEN}"))
            .header("Content-Type", "application/json")
            .body(body)
            .unwrap()
    }

    async fn status_of(request: Request<Body>) -> StatusCode {
        app(test_state(TOKEN))
            .oneshot(request)
            .await
            .unwrap()
            .status()
    }

    #[tokio::test]
    async fn test_api_requires_a_token() {
        let request = Request::builder()
            .uri("/api/backends")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(request).await, StatusCode::UNAUTHORIZED);
    }

    /// Regression: the token was the compiled-in literal "obsidian_secret",
    /// published in this repository and shipped inside the web bundle.
    #[tokio::test]
    async fn test_api_rejects_the_old_hardcoded_token() {
        let request = Request::builder()
            .uri("/api/backends")
            .header("Authorization", "Bearer obsidian_secret")
            .body(Body::empty())
            .unwrap();
        assert_eq!(status_of(request).await, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_every_route_is_guarded() {
        for (method, uri) in [
            ("GET", "/api/backends"),
            ("PUT", "/api/backends"),
            ("POST", "/api/reload"),
            ("GET", "/api/stats"),
        ] {
            let request = Request::builder()
                .method(method)
                .uri(uri)
                .body(Body::empty())
                .unwrap();
            assert_eq!(
                status_of(request).await,
                StatusCode::UNAUTHORIZED,
                "{method} {uri} was not guarded"
            );
        }
    }

    #[tokio::test]
    async fn test_listing_backends_reports_configuration_and_health() {
        let response = app(test_state(TOKEN))
            .oneshot(authorised("GET", "/api/backends", Body::empty()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let views: serde_json::Value = serde_json::from_slice(&body).unwrap();

        assert_eq!(views[0]["name"], "survival");
        assert_eq!(views[0]["default"], true);
        assert_eq!(views[0]["health"], "unknown");
        assert_eq!(views[0]["hibernates"], false);
    }

    /// The point of this phase: an edit through the panel becomes the file and
    /// the live routing table, not a row in a table nobody reads.
    #[tokio::test]
    async fn test_saving_backends_rewrites_the_file_and_republishes_routing() {
        let state = test_state(TOKEN);
        let path = state.config_store.path().to_path_buf();
        let routing = state.routing.clone();

        let body = Body::from(
            serde_json::json!([
                {
                    "name": "survival",
                    "addr": "10.0.0.2:25566",
                    "hostnames": ["play.example.com"],
                    "default": true
                },
                { "name": "creative", "addr": "10.0.0.3:25567" }
            ])
            .to_string(),
        );

        let response = app(state)
            .oneshot(authorised("PUT", "/api/backends", body))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let written = std::fs::read_to_string(&path).unwrap();
        assert!(written.contains("10.0.0.2:25566"), "file: {written}");
        assert!(written.contains("creative"), "file: {written}");

        let table = routing.load();
        assert_eq!(table.resolve("play.example.com").addr, "10.0.0.2:25566");
        assert_eq!(
            table.entry_by_name("creative").unwrap().addr,
            "10.0.0.3:25567"
        );
    }

    /// Invalid topology is refused and the file is left alone.
    #[tokio::test]
    async fn test_an_invalid_edit_is_refused_without_writing() {
        let state = test_state(TOKEN);
        let path = state.config_store.path().to_path_buf();
        let before = std::fs::read_to_string(&path).unwrap();

        let body = Body::from(
            serde_json::json!([
                { "name": "same", "addr": "10.0.0.2:1" },
                { "name": "same", "addr": "10.0.0.3:2" }
            ])
            .to_string(),
        );

        let response = app(state)
            .oneshot(authorised("PUT", "/api/backends", body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), before);
    }

    /// An edit made in an editor while the panel was open answers 409 rather
    /// than overwriting it.
    #[tokio::test]
    async fn test_an_outside_edit_answers_conflict() {
        let state = test_state(TOKEN);
        let path = state.config_store.path().to_path_buf();
        std::fs::write(
            &path,
            "# edited by hand\n[[backend]]\nname = \"survival\"\naddr = \"127.0.0.1:9999\"\n",
        )
        .unwrap();

        let body = Body::from(
            serde_json::json!([{ "name": "survival", "addr": "10.0.0.2:1" }]).to_string(),
        );

        let response = app(state)
            .oneshot(authorised("PUT", "/api/backends", body))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("edited by hand")
        );
    }

    /// Reload is how an edit made in an editor takes effect without a restart,
    /// and how the panel recovers after a 409 Conflict so subsequent saves work.
    #[tokio::test]
    async fn test_reload_picks_up_an_outside_edit() {
        let state = test_state(TOKEN);
        let path = state.config_store.path().to_path_buf();
        let routing = state.routing.clone();

        std::fs::write(
            &path,
            "# manual comment\n[proxy]\nmotd = \"Kept\"\n\n[[backend]]\nname = \"survival\"\naddr = \"10.9.9.9:25566\"\ndefault = true\n",
        )
        .unwrap();

        let response = app(state.clone())
            .oneshot(authorised("POST", "/api/reload", Body::empty()))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(routing.load().default_entry().addr, "10.9.9.9:25566");

        // Now a panel save on top of the reloaded state must succeed (200 OK),
        // not fail with 409 Conflict, and must preserve the manual comment.
        let body = Body::from(
            serde_json::json!([
                { "name": "survival", "addr": "10.9.9.9:25567", "default": true }
            ])
            .to_string(),
        );
        let save_resp = app(state)
            .oneshot(authorised("PUT", "/api/backends", body))
            .await
            .unwrap();
        assert_eq!(save_resp.status(), StatusCode::OK);
        assert_eq!(routing.load().default_entry().addr, "10.9.9.9:25567");
        assert!(
            std::fs::read_to_string(&path)
                .unwrap()
                .contains("# manual comment")
        );
    }

    #[tokio::test]
    async fn test_no_cross_origin_access_by_default() {
        let request = Request::builder()
            .uri("/api/stats")
            .header("Origin", "https://evil.example")
            .header("Authorization", format!("Bearer {TOKEN}"))
            .body(Body::empty())
            .unwrap();

        let response = app(test_state(TOKEN)).oneshot(request).await.unwrap();

        assert!(
            !response
                .headers()
                .contains_key("access-control-allow-origin"),
            "an arbitrary origin must not be granted access"
        );
    }

    #[tokio::test]
    async fn test_wake_endpoint_starts_hibernating_backend() {
        let dir = std::env::temp_dir().join(format!(
            "obsidian-web-wake-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("obsidian.toml");
        std::fs::write(
            &path,
            "[[backend]]\nname = \"survival\"\naddr = \"127.0.0.1:25566\"\ndefault = true\nwake = \"start\"\nwake_on_connect = false\n\n[wake.start]\ncommand = \"true\"\n",
        )
        .unwrap();

        let (store, config) = ConfigStore::open(path).unwrap();
        let state = AppState {
            routing: SharedRouting::from_config(&config),
            config: Arc::new(ArcSwap::from_pointee(config)),
            config_store: Arc::new(store),
            stats: Arc::new(ProxyStats::default()),
            admin_token: AdminToken::new(TOKEN),
            events: None,
            event_sink: EventSink::disabled(),
            wakes: Arc::new(WakeSupervisor::new(EventSink::disabled())),
        };

        let response = app(state.clone())
            .oneshot(authorised(
                "POST",
                "/api/backends/survival/wake",
                Body::empty(),
            ))
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::OK);

        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "started");
        assert_eq!(json["health"], "starting");
    }
}
