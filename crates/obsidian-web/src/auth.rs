use axum::{
    extract::Request,
    http::StatusCode,
    middleware::Next,
    response::Response,
};

pub async fn auth_middleware(req: Request, next: Next) -> Result<Response, StatusCode> {
    let auth_header = req
        .headers()
        .get("Authorization")
        .and_then(|value| value.to_str().ok());

    let expected_token = std::env::var("OBSIDIAN_ADMIN_TOKEN").unwrap_or_else(|_| "obsidian_secret".to_string());
    let expected_auth = format!("Bearer {}", expected_token);

    match auth_header {
        Some(auth) if auth == expected_auth => {
            Ok(next.run(req).await)
        }
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}
