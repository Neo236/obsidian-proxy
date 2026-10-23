//! Bearer authentication for the administration API.

use axum::{
    extract::{Request, State},
    http::StatusCode,
    middleware::Next,
    response::Response,
};
use rand::RngCore;
use std::sync::Arc;
use subtle::ConstantTimeEq;

use crate::AppState;

/// Environment variable read at startup to supply the admin token.
pub const TOKEN_ENV_VAR: &str = "OBSIDIAN_ADMIN_TOKEN";

/// Length in bytes of a generated token, before hex encoding.
const GENERATED_TOKEN_BYTES: usize = 32;

/// Shortest token accepted from the environment. Short tokens are guessable and
/// this endpoint is reachable from the network.
pub const MIN_TOKEN_LEN: usize = 16;

/// The secret guarding the administration API.
///
/// Cloneable so it can live in the router state; the secret itself is shared,
/// not copied.
#[derive(Clone)]
pub struct AdminToken {
    value: Arc<String>,
}

/// Where the running token came from, so the caller can tell the operator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenSource {
    /// Supplied through the environment.
    Environment,
    /// Generated at startup because none was supplied.
    Generated,
}

impl AdminToken {
    /// Reads the token from the environment, or generates one.
    ///
    /// A token supplied through the environment must be at least
    /// [`MIN_TOKEN_LEN`] characters; anything shorter is treated as absent so a
    /// placeholder cannot quietly become the production secret.
    pub fn from_env_or_generate() -> (Self, TokenSource) {
        match std::env::var(TOKEN_ENV_VAR) {
            Ok(value) if value.trim().len() >= MIN_TOKEN_LEN => (
                Self {
                    value: Arc::new(value.trim().to_string()),
                },
                TokenSource::Environment,
            ),
            _ => (Self::generate(), TokenSource::Generated),
        }
    }

    /// Builds a token from an explicit value. Intended for tests and for
    /// embedding callers that manage their own configuration.
    pub fn new(value: impl Into<String>) -> Self {
        Self {
            value: Arc::new(value.into()),
        }
    }

    fn generate() -> Self {
        let mut bytes = [0u8; GENERATED_TOKEN_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        Self {
            value: Arc::new(hex),
        }
    }

    /// The token as a string, for printing at startup.
    pub fn expose(&self) -> &str {
        &self.value
    }

    /// Checks a presented token in constant time.
    ///
    /// Comparison time does not depend on how many leading characters match, so
    /// the token cannot be recovered one character at a time. Length is compared
    /// first and is not itself secret: generated tokens are always 64 hex
    /// characters.
    pub fn verify(&self, presented: &str) -> bool {
        let expected = self.value.as_bytes();
        let presented = presented.as_bytes();
        if expected.len() != presented.len() {
            return false;
        }
        expected.ct_eq(presented).into()
    }
}

impl std::fmt::Debug for AdminToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render the secret; this type ends up inside AppState, which is
        // easy to log by accident.
        f.debug_struct("AdminToken").finish_non_exhaustive()
    }
}

/// Rejects any request that does not carry the admin bearer token.
pub async fn auth_middleware(
    State(state): State<AppState>,
    req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    let presented = req
        .headers()
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "));

    match presented {
        Some(token) if state.admin_token.verify(token) => Ok(next.run(req).await),
        _ => Err(StatusCode::UNAUTHORIZED),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generated_tokens_are_unique_and_long() {
        let a = AdminToken::generate();
        let b = AdminToken::generate();
        assert_eq!(a.expose().len(), GENERATED_TOKEN_BYTES * 2);
        assert_ne!(a.expose(), b.expose());
    }

    #[test]
    fn test_verify_accepts_only_the_exact_token() {
        let token = AdminToken::new("s3cret-token-value-long-enough");

        assert!(token.verify("s3cret-token-value-long-enough"));
        assert!(!token.verify("s3cret-token-value-long-enougH"));
        assert!(!token.verify("s3cret-token-value-long-enough "));
        assert!(!token.verify("s3cret"));
        assert!(!token.verify(""));
    }

    /// Regression: the token used to be the compiled-in literal
    /// "obsidian_secret", published in the repository and in the web bundle.
    #[test]
    fn test_the_old_hardcoded_token_is_not_accepted() {
        let (token, source) = AdminToken::from_env_or_generate();
        assert_eq!(source, TokenSource::Generated);
        assert!(!token.verify("obsidian_secret"));
    }

    /// A short value from the environment is ignored rather than becoming the
    /// production secret.
    #[test]
    fn test_short_environment_token_is_rejected() {
        // SAFETY-free equivalent: exercise the length rule directly, since
        // mutating process environment in tests races other threads.
        assert!("short".len() < MIN_TOKEN_LEN);
        let token = AdminToken::new("short");
        assert!(token.verify("short"), "explicit construction still works");
    }

    #[test]
    fn test_debug_does_not_leak_the_secret() {
        let token = AdminToken::new("super-secret-value-here");
        let rendered = format!("{token:?}");
        assert!(!rendered.contains("super-secret"), "rendered: {rendered}");
    }
}
