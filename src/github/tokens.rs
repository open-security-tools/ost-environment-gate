use std::{
    fmt,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{
    error::AppError,
    github::{github_api_url, github_request, send_github_request, GithubApiBase},
};

id_type!(InstallationId);

/// Wraps a sensitive GitHub access token while redacting its display output.
#[derive(Clone, PartialEq, Eq)]
pub struct Token(String);

impl Token {
    /// Returns the underlying token string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Token {
    /// Borrows the token as a string slice.
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for Token {
    /// Formats the token using a redacted debug representation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

impl fmt::Display for Token {
    /// Formats the token using a redacted display representation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("<redacted>")
    }
}

impl<'de> Deserialize<'de> for Token {
    /// Deserializes a token from its raw string representation.
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

/// Contains the installation token returned by GitHub for an app installation.
#[derive(Debug, Clone, Deserialize)]
pub struct InstallationToken {
    pub token: Token,
}

/// Defines the JWT claims used to authenticate as a GitHub App.
#[derive(Debug, Serialize)]
struct AppJwtClaims<'a> {
    iat: u64,
    exp: u64,
    iss: &'a str,
}

/// Creates a signed GitHub App JWT for authenticating installation token requests.
pub fn create_app_jwt(
    app_id: impl AsRef<str>,
    private_key_pem: impl AsRef<str>,
) -> Result<String, AppError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| Duration::from_secs(0))
        .as_secs();

    let claims = AppJwtClaims {
        iat: now.saturating_sub(60),
        exp: now + 9 * 60,
        iss: app_id.as_ref(),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.typ = Some("JWT".to_string());

    jsonwebtoken::encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_key_pem.as_ref().as_bytes()).map_err(|error| {
            tracing::error!(?error, "failed to parse github app private key");
            AppError::GithubAppAuthInvalid
        })?,
    )
    .map_err(|error| {
        tracing::error!(?error, "failed to encode github app jwt");
        AppError::GithubAppAuthInvalid
    })
}

/// Requests an installation token from GitHub for the specified repository scope and permissions.
pub async fn mint_installation_token(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    app_jwt: &str,
    installation_id: u64,
    repository_ids: &[u64],
    permissions: Value,
) -> Result<InstallationToken, AppError> {
    let url = github_api_url(
        github_api_base,
        &format!("app/installations/{installation_id}/access_tokens"),
    )?;
    let payload = json!({
        "repository_ids": repository_ids,
        "permissions": permissions,
    });

    // TODO: Revisit retries here. This endpoint is non-idempotent, so retrying after
    // an ambiguous transport failure can mint multiple valid installation tokens.
    let response = send_github_request(
        github_request(http_client.post(url), app_jwt).json(&payload),
        "installation token request",
    )
    .await
    .map_err(|error| {
        tracing::error!(?error, "installation token request failed");
        AppError::GithubAccessTokenRequestFailed
    })?;

    match response.status().as_u16() {
        201 => response.json::<InstallationToken>().await.map_err(|error| {
            tracing::error!(?error, "failed to decode installation token response");
            AppError::GithubAccessTokenRequestFailed
        }),
        401 => Err(AppError::GithubAppAuthInvalid),
        403 => Err(AppError::GithubAccessTokenRequestForbidden),
        404 => Err(AppError::InstallationNotFound),
        422 => Err(AppError::InstallationTokenRequestInvalid),
        _ => {
            tracing::error!(status = %response.status(), "unexpected installation token status");
            Err(AppError::GithubAccessTokenRequestFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{mint_installation_token, InstallationToken, Token};
    use crate::github::GithubApiBase;
    use serde_json::json;
    use wiremock::{
        matchers::{body_json, header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn test_base_url(server: &MockServer) -> GithubApiBase {
        GithubApiBase::try_from(server.uri()).unwrap()
    }

    #[tokio::test]
    async fn mint_installation_token_posts_expected_request() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/app/installations/123/access_tokens"))
            .and(header("authorization", "Bearer app-jwt"))
            .and(header("accept", "application/vnd.github+json"))
            .and(header("x-github-api-version", "2022-11-28"))
            .and(body_json(json!({
                "repository_ids": [42],
                "permissions": { "actions": "read", "deployments": "write" },
            })))
            .respond_with(ResponseTemplate::new(201).set_body_json(json!({
                "token": "installation-token"
            })))
            .mount(&server)
            .await;

        let token = mint_installation_token(
            &test_http_client(),
            &test_base_url(&server),
            "app-jwt",
            123,
            &[42],
            json!({ "actions": "read", "deployments": "write" }),
        )
        .await
        .unwrap();

        assert_eq!(token.token.as_str(), "installation-token");
    }

    #[tokio::test]
    async fn mint_installation_token_maps_error_statuses() {
        let server = MockServer::start().await;

        for (status, expected) in [
            (401, "GithubAppAuthInvalid"),
            (403, "GithubAccessTokenRequestForbidden"),
            (404, "InstallationNotFound"),
            (422, "InstallationTokenRequestInvalid"),
            (500, "GithubAccessTokenRequestFailed"),
        ] {
            Mock::given(method("POST"))
                .and(path("/app/installations/999/access_tokens"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&server)
                .await;

            let error = mint_installation_token(
                &test_http_client(),
                &test_base_url(&server),
                "app-jwt",
                999,
                &[1],
                json!({ "actions": "read", "deployments": "write" }),
            )
            .await
            .unwrap_err();

            assert!(
                format!("{error:?}").contains(expected),
                "status {status} should produce {expected}, got {error:?}"
            );

            server.reset().await;
        }
    }

    #[test]
    fn token_debug_is_redacted() {
        let token = Token("secret-value".to_string());
        assert_eq!(format!("{token:?}"), "Token(<redacted>)");
        assert_eq!(format!("{token}"), "<redacted>");
        assert_eq!(token.as_str(), "secret-value");
    }

    #[test]
    fn installation_token_deserializes_redacted_token() {
        let token: InstallationToken =
            serde_json::from_value(json!({ "token": "installation-token" })).unwrap();

        assert_eq!(token.token.as_str(), "installation-token");
    }
}
