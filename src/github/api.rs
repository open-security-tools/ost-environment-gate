use std::{env, net::IpAddr, time::Duration};

use reqwest::{
    header::{HeaderMap, RETRY_AFTER},
    StatusCode,
};
use tokio::time::sleep;

use crate::error::AppError;

const DEFAULT_GITHUB_API_URL: &str = "https://api.github.com/";
const GITHUB_API_VERSION: &str = "2022-11-28";
const GITHUB_REQUEST_MAX_ATTEMPTS: usize = 3;
const GITHUB_REQUEST_INITIAL_BACKOFF: Duration = Duration::from_millis(200);

/// Stores the configured base URL for GitHub API requests.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GithubApiBase(reqwest::Url);

impl GithubApiBase {
    /// Loads the GitHub API base URL from the environment or falls back to the public default.
    pub fn from_env() -> Result<Self, AppError> {
        let github_api_url =
            env::var("GITHUB_API_URL").unwrap_or_else(|_| DEFAULT_GITHUB_API_URL.to_string());
        Self::try_from(github_api_url)
    }

    /// Returns the underlying GitHub API base URL.
    pub fn as_url(&self) -> &reqwest::Url {
        &self.0
    }
}

impl AsRef<reqwest::Url> for GithubApiBase {
    /// Borrows the configured GitHub API base URL.
    fn as_ref(&self) -> &reqwest::Url {
        self.as_url()
    }
}

impl TryFrom<reqwest::Url> for GithubApiBase {
    type Error = AppError;

    /// Wraps a parsed URL as a GitHub API base URL.
    fn try_from(value: reqwest::Url) -> Result<Self, Self::Error> {
        if !has_allowed_github_api_scheme(&value) {
            return Err(AppError::InvalidGithubApiUrl);
        }

        Ok(Self(normalize_github_api_base(value)))
    }
}

impl TryFrom<String> for GithubApiBase {
    type Error = AppError;

    /// Parses and validates a GitHub API base URL from an owned string.
    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err(AppError::InvalidGithubApiUrl);
        }
        let url = reqwest::Url::parse(&value).map_err(|_| AppError::InvalidGithubApiUrl)?;
        Self::try_from(url)
    }
}

/// Adds the standard GitHub API authentication and version headers to a request.
pub fn github_request(builder: reqwest::RequestBuilder, token: &str) -> reqwest::RequestBuilder {
    builder
        .bearer_auth(token)
        .header("accept", "application/vnd.github+json")
        .header("x-github-api-version", GITHUB_API_VERSION)
}

/// Sends a GitHub API request with retries for transient transport and server failures.
pub async fn send_github_request(
    builder: reqwest::RequestBuilder,
    operation: &'static str,
) -> Result<reqwest::Response, reqwest::Error> {
    let mut builder = builder;
    let mut backoff = GITHUB_REQUEST_INITIAL_BACKOFF;

    for attempt in 1..=GITHUB_REQUEST_MAX_ATTEMPTS {
        let next_builder = (attempt < GITHUB_REQUEST_MAX_ATTEMPTS)
            .then(|| builder.try_clone())
            .flatten();

        match builder.send().await {
            Ok(response) if is_retryable_response(response.status(), response.headers()) => {
                if let Some(next_builder) = next_builder {
                    let retry_delay = retry_delay(response.status(), response.headers(), backoff);
                    tracing::warn!(
                        operation,
                        attempt,
                        status = %response.status(),
                        retry_delay_ms = retry_delay.as_millis(),
                        "github request returned retryable status"
                    );
                    sleep(retry_delay).await;
                    builder = next_builder;
                    backoff = backoff.saturating_mul(2);
                    continue;
                }

                return Ok(response);
            }
            Ok(response) => return Ok(response),
            Err(error) if is_retryable_error(&error) => {
                if let Some(next_builder) = next_builder {
                    tracing::warn!(
                        operation,
                        attempt,
                        ?error,
                        retry_delay_ms = backoff.as_millis(),
                        "github request failed with retryable transport error"
                    );
                    sleep(backoff).await;
                    builder = next_builder;
                    backoff = backoff.saturating_mul(2);
                    continue;
                }

                return Err(error);
            }
            Err(error) => return Err(error),
        }
    }

    unreachable!("github request retry loop always returns or retries")
}

/// Resolves a relative GitHub API path against the configured API base URL.
pub fn github_api_url(base: &GithubApiBase, path: &str) -> Result<reqwest::Url, AppError> {
    base.as_url()
        .join(path)
        .map_err(|_| AppError::InvalidGithubApiUrl)
}

fn has_allowed_github_api_scheme(url: &reqwest::Url) -> bool {
    match url.scheme() {
        "https" => true,
        "http" => url.host_str().is_some_and(is_loopback_host),
        _ => false,
    }
}

fn is_loopback_host(host: &str) -> bool {
    let host = host
        .strip_prefix('[')
        .and_then(|host| host.strip_suffix(']'))
        .unwrap_or(host);

    host.eq_ignore_ascii_case("localhost")
        || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

fn normalize_github_api_base(mut url: reqwest::Url) -> reqwest::Url {
    if !url.path().ends_with('/') {
        let normalized_path = format!("{}/", url.path());
        url.set_path(&normalized_path);
    }

    url
}

fn retry_delay(status: StatusCode, headers: &HeaderMap, fallback: Duration) -> Duration {
    if is_retryable_response(status, headers) {
        retry_after_delay(headers).unwrap_or(fallback)
    } else {
        fallback
    }
}

fn retry_after_delay(headers: &HeaderMap) -> Option<Duration> {
    headers
        .get(RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse::<u64>()
        .ok()
        .map(Duration::from_secs)
}

fn is_retryable_status(status: StatusCode) -> bool {
    matches!(
        status,
        StatusCode::TOO_MANY_REQUESTS
            | StatusCode::INTERNAL_SERVER_ERROR
            | StatusCode::BAD_GATEWAY
            | StatusCode::SERVICE_UNAVAILABLE
            | StatusCode::GATEWAY_TIMEOUT
    )
}

fn is_retryable_response(status: StatusCode, headers: &HeaderMap) -> bool {
    is_retryable_status(status)
        || (status == StatusCode::FORBIDDEN && headers.contains_key(RETRY_AFTER))
}

fn is_retryable_error(error: &reqwest::Error) -> bool {
    error.is_timeout() || error.is_connect()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use reqwest::header::{HeaderMap, HeaderValue, RETRY_AFTER};
    use wiremock::{
        matchers::{method, path},
        Mock, MockServer, ResponseTemplate,
    };

    use super::{github_api_url, retry_delay, send_github_request, GithubApiBase};

    #[test]
    fn github_api_base_normalizes_trailing_slash_for_path_prefixes() {
        let base = GithubApiBase::try_from(String::from("https://ghe.example.com/api/v3")).unwrap();

        let url = github_api_url(&base, "repos/octo/tools").unwrap();

        assert_eq!(
            url.as_str(),
            "https://ghe.example.com/api/v3/repos/octo/tools"
        );
    }

    #[test]
    fn github_api_base_keeps_root_urls_working() {
        let base = GithubApiBase::try_from(String::from("https://api.github.com")).unwrap();

        let url = github_api_url(&base, "repos/octo/tools").unwrap();

        assert_eq!(url.as_str(), "https://api.github.com/repos/octo/tools");
    }

    #[test]
    fn github_api_base_rejects_non_https_non_loopback_urls() {
        assert!(GithubApiBase::try_from(String::from("http://ghe.example.com/api/v3")).is_err());
    }

    #[test]
    fn github_api_base_accepts_http_loopback_urls() {
        let base = GithubApiBase::try_from(String::from("http://127.0.0.1:8080/api/v3")).unwrap();

        let url = github_api_url(&base, "repos/octo/tools").unwrap();

        assert_eq!(
            url.as_str(),
            "http://127.0.0.1:8080/api/v3/repos/octo/tools"
        );
    }

    #[test]
    fn retry_delay_uses_retry_after_when_present() {
        let mut headers = HeaderMap::new();
        headers.insert(RETRY_AFTER, HeaderValue::from_static("7"));

        assert_eq!(
            retry_delay(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                &headers,
                Duration::from_millis(200)
            ),
            Duration::from_secs(7)
        );
    }

    #[test]
    fn retry_delay_falls_back_when_retry_after_is_missing_or_invalid() {
        let mut invalid_headers = HeaderMap::new();
        invalid_headers.insert(RETRY_AFTER, HeaderValue::from_static("later"));

        assert_eq!(
            retry_delay(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                &HeaderMap::new(),
                Duration::from_millis(200)
            ),
            Duration::from_millis(200)
        );
        assert_eq!(
            retry_delay(
                reqwest::StatusCode::TOO_MANY_REQUESTS,
                &invalid_headers,
                Duration::from_millis(200)
            ),
            Duration::from_millis(200)
        );
    }

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn test_http_client_with_timeout(timeout: Duration) -> reqwest::Client {
        reqwest::Client::builder().timeout(timeout).build().unwrap()
    }

    #[tokio::test]
    async fn send_github_request_retries_retryable_statuses_once_before_success() {
        let server = MockServer::start().await;
        let client = test_http_client();

        for status in [429, 500, 502, 503, 504] {
            server.reset().await;

            Mock::given(method("GET"))
                .and(path("/retry"))
                .respond_with(ResponseTemplate::new(status))
                .up_to_n_times(1)
                .expect(1)
                .mount(&server)
                .await;

            Mock::given(method("GET"))
                .and(path("/retry"))
                .respond_with(ResponseTemplate::new(200))
                .expect(1)
                .mount(&server)
                .await;

            let response = send_github_request(
                client.get(format!("{}/retry", server.uri())),
                "retryable status test",
            )
            .await
            .unwrap();

            assert_eq!(response.status(), reqwest::StatusCode::OK);
            assert_eq!(server.received_requests().await.unwrap().len(), 2);
        }
    }

    #[tokio::test]
    async fn send_github_request_retries_forbidden_with_retry_after_before_success() {
        let server = MockServer::start().await;
        let client = test_http_client();

        Mock::given(method("GET"))
            .and(path("/secondary-rate-limit"))
            .respond_with(ResponseTemplate::new(403).insert_header("retry-after", "1"))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/secondary-rate-limit"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let response = send_github_request(
            client.get(format!("{}/secondary-rate-limit", server.uri())),
            "secondary rate limit test",
        )
        .await
        .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }

    #[tokio::test]
    async fn send_github_request_does_not_retry_non_retryable_status() {
        let server = MockServer::start().await;
        let client = test_http_client();

        Mock::given(method("GET"))
            .and(path("/not-found"))
            .respond_with(ResponseTemplate::new(404))
            .expect(1)
            .mount(&server)
            .await;

        let response = send_github_request(
            client.get(format!("{}/not-found", server.uri())),
            "non-retryable status test",
        )
        .await
        .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::NOT_FOUND);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn send_github_request_does_not_retry_forbidden_without_retry_after() {
        let server = MockServer::start().await;
        let client = test_http_client();

        Mock::given(method("GET"))
            .and(path("/forbidden"))
            .respond_with(ResponseTemplate::new(403))
            .expect(1)
            .mount(&server)
            .await;

        let response = send_github_request(
            client.get(format!("{}/forbidden", server.uri())),
            "forbidden test",
        )
        .await
        .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::FORBIDDEN);
        assert_eq!(server.received_requests().await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn send_github_request_retries_timeout_errors_before_success() {
        let server = MockServer::start().await;
        let client = test_http_client_with_timeout(Duration::from_millis(20));

        Mock::given(method("GET"))
            .and(path("/timeout"))
            .respond_with(ResponseTemplate::new(200).set_delay(Duration::from_millis(100)))
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/timeout"))
            .respond_with(ResponseTemplate::new(200))
            .expect(1)
            .mount(&server)
            .await;

        let response = send_github_request(
            client.get(format!("{}/timeout", server.uri())),
            "timeout retry test",
        )
        .await
        .unwrap();

        assert_eq!(response.status(), reqwest::StatusCode::OK);
        assert_eq!(server.received_requests().await.unwrap().len(), 2);
    }
}
