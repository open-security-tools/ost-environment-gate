use lambda_http::http::{Method, StatusCode};
use lambda_http::{run, service_fn, Body, Error, Request, Response};
use tracing::Instrument;

use crate::error::AppError;
use crate::response::AppResponse;

macro_rules! impl_string_newtype {
    ($name:ident, $error_ty:ty, $error:expr $(, validate = $validate:expr)? ) => {
        impl $name {
            /// Returns the validated string slice.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl AsRef<str> for $name {
            /// Borrows the validated string as a `&str`.
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl std::fmt::Display for $name {
            /// Formats the validated string without additional decoration.
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl TryFrom<String> for $name {
            type Error = $error_ty;

            /// Validates that an owned string remains non-empty after trimming.
            fn try_from(value: String) -> Result<Self, Self::Error> {
                let value = value.trim().to_string();
                if value.is_empty() {
                    return Err($error);
                }
                $(
                    if !($validate)(&value) {
                        return Err($error);
                    }
                )?
                Ok(Self(value))
            }
        }

        impl TryFrom<&str> for $name {
            type Error = $error_ty;

            /// Validates that a borrowed string remains non-empty after trimming.
            fn try_from(value: &str) -> Result<Self, Self::Error> {
                value.to_owned().try_into()
            }
        }
    };
}

pub(crate) use impl_string_newtype;

mod config;
mod error;
mod github;
mod queue;
mod response;
mod rule;
mod worker;

/// Starts the Lambda runtime for the environment gate service.
#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    if std::env::var("HANDLER_MODE").as_deref() == Ok("worker") {
        let config = config::Config::load().await?;
        return lambda_runtime::run(lambda_runtime::service_fn(
            move |event: lambda_runtime::LambdaEvent<worker::SqsEvent>| {
                let config = config.clone();
                async move { worker::handle_batch(config, event.payload).await }
            },
        ))
        .await;
    }

    let config = config::WebhookConfig::load().await?;

    run(service_fn(move |request: Request| {
        let config = config.clone();
        async move {
            match handle_request(config, request).await {
                Ok(response) => Ok::<Response<Body>, Error>(response.into_response()),
                Err(error) => Ok::<Response<Body>, Error>(error.into_response()),
            }
        }
    }))
    .await
}

/// Routes an incoming HTTP request to the appropriate handler.
async fn handle_request(
    config: config::WebhookConfig,
    request: Request,
) -> Result<AppResponse, AppError> {
    match (request.method().clone(), request.uri().path()) {
        (Method::GET, "/health") => Ok(AppResponse::health("ost-environment-gate")),
        (Method::POST, "/github/webhook") => handle_github_webhook(config, request).await,
        _ => Err(AppError::NotFound),
    }
}

/// Returns a borrowed byte slice view of the Lambda request body.
fn request_body_bytes(request: &Request) -> &[u8] {
    match request.body() {
        Body::Empty => &[],
        Body::Text(text) => text.as_bytes(),
        Body::Binary(bytes) => bytes.as_slice(),
    }
}

/// Verifies and processes a GitHub webhook request.
async fn handle_github_webhook(
    config: config::WebhookConfig,
    request: Request,
) -> Result<AppResponse, AppError> {
    let delivery_id = request
        .headers()
        .get("x-github-delivery")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("<missing>")
        .to_string();
    let span = tracing::info_span!("github_webhook", delivery_id = %delivery_id);

    let result: Result<AppResponse, AppError> = async move {
        let signature = github::WebhookSignature::try_from(&request)?;
        let event = github::WebhookEvent::try_from(&request)?;
        let body_bytes = request_body_bytes(&request);

        signature.verify(&config.webhook_secret, body_bytes)?;

        match event {
            github::WebhookEvent::Ping => {
                tracing::info!(webhook_event = "ping", outcome = "acknowledged");
                Ok(AppResponse::status(StatusCode::NO_CONTENT))
            }
            github::WebhookEvent::Other(event) => {
                tracing::info!(webhook_event = %event, outcome = "ignored");
                Ok(AppResponse::status(StatusCode::NO_CONTENT))
            }
            github::WebhookEvent::DeploymentProtectionRule => {
                let payload: github::DeploymentProtectionRulePayload =
                    serde_json::from_slice(body_bytes)
                        .map_err(|_| AppError::DeploymentProtectionPayloadInvalid)?;
                let action = payload.action.as_deref().unwrap_or_default();
                if action != "requested" {
                    tracing::info!(
                        webhook_event = "deployment_protection_rule",
                        outcome = "ignored",
                        action = %action
                    );
                    return Ok(AppResponse::status(StatusCode::NO_CONTENT));
                }

                let requested = github::RequestedDeploymentProtection::parse(
                    payload.clone(),
                    &config.github_api_base,
                )?;
                config
                    .deployment_review_queue
                    .enqueue(&delivery_id, payload, &requested)
                    .await?;
                tracing::info!(
                    webhook_event = "deployment_protection_rule",
                    outcome = "queued",
                    repository = %requested.repository,
                    run_id = *requested.run_id,
                    environment = %requested.environment,
                    deployment_id = ?requested.deployment_id
                );
                Ok(AppResponse::status(StatusCode::NO_CONTENT))
            }
        }
    }
    .instrument(span.clone())
    .await;

    if let Err(error) = &result {
        span.in_scope(|| {
            tracing::error!(
                code = error.code(),
                status = %error.status(),
                error = %error,
                "github webhook request failed"
            );
        });
    }

    result
}

#[cfg(test)]
mod integration_tests {
    use super::handle_request;
    use crate::config;
    use hmac::{Hmac, Mac};
    use lambda_http::http::{Request as HttpRequest, StatusCode};
    use lambda_http::{Body, Request, Response};
    use rand::thread_rng;
    use rsa::pkcs8::EncodePrivateKey;
    use serde_json::{json, Value};
    use sha2::Sha256;
    use std::sync::OnceLock;
    use wiremock::{
        matchers::{body_json, method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    type HmacSha256 = Hmac<Sha256>;

    const WEBHOOK_SECRET: &str = "super-secret";
    const RUN_ID: u64 = 23625057533;
    const INSTALLATION_ID: u64 = 119022551;
    const REPOSITORY_ID: u64 = 1192056896;
    const GATE_DEPLOYMENT_ID: u64 = 4189575564;
    const GATE_JOB_ID: u64 = 69582278191;
    const OWNER: &str = "zaniebot";
    const REPO: &str = "release-authenticator-example";
    const SHA: &str = "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54";

    struct Harness {
        server: MockServer,
        config: config::Config,
        webhook_config: config::WebhookConfig,
    }

    impl Harness {
        async fn new() -> Self {
            Self::new_with_policy(test_policy()).await
        }

        async fn new_with_policy(policy: config::Policy) -> Self {
            let server = MockServer::start().await;
            let config = config::Config {
                policy,
                app_id: "123".to_string().try_into().unwrap(),
                app_private_key: test_app_private_key().to_string().try_into().unwrap(),
                github_api_base: server.uri().try_into().unwrap(),
                http_client: config::build_http_client().unwrap(),
            };

            let webhook_config = config::WebhookConfig {
                webhook_secret: WEBHOOK_SECRET.to_string().try_into().unwrap(),
                github_api_base: server.uri().try_into().unwrap(),
                deployment_review_queue: crate::queue::DeploymentReviewQueue::in_memory(),
            };

            Self {
                server,
                config,
                webhook_config,
            }
        }

        async fn dispatch(&self, request: Request) -> Response<Body> {
            let response = self.enqueue(request).await;
            if !response.status().is_success() {
                return response;
            }

            for message in self.webhook_config.deployment_review_queue.take_messages() {
                let message: crate::queue::DeploymentReviewMessage =
                    serde_json::from_str(&message.body).unwrap();
                let body = serde_json::to_vec(&message.payload).unwrap();
                if let Err(error) = crate::rule::handle_deployment_protection_rule_webhook(
                    self.config.clone(),
                    &body,
                )
                .await
                {
                    return error.into_response();
                }
            }

            response
        }

        async fn enqueue(&self, request: Request) -> Response<Body> {
            match handle_request(self.webhook_config.clone(), request).await {
                Ok(response) => response.into_response(),
                Err(error) => error.into_response(),
            }
        }

        async fn process_batch(&self, messages: &[crate::queue::QueuedDeploymentReview]) -> Value {
            let event = serde_json::from_value(json!({
                "Records": messages
                    .iter()
                    .enumerate()
                    .map(|(index, message)| json!({
                        "messageId": format!("message-{index}"),
                        "body": message.body,
                        "attributes": { "MessageGroupId": message.group_id },
                    }))
                    .collect::<Vec<_>>()
            }))
            .unwrap();

            serde_json::to_value(
                crate::worker::handle_batch(self.config.clone(), event)
                    .await
                    .unwrap(),
            )
            .unwrap()
        }

        fn requested_payload(&self) -> Value {
            let mut payload: Value = serde_json::from_str(include_str!(
                "../testdata/deployment-protection-requested.json"
            ))
            .unwrap();
            payload["deployment_callback_url"] = json!(format!(
                "{}/repos/{OWNER}/{REPO}/actions/runs/{RUN_ID}/deployment_protection_rule",
                self.server.uri()
            ));
            payload
        }

        fn webhook_request(&self, event: &str, payload: &Value) -> Request {
            self.webhook_request_with_delivery(
                event,
                payload,
                "00000000-0000-4000-8000-000000000001",
            )
        }

        fn webhook_request_with_delivery(
            &self,
            event: &str,
            payload: &Value,
            delivery_id: &str,
        ) -> Request {
            let body = serde_json::to_vec(payload).unwrap();
            let signature = sign_webhook(WEBHOOK_SECRET, &body);

            HttpRequest::builder()
                .method("POST")
                .uri("/github/webhook")
                .header("x-github-event", event)
                .header("x-github-delivery", delivery_id)
                .header("x-hub-signature-256", signature)
                .body(Body::Binary(body))
                .unwrap()
        }

        fn webhook_request_with_signature(
            &self,
            event: &str,
            payload: &Value,
            signature: &str,
        ) -> Request {
            let body = serde_json::to_vec(payload).unwrap();

            HttpRequest::builder()
                .method("POST")
                .uri("/github/webhook")
                .header("x-github-event", event)
                .header("x-hub-signature-256", signature)
                .body(Body::Binary(body))
                .unwrap()
        }

        fn webhook_request_without_signature(&self, event: &str, payload: &Value) -> Request {
            let body = serde_json::to_vec(payload).unwrap();

            HttpRequest::builder()
                .method("POST")
                .uri("/github/webhook")
                .header("x-github-event", event)
                .body(Body::Binary(body))
                .unwrap()
        }

        fn webhook_request_without_event(&self, payload: &Value) -> Request {
            let body = serde_json::to_vec(payload).unwrap();
            let signature = sign_webhook(WEBHOOK_SECRET, &body);

            HttpRequest::builder()
                .method("POST")
                .uri("/github/webhook")
                .header("x-hub-signature-256", signature)
                .body(Body::Binary(body))
                .unwrap()
        }

        async fn mock_installation_token(&self, status: u16) {
            let template = if status == 201 {
                ResponseTemplate::new(status)
                    .set_body_json(json!({ "token": "installation-token" }))
            } else {
                ResponseTemplate::new(status)
            };

            let mut mock = Mock::given(method("POST")).and(path(installation_token_path()));
            if status == 201 {
                mock = mock.and(body_json(json!({
                    "repository_ids": [REPOSITORY_ID],
                    "permissions": { "actions": "read", "deployments": "write" },
                })));
            }

            mock.respond_with(template).mount(&self.server).await;
        }

        async fn mock_workflow_run_path(&self, workflow_path: &str) {
            self.mock_workflow_run_summary(
                workflow_path,
                &format!("{OWNER}/{REPO}"),
                "workflow_dispatch",
            )
            .await;
        }

        async fn mock_workflow_run_path_and_head_repository(
            &self,
            workflow_path: &str,
            head_repository_full_name: &str,
        ) {
            self.mock_workflow_run_summary(
                workflow_path,
                head_repository_full_name,
                "workflow_dispatch",
            )
            .await;
        }

        async fn mock_workflow_run_summary(
            &self,
            workflow_path: &str,
            head_repository_full_name: &str,
            event: &str,
        ) {
            Mock::given(method("GET"))
                .and(path(workflow_run_path()))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "path": workflow_path,
                    "event": event,
                    "head_repository": {
                        "full_name": head_repository_full_name,
                    }
                })))
                .mount(&self.server)
                .await;
        }

        async fn mock_workflow_run_status(&self, status: u16) {
            Mock::given(method("GET"))
                .and(path(workflow_run_path()))
                .respond_with(ResponseTemplate::new(status))
                .mount(&self.server)
                .await;
        }

        async fn mock_gate_deployment(&self) {
            self.mock_gate_deployments(&[GATE_DEPLOYMENT_ID]).await;
        }

        async fn mock_gate_deployments(&self, deployment_ids: &[u64]) {
            Mock::given(method("GET"))
                .and(path(deployments_path()))
                .and(query_param("environment", "release-gate"))
                .and(query_param("sha", SHA))
                .and(query_param("per_page", "100"))
                .respond_with(
                    ResponseTemplate::new(200).set_body_json(
                        deployment_ids
                            .iter()
                            .map(|id| json!({ "id": id }))
                            .collect::<Vec<_>>(),
                    ),
                )
                .mount(&self.server)
                .await;
        }

        async fn mock_missing_gate_deployment(&self) {
            Mock::given(method("GET"))
                .and(path(deployments_path()))
                .and(query_param("environment", "release-gate"))
                .and(query_param("sha", SHA))
                .and(query_param("per_page", "100"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
                .mount(&self.server)
                .await;
        }

        async fn mock_deployment_lookup_status(&self, status: u16) {
            Mock::given(method("GET"))
                .and(path(deployments_path()))
                .and(query_param("environment", "release-gate"))
                .and(query_param("sha", SHA))
                .and(query_param("per_page", "100"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&self.server)
                .await;
        }

        async fn mock_gate_deployment_status(&self, state: &str) {
            Mock::given(method("GET"))
                .and(path(deployment_statuses_path()))
                .and(query_param("per_page", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    {
                        "state": state,
                        "log_url": format!(
                            "https://github.com/{OWNER}/{REPO}/actions/runs/{RUN_ID}/job/{GATE_JOB_ID}"
                        ),
                        "target_url": format!(
                            "https://github.com/{OWNER}/{REPO}/actions/runs/{RUN_ID}/job/{GATE_JOB_ID}"
                        )
                    }
                ])))
                .mount(&self.server)
                .await;
        }

        async fn mock_gate_deployment_status_without_job_url(&self, state: &str) {
            Mock::given(method("GET"))
                .and(path(deployment_statuses_path()))
                .and(query_param("per_page", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    { "state": state }
                ])))
                .mount(&self.server)
                .await;
        }

        async fn mock_gate_deployment_status_with_mismatched_job_urls(&self, state: &str) {
            Mock::given(method("GET"))
                .and(path(deployment_statuses_path()))
                .and(query_param("per_page", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    {
                        "state": state,
                        "log_url": format!(
                            "https://github.com/{OWNER}/{REPO}/actions/runs/{RUN_ID}/job/{GATE_JOB_ID}"
                        ),
                        "target_url": format!(
                            "https://github.com/{OWNER}/{REPO}/actions/runs/{RUN_ID}/job/{}",
                            GATE_JOB_ID + 1
                        )
                    }
                ])))
                .mount(&self.server)
                .await;
        }

        async fn mock_gate_deployment_status_with_custom_urls(
            &self,
            state: &str,
            log_url: Option<String>,
            target_url: Option<String>,
        ) {
            Mock::given(method("GET"))
                .and(path(deployment_statuses_path()))
                .and(query_param("per_page", "1"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                    {
                        "state": state,
                        "log_url": log_url,
                        "target_url": target_url
                    }
                ])))
                .mount(&self.server)
                .await;
        }

        async fn mock_gate_deployment_status_lookup(&self, status: u16) {
            Mock::given(method("GET"))
                .and(path(deployment_statuses_path()))
                .and(query_param("per_page", "1"))
                .respond_with(ResponseTemplate::new(status))
                .mount(&self.server)
                .await;
        }

        async fn mock_gate_workflow_job(
            &self,
            name: &str,
            conclusion: &str,
            run_id: u64,
            sha: &str,
        ) {
            Mock::given(method("GET"))
                .and(path(workflow_job_path()))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "run_id": run_id,
                    "head_sha": sha,
                    "name": name,
                    "conclusion": conclusion
                })))
                .mount(&self.server)
                .await;
        }

        async fn mock_gate_workflow_job_lookup(&self, status: u16) {
            Mock::given(method("GET"))
                .and(path(workflow_job_path()))
                .respond_with(ResponseTemplate::new(status))
                .mount(&self.server)
                .await;
        }

        async fn mock_review_response(&self, status: u16, expected_body: Option<Value>) {
            let mut mock = Mock::given(method("POST")).and(path(review_path()));
            if let Some(body) = expected_body {
                mock = mock.and(body_json(body));
            }

            mock.respond_with(ResponseTemplate::new(status))
                .mount(&self.server)
                .await;
        }

        async fn mock_pending_deployments(&self, pending: bool) {
            let body = if pending {
                json!([{ "environment": { "name": "release" } }])
            } else {
                json!([])
            };
            Mock::given(method("GET"))
                .and(path(pending_deployments_path()))
                .respond_with(ResponseTemplate::new(200).set_body_json(body))
                .mount(&self.server)
                .await;
        }

        async fn received_paths(&self) -> Vec<String> {
            self.server
                .received_requests()
                .await
                .unwrap()
                .into_iter()
                .map(|request| request.url.path().to_string())
                .collect()
        }
    }

    fn test_policy() -> config::Policy {
        serde_json::from_value(json!({
            "allowed_ref": "refs/heads/main",
            "allowed_events": ["workflow_dispatch"],
            "release_environment_name": "release",
            "release_gate_environment_name": "release-gate",
            "release_gate_job_name": "release-gate",
            "release_workflow_path": ".github/workflows/release.yml"
        }))
        .unwrap()
    }

    fn test_policy_without_gate_job_name() -> config::Policy {
        serde_json::from_value(json!({
            "allowed_ref": "refs/heads/main",
            "allowed_events": ["workflow_dispatch"],
            "release_environment_name": "release",
            "release_gate_environment_name": "release-gate",
            "release_workflow_path": ".github/workflows/release.yml"
        }))
        .unwrap()
    }

    fn test_app_private_key() -> &'static str {
        static APP_PRIVATE_KEY: OnceLock<String> = OnceLock::new();

        APP_PRIVATE_KEY
            .get_or_init(|| {
                let mut rng = thread_rng();
                rsa::RsaPrivateKey::new(&mut rng, 2048)
                    .unwrap()
                    .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
                    .unwrap()
                    .to_string()
            })
            .as_str()
    }

    fn sign_webhook(secret: &str, body: &[u8]) -> String {
        let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let signature = mac.finalize().into_bytes();
        format!("sha256={}", hex::encode(signature))
    }

    fn installation_token_path() -> String {
        format!("/app/installations/{INSTALLATION_ID}/access_tokens")
    }

    fn workflow_run_path() -> String {
        format!("/repos/{OWNER}/{REPO}/actions/runs/{RUN_ID}")
    }

    fn deployments_path() -> String {
        format!("/repos/{OWNER}/{REPO}/deployments")
    }

    fn deployment_statuses_path() -> String {
        deployment_statuses_path_for(GATE_DEPLOYMENT_ID)
    }

    fn deployment_statuses_path_for(deployment_id: u64) -> String {
        format!("/repos/{OWNER}/{REPO}/deployments/{deployment_id}/statuses")
    }

    fn workflow_job_path() -> String {
        format!("/repos/{OWNER}/{REPO}/actions/jobs/{GATE_JOB_ID}")
    }

    fn review_path() -> String {
        format!("/repos/{OWNER}/{REPO}/actions/runs/{RUN_ID}/deployment_protection_rule")
    }

    fn pending_deployments_path() -> String {
        format!("/repos/{OWNER}/{REPO}/actions/runs/{RUN_ID}/pending_deployments")
    }

    fn response_json(response: &Response<Body>) -> Value {
        let bytes = match response.body() {
            Body::Empty => Vec::new(),
            Body::Text(text) => text.as_bytes().to_vec(),
            Body::Binary(bytes) => bytes.to_vec(),
        };

        if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).unwrap()
        }
    }

    fn assert_no_content(response: &Response<Body>) {
        assert_eq!(response.status(), StatusCode::NO_CONTENT);
        assert!(matches!(response.body(), Body::Empty));
    }

    fn assert_path_call_count(paths: &[String], expected_path: &str, expected_calls: usize) {
        let actual_calls = paths
            .iter()
            .filter(|path| path.as_str() == expected_path)
            .count();
        assert_eq!(
            actual_calls, expected_calls,
            "expected {expected_calls} calls to {expected_path}, got {actual_calls}: {paths:?}"
        );
    }

    #[tokio::test]
    async fn health_route_returns_json_ok() {
        let harness = Harness::new().await;

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/health")
            .body(Body::Empty)
            .unwrap();

        let response = harness.dispatch(request).await;

        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_json(&response),
            json!({
                "ok": true,
                "service": "ost-environment-gate"
            })
        );
    }

    #[tokio::test]
    async fn unknown_route_returns_not_found_error() {
        let harness = Harness::new().await;

        let request = HttpRequest::builder()
            .method("GET")
            .uri("/missing")
            .body(Body::Empty)
            .unwrap();

        let response = harness.dispatch(request).await;

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "not_found",
                "error": "not found"
            })
        );
    }

    #[tokio::test]
    async fn webhook_ping_acknowledges_without_github_calls() {
        let harness = Harness::new().await;
        let request = harness.webhook_request("ping", &json!({"hello": "world"}));

        let response = harness.dispatch(request).await;

        assert_no_content(&response);
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_other_event_acknowledges_without_github_calls() {
        let harness = Harness::new().await;
        let request = harness.webhook_request("push", &json!({"hello": "world"}));

        let response = harness.dispatch(request).await;

        assert_no_content(&response);
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_ignores_non_requested_actions_without_calling_github() {
        let harness = Harness::new().await;
        let mut payload = harness.requested_payload();
        payload["action"] = json!("completed");

        let response = harness
            .dispatch(harness.webhook_request("deployment_protection_rule", &payload))
            .await;

        assert_no_content(&response);
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_returns_unauthorized_for_invalid_signature() {
        let harness = Harness::new().await;
        let payload = harness.requested_payload();

        let response = harness
            .dispatch(harness.webhook_request_with_signature(
                "deployment_protection_rule",
                &payload,
                "sha256=deadbeef",
            ))
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "invalid_github_webhook_signature",
                "error": "invalid github webhook signature"
            })
        );
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_returns_unauthorized_when_signature_header_is_missing() {
        let harness = Harness::new().await;
        let payload = harness.requested_payload();

        let response = harness
            .dispatch(
                harness.webhook_request_without_signature("deployment_protection_rule", &payload),
            )
            .await;

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "invalid_github_webhook_signature",
                "error": "invalid github webhook signature"
            })
        );
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_returns_bad_request_when_event_header_is_missing() {
        let harness = Harness::new().await;
        let payload = harness.requested_payload();

        let response = harness
            .dispatch(harness.webhook_request_without_event(&payload))
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "missing_webhook_event",
                "error": "missing or invalid webhook event header"
            })
        );
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_returns_bad_request_for_invalid_deployment_payload() {
        let harness = Harness::new().await;
        let payload = json!({
            "action": "requested",
            "repository": {"full_name": "zaniebot/release-authenticator-example"}
        });

        let response = harness
            .dispatch(harness.webhook_request("deployment_protection_rule", &payload))
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "deployment_protection_payload_invalid",
                "error": "deployment protection payload is invalid"
            })
        );
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_returns_bad_request_for_mismatched_deployment_callback_url() {
        let harness = Harness::new().await;
        let mut payload = harness.requested_payload();
        payload["deployment_callback_url"] = json!(format!(
            "{}/repos/{OWNER}/{REPO}/actions/runs/{}/deployment_protection_rule",
            harness.server.uri(),
            RUN_ID + 1,
        ));

        let response = harness
            .dispatch(harness.webhook_request("deployment_protection_rule", &payload))
            .await;

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "deployment_protection_payload_invalid",
                "error": "deployment protection payload is invalid"
            })
        );
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_returns_unprocessable_entity_for_invalid_run_id_in_callback_url() {
        let harness = Harness::new().await;
        let payload = json!({
            "action": "requested",
            "environment": "release",
            "ref": "main",
            "sha": SHA,
            "installation": { "id": 1 },
            "repository": {
                "id": 1,
                "full_name": "zaniebot/release-authenticator-example"
            },
            "deployment_callback_url": format!(
                "{}/repos/zaniebot/release-authenticator-example/actions/runs/not-a-number/deployment_protection_rule",
                harness.server.uri()
            )
        });

        let response = harness
            .dispatch(harness.webhook_request("deployment_protection_rule", &payload))
            .await;

        assert_eq!(response.status(), StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "deployment_protection_run_id_invalid",
                "error": "deployment protection payload is missing a valid workflow run id"
            })
        );
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_approves_release_when_policy_passes() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "approved",
                    "comment": "release-gate deployment succeeded"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 6, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_approves_when_an_older_gate_deployment_matches_the_expected_job() {
        let harness = Harness::new().await;
        let newer_deployment_id = GATE_DEPLOYMENT_ID + 1;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness
            .mock_gate_deployments(&[newer_deployment_id, GATE_DEPLOYMENT_ID])
            .await;

        Mock::given(method("GET"))
            .and(path(deployment_statuses_path_for(newer_deployment_id)))
            .and(query_param("per_page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "state": "success",
                    "log_url": format!(
                        "https://github.com/{OWNER}/{REPO}/actions/runs/1/job/{GATE_JOB_ID}"
                    ),
                    "target_url": format!(
                        "https://github.com/{OWNER}/{REPO}/actions/runs/1/job/{GATE_JOB_ID}"
                    )
                }
            ])))
            .mount(&harness.server)
            .await;

        Mock::given(method("GET"))
            .and(path(deployment_statuses_path()))
            .and(query_param("per_page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "state": "success",
                    "log_url": format!(
                        "https://github.com/{OWNER}/{REPO}/actions/runs/{RUN_ID}/job/{GATE_JOB_ID}"
                    ),
                    "target_url": format!(
                        "https://github.com/{OWNER}/{REPO}/actions/runs/{RUN_ID}/job/{GATE_JOB_ID}"
                    )
                }
            ])))
            .mount(&harness.server)
            .await;

        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "approved",
                    "comment": "release-gate deployment succeeded"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 7, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(
            &paths,
            &deployment_statuses_path_for(newer_deployment_id),
            1,
        );
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_retries_installation_token_request_on_transient_failure() {
        let harness = Harness::new().await;

        Mock::given(method("POST"))
            .and(path(installation_token_path()))
            .respond_with(ResponseTemplate::new(500))
            .up_to_n_times(1)
            .expect(1)
            .mount(&harness.server)
            .await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "approved",
                    "comment": "release-gate deployment succeeded"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 7, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 2);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_does_not_retry_a_transient_review_submission_in_process() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;

        harness.mock_review_response(503, None).await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 6, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_does_not_retry_an_ambiguous_422_review_submission_in_process() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;

        Mock::given(method("POST"))
            .and(path(review_path()))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "message": "There was a problem approving one of the gates"
            })))
            .expect(1)
            .mount(&harness.server)
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_path_call_count(&harness.received_paths().await, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_queues_and_coalesces_a_29_job_release_burst() {
        let harness = std::sync::Arc::new(Harness::new().await);

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;

        harness.mock_review_response(204, None).await;
        harness.mock_pending_deployments(false).await;

        let mut deliveries = tokio::task::JoinSet::new();
        for index in 1..=29 {
            let harness = harness.clone();
            deliveries.spawn(async move {
                let mut payload = harness.requested_payload();
                payload["deployment"]["id"] = json!(5525311100_u64 + index);
                harness
                    .enqueue(harness.webhook_request_with_delivery(
                        "deployment_protection_rule",
                        &payload,
                        &format!("00000000-0000-4000-8000-{index:012x}"),
                    ))
                    .await
            });
        }
        while let Some(response) = deliveries.join_next().await {
            assert_no_content(&response.unwrap());
        }

        assert!(harness.received_paths().await.is_empty());
        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_eq!(messages.len(), 29);
        assert_eq!(
            messages
                .iter()
                .map(|message| message.group_id.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            1
        );
        assert_eq!(
            messages
                .iter()
                .map(|message| message.deduplication_id.as_str())
                .collect::<std::collections::HashSet<_>>()
                .len(),
            29
        );

        for batch in messages.chunks(10) {
            assert_eq!(
                harness.process_batch(batch).await,
                json!({ "batchItemFailures": [] })
            );
        }

        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &installation_token_path(), 3);
        assert_path_call_count(&paths, &workflow_run_path(), 3);
        assert_path_call_count(&paths, &deployments_path(), 3);
        assert_path_call_count(&paths, &deployment_statuses_path(), 3);
        assert_path_call_count(&paths, &workflow_job_path(), 3);
        assert_path_call_count(&paths, &review_path(), 3);
        assert_path_call_count(&paths, &pending_deployments_path(), 3);
    }

    #[tokio::test]
    async fn webhook_deduplicates_the_same_delivery_but_preserves_later_deployments() {
        let harness = Harness::new().await;
        let mut first = harness.requested_payload();
        first["deployment"]["id"] = json!(5525311101_u64);
        let mut second = harness.requested_payload();
        second["deployment"]["id"] = json!(5525311102_u64);

        for (payload, delivery_id) in [
            (&first, "00000000-0000-4000-8000-000000000001"),
            (&first, "00000000-0000-4000-8000-000000000001"),
            (&second, "00000000-0000-4000-8000-000000000002"),
        ] {
            assert_no_content(
                &harness
                    .enqueue(harness.webhook_request_with_delivery(
                        "deployment_protection_rule",
                        payload,
                        delivery_id,
                    ))
                    .await,
            );
        }

        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].group_id, messages[1].group_id);
        assert_ne!(messages[0].deduplication_id, messages[1].deduplication_id);
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_rejects_invalid_delivery_ids_before_queueing() {
        let harness = Harness::new().await;
        for delivery_id in [
            "not-a-uuid",
            "00000000-0000-0000-0000-000000000000",
            "00000000-0000-4000-8000-00000000000A",
        ] {
            let response = harness
                .enqueue(harness.webhook_request_with_delivery(
                    "deployment_protection_rule",
                    &harness.requested_payload(),
                    delivery_id,
                ))
                .await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response_json(&response),
                json!({
                    "code": "invalid_github_delivery",
                    "error": "missing or invalid github delivery id"
                })
            );
        }

        assert!(harness
            .webhook_config
            .deployment_review_queue
            .take_messages()
            .is_empty());
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn worker_coalesces_environment_names_case_insensitively() {
        let harness = Harness::new().await;
        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        harness.mock_review_response(204, None).await;
        harness.mock_pending_deployments(false).await;

        for (environment, delivery_id, deployment_id) in [
            (
                "release",
                "00000000-0000-4000-8000-000000000001",
                5525311101_u64,
            ),
            (
                "Release",
                "00000000-0000-4000-8000-000000000002",
                5525311102_u64,
            ),
        ] {
            let mut payload = harness.requested_payload();
            payload["environment"] = json!(environment);
            payload["deployment"]["id"] = json!(deployment_id);
            assert_no_content(
                &harness
                    .enqueue(harness.webhook_request_with_delivery(
                        "deployment_protection_rule",
                        &payload,
                        delivery_id,
                    ))
                    .await,
            );
        }

        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_eq!(messages.len(), 2);
        assert_eq!(messages[0].group_id, messages[1].group_id);
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({ "batchItemFailures": [] })
        );
        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &review_path(), 1);
        assert_path_call_count(&paths, &pending_deployments_path(), 1);
    }

    #[tokio::test]
    async fn worker_rejects_conflicting_review_context_within_a_fifo_group() {
        let harness = Harness::new().await;
        for (sha, delivery_id) in [
            (SHA, "00000000-0000-4000-8000-000000000001"),
            (
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "00000000-0000-4000-8000-000000000002",
            ),
        ] {
            let mut payload = harness.requested_payload();
            payload["sha"] = json!(sha);
            assert_no_content(
                &harness
                    .enqueue(harness.webhook_request_with_delivery(
                        "deployment_protection_rule",
                        &payload,
                        delivery_id,
                    ))
                    .await,
            );
        }

        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_eq!(messages[0].group_id, messages[1].group_id);
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({
                "batchItemFailures": [
                    { "itemIdentifier": "message-0" },
                    { "itemIdentifier": "message-1" }
                ]
            })
        );
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn worker_keeps_independent_fifo_groups_moving_after_a_review_failure() {
        let harness = Harness::new().await;
        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        harness
            .mock_review_response(
                204,
                Some(json!({
                    "environment_name": "another-environment",
                    "state": "rejected",
                    "comment": "environment another-environment is not allowed"
                })),
            )
            .await;
        harness
            .mock_review_response(
                403,
                Some(json!({
                    "environment_name": "release",
                    "state": "approved",
                    "comment": "release-gate deployment succeeded"
                })),
            )
            .await;
        harness
            .mock_review_response(
                204,
                Some(json!({
                    "environment_name": "later-environment",
                    "state": "rejected",
                    "comment": "environment later-environment is not allowed"
                })),
            )
            .await;
        harness.mock_pending_deployments(false).await;

        for (environment, delivery_id) in [
            (
                "another-environment",
                "00000000-0000-4000-8000-000000000001",
            ),
            ("release", "00000000-0000-4000-8000-000000000002"),
            ("later-environment", "00000000-0000-4000-8000-000000000003"),
        ] {
            let mut payload = harness.requested_payload();
            payload["environment"] = json!(environment);
            assert_no_content(
                &harness
                    .enqueue(harness.webhook_request_with_delivery(
                        "deployment_protection_rule",
                        &payload,
                        delivery_id,
                    ))
                    .await,
            );
        }

        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_ne!(messages[0].group_id, messages[1].group_id);
        assert_ne!(messages[1].group_id, messages[2].group_id);
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({
                "batchItemFailures": [
                    { "itemIdentifier": "message-1" }
                ]
            })
        );
        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &review_path(), 3);
        assert_path_call_count(&paths, &pending_deployments_path(), 2);
    }

    #[tokio::test]
    async fn worker_accepts_an_ambiguous_review_when_no_environment_remains_pending() {
        let harness = Harness::new().await;
        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        Mock::given(method("POST"))
            .and(path(review_path()))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "message": "There was a problem approving one of the gates"
            })))
            .expect(1)
            .mount(&harness.server)
            .await;
        harness.mock_pending_deployments(false).await;

        assert_no_content(
            &harness
                .enqueue(
                    harness.webhook_request(
                        "deployment_protection_rule",
                        &harness.requested_payload(),
                    ),
                )
                .await,
        );
        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({ "batchItemFailures": [] })
        );
        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &review_path(), 1);
        assert_path_call_count(&paths, &pending_deployments_path(), 1);
    }

    #[tokio::test]
    async fn worker_accepts_a_successful_review_when_another_protection_rule_remains_pending() {
        let harness = Harness::new().await;
        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        harness.mock_review_response(204, None).await;
        harness.mock_pending_deployments(true).await;

        assert_no_content(
            &harness
                .enqueue(
                    harness.webhook_request(
                        "deployment_protection_rule",
                        &harness.requested_payload(),
                    ),
                )
                .await,
        );
        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({ "batchItemFailures": [] })
        );
        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &review_path(), 1);
        assert_path_call_count(&paths, &pending_deployments_path(), 1);
    }

    #[tokio::test]
    async fn worker_retries_a_partially_applied_review_before_returning_the_fifo_batch() {
        let harness = Harness::new().await;
        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        Mock::given(method("POST"))
            .and(path(review_path()))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "message": "There was a problem approving one of the gates"
            })))
            .up_to_n_times(1)
            .expect(1)
            .mount(&harness.server)
            .await;
        harness.mock_review_response(204, None).await;
        Mock::given(method("GET"))
            .and(path(pending_deployments_path()))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                { "environment": { "name": "RELEASE" } }
            ])))
            .up_to_n_times(1)
            .expect(1)
            .mount(&harness.server)
            .await;
        harness.mock_pending_deployments(false).await;

        assert_no_content(
            &harness
                .enqueue(
                    harness.webhook_request(
                        "deployment_protection_rule",
                        &harness.requested_payload(),
                    ),
                )
                .await,
        );
        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({ "batchItemFailures": [] })
        );
        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &review_path(), 2);
        assert_path_call_count(&paths, &pending_deployments_path(), 2);
    }

    #[tokio::test]
    async fn worker_processes_a_later_deployment_wave_for_the_same_run() {
        let harness = Harness::new().await;
        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        harness.mock_review_response(204, None).await;
        harness.mock_pending_deployments(false).await;

        for index in 1..=2 {
            let mut payload = harness.requested_payload();
            payload["deployment"]["id"] = json!(5525311100_u64 + index);
            assert_no_content(
                &harness
                    .enqueue(harness.webhook_request_with_delivery(
                        "deployment_protection_rule",
                        &payload,
                        &format!("00000000-0000-4000-8000-{index:012x}"),
                    ))
                    .await,
            );
            let messages = harness
                .webhook_config
                .deployment_review_queue
                .take_messages();
            assert_eq!(
                harness.process_batch(&messages).await,
                json!({ "batchItemFailures": [] })
            );
        }

        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &review_path(), 2);
        assert_path_call_count(&paths, &pending_deployments_path(), 2);
    }

    #[tokio::test]
    async fn worker_returns_every_coalesced_message_when_an_ambiguous_review_stays_pending() {
        let harness = Harness::new().await;
        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        Mock::given(method("POST"))
            .and(path(review_path()))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "message": "There was a problem approving one of the gates"
            })))
            .expect(2)
            .mount(&harness.server)
            .await;
        harness.mock_pending_deployments(true).await;

        for index in 1..=10 {
            let mut payload = harness.requested_payload();
            payload["deployment"]["id"] = json!(5525311100_u64 + index);
            assert_no_content(
                &harness
                    .enqueue(harness.webhook_request_with_delivery(
                        "deployment_protection_rule",
                        &payload,
                        &format!("00000000-0000-4000-8000-{index:012x}"),
                    ))
                    .await,
            );
        }
        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({
                "batchItemFailures": (0..10)
                    .map(|index| json!({ "itemIdentifier": format!("message-{index}") }))
                    .collect::<Vec<_>>()
            })
        );
        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &review_path(), 2);
        assert_path_call_count(&paths, &pending_deployments_path(), 2);
    }

    #[tokio::test]
    async fn worker_defers_rate_limited_reviews_instead_of_immediately_reposting() {
        let harness = Harness::new().await;
        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        Mock::given(method("POST"))
            .and(path(review_path()))
            .respond_with(ResponseTemplate::new(429).set_body_json(json!({
                "message": "You have exceeded a secondary rate limit"
            })))
            .expect(1)
            .mount(&harness.server)
            .await;
        harness.mock_pending_deployments(true).await;

        assert_no_content(
            &harness
                .enqueue(
                    harness.webhook_request(
                        "deployment_protection_rule",
                        &harness.requested_payload(),
                    ),
                )
                .await,
        );
        let messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({
                "batchItemFailures": [{ "itemIdentifier": "message-0" }]
            })
        );
        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &review_path(), 1);
        assert_path_call_count(&paths, &pending_deployments_path(), 1);
    }

    #[tokio::test]
    async fn worker_returns_malformed_fifo_records_without_calling_github() {
        let harness = Harness::new().await;
        let event = serde_json::from_value(json!({
            "Records": [
                {
                    "messageId": "invalid-message",
                    "body": "not-json",
                    "attributes": { "MessageGroupId": "not-a-group" }
                },
                {
                    "messageId": "unprocessed-message",
                    "body": "{}",
                    "attributes": { "MessageGroupId": "not-a-group" }
                }
            ]
        }))
        .unwrap();

        assert_eq!(
            serde_json::to_value(
                crate::worker::handle_batch(harness.config.clone(), event)
                    .await
                    .unwrap()
            )
            .unwrap(),
            json!({
                "batchItemFailures": [
                    { "itemIdentifier": "invalid-message" },
                    { "itemIdentifier": "unprocessed-message" }
                ]
            })
        );
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn worker_does_not_block_a_valid_fifo_group_behind_a_malformed_group() {
        let harness = Harness::new().await;
        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        harness.mock_review_response(204, None).await;
        harness.mock_pending_deployments(false).await;
        assert_no_content(
            &harness
                .enqueue(
                    harness.webhook_request(
                        "deployment_protection_rule",
                        &harness.requested_payload(),
                    ),
                )
                .await,
        );
        let valid = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        let event = serde_json::from_value(json!({
            "Records": [
                {
                    "messageId": "invalid-message",
                    "body": "not-json",
                    "attributes": { "MessageGroupId": "invalid-group" }
                },
                {
                    "messageId": "valid-message",
                    "body": valid[0].body,
                    "attributes": { "MessageGroupId": valid[0].group_id }
                }
            ]
        }))
        .unwrap();

        assert_eq!(
            serde_json::to_value(
                crate::worker::handle_batch(harness.config.clone(), event)
                    .await
                    .unwrap()
            )
            .unwrap(),
            json!({
                "batchItemFailures": [{ "itemIdentifier": "invalid-message" }]
            })
        );
        let paths = harness.received_paths().await;
        assert_path_call_count(&paths, &review_path(), 1);
        assert_path_call_count(&paths, &pending_deployments_path(), 1);
    }

    #[tokio::test]
    async fn worker_rejects_a_tampered_fifo_group_and_callback_before_calling_github() {
        let harness = Harness::new().await;
        assert_no_content(
            &harness
                .enqueue(
                    harness.webhook_request(
                        "deployment_protection_rule",
                        &harness.requested_payload(),
                    ),
                )
                .await,
        );
        let mut messages = harness
            .webhook_config
            .deployment_review_queue
            .take_messages();
        let original_body = messages[0].body.clone();

        messages[0].group_id = "invalid-group".to_string();
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({
                "batchItemFailures": [{ "itemIdentifier": "message-0" }]
            })
        );

        let mut body: Value = serde_json::from_str(&original_body).unwrap();
        body["payload"]["deployment_callback_url"] = json!(
            "https://api.github.com/repos/evil/tools/actions/runs/1/deployment_protection_rule"
        );
        messages[0].body = serde_json::to_string(&body).unwrap();
        messages[0].group_id = crate::queue::deployment_review_group_id(
            &crate::github::RequestedDeploymentProtection::parse(
                serde_json::from_value(harness.requested_payload()).unwrap(),
                &harness.config.github_api_base,
            )
            .unwrap(),
        );
        assert_eq!(
            harness.process_batch(&messages).await,
            json!({
                "batchItemFailures": [{ "itemIdentifier": "message-0" }]
            })
        );
        assert!(harness.received_paths().await.is_empty());
    }

    #[tokio::test]
    async fn webhook_rejects_when_workflow_run_event_is_unexpected() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_summary(
                ".github/workflows/release.yml",
                &format!("{OWNER}/{REPO}"),
                "push",
            )
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "workflow run event push is not allowed"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 3, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_workflow_run_head_repository_is_unexpected() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path_and_head_repository(
                ".github/workflows/release.yml",
                "evil/release-authenticator-example",
            )
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "workflow run head repository evil/release-authenticator-example is not allowed"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 3, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_workflow_path_is_unexpected() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/ci.yml")
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "workflow path .github/workflows/ci.yml is not allowed"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 3, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 0);
        assert_path_call_count(&paths, &deployment_statuses_path(), 0);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_is_missing() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_missing_gate_deployment().await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "no successful deployment to release-gate was found"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 4, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 0);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_wrong_ref_without_fetching_workflow_metadata() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "ref develop is not allowed"
                })),
            )
            .await;

        let mut payload = harness.requested_payload();
        payload["ref"] = json!("develop");

        let response = harness
            .dispatch(harness.webhook_request("deployment_protection_rule", &payload))
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 2, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 0);
        assert_path_call_count(&paths, &deployments_path(), 0);
        assert_path_call_count(&paths, &deployment_statuses_path(), 0);
    }

    #[tokio::test]
    async fn webhook_returns_bad_gateway_when_workflow_run_lookup_fails() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness.mock_workflow_run_status(500).await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "workflow_run_lookup_failed",
                "error": "github workflow run lookup failed"
            })
        );

        let paths = harness.received_paths().await;
        assert!(paths.contains(&workflow_run_path()));
        assert!(!paths.iter().any(|path| path == &deployments_path()));
        assert!(!paths.iter().any(|path| path == &deployment_statuses_path()));
        assert!(!paths.iter().any(|path| path == &review_path()));
    }

    #[tokio::test]
    async fn webhook_returns_bad_gateway_when_deployment_lookup_fails() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_deployment_lookup_status(500).await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "deployment_lookup_failed",
                "error": "github deployment lookup failed"
            })
        );

        let paths = harness.received_paths().await;
        assert!(paths.contains(&deployments_path()));
        assert!(!paths.iter().any(|path| path == &deployment_statuses_path()));
        assert!(!paths.iter().any(|path| path == &review_path()));
    }

    #[tokio::test]
    async fn webhook_returns_bad_gateway_when_deployment_status_lookup_fails() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status_lookup(500).await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "deployment_lookup_failed",
                "error": "github deployment lookup failed"
            })
        );

        let paths = harness.received_paths().await;
        assert!(paths.contains(&deployment_statuses_path()));
        assert!(!paths.iter().any(|path| path == &review_path()));
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_status_lacks_actions_job_url() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness
            .mock_gate_deployment_status_without_job_url("success")
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "release-gate deployment status is missing a valid actions job url"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 5, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 0);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_status_job_urls_disagree() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness
            .mock_gate_deployment_status_with_mismatched_job_urls("success")
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "release-gate deployment status URLs are inconsistent"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 5, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 0);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_status_references_wrong_repository() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness
            .mock_gate_deployment_status_with_custom_urls(
                "success",
                Some(format!(
                    "https://github.com/octo/tools/actions/runs/{RUN_ID}/job/{GATE_JOB_ID}"
                )),
                Some(format!(
                    "https://github.com/octo/tools/actions/runs/{RUN_ID}/job/{GATE_JOB_ID}"
                )),
            )
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "release-gate deployment status references repository octo/tools, expected zaniebot/release-authenticator-example"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 5, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 0);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_status_references_wrong_workflow_run() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness
            .mock_gate_deployment_status_with_custom_urls(
                "success",
                Some(format!(
                    "https://github.com/{OWNER}/{REPO}/actions/runs/1/job/{GATE_JOB_ID}"
                )),
                Some(format!(
                    "https://github.com/{OWNER}/{REPO}/actions/runs/1/job/{GATE_JOB_ID}"
                )),
            )
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": format!(
                        "release-gate deployment status references workflow run 1, expected {RUN_ID}"
                    )
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 5, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 0);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_status_contains_malformed_job_url() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness
            .mock_gate_deployment_status_with_custom_urls(
                "success",
                Some("not-a-valid-url".to_string()),
                Some(format!(
                    "https://github.com/{OWNER}/{REPO}/actions/runs/{RUN_ID}/job/{GATE_JOB_ID}"
                )),
            )
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "release-gate deployment status is missing a valid actions job url"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 5, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 0);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_job_belongs_to_different_workflow_run() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", 1, SHA)
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": format!(
                        "release-gate deployment job belongs to workflow run 1, expected {RUN_ID}"
                    )
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 6, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_job_sha_is_unexpected() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, "deadbeef")
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": format!(
                        "release-gate deployment job sha deadbeef does not match {SHA}"
                    )
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 6, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_job_conclusion_is_not_success() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "failure", RUN_ID, SHA)
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "release-gate deployment job release-gate concluded with failure"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 6, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_approves_when_gate_job_name_is_not_configured() {
        let harness = Harness::new_with_policy(test_policy_without_gate_job_name()).await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("publish", "success", RUN_ID, SHA)
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "approved",
                    "comment": "release-gate deployment succeeded"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 6, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_job_name_is_unexpected() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("publish", "success", RUN_ID, SHA)
            .await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": "release-gate deployment job publish does not match expected release-gate"
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 6, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_returns_bad_gateway_when_workflow_job_lookup_fails() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness.mock_gate_workflow_job_lookup(500).await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "workflow_job_lookup_failed",
                "error": "github workflow job lookup failed"
            })
        );

        let paths = harness.received_paths().await;
        assert!(paths.contains(&workflow_job_path()));
        assert!(!paths.iter().any(|path| path == &review_path()));
    }

    #[tokio::test]
    async fn webhook_rejects_when_gate_deployment_status_references_missing_workflow_job() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness.mock_gate_workflow_job_lookup(404).await;
        harness
            .mock_review_response(
                200,
                Some(json!({
                    "environment_name": "release",
                    "state": "rejected",
                    "comment": format!(
                        "release-gate deployment status references missing workflow job {GATE_JOB_ID}"
                    )
                })),
            )
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);

        let paths = harness.received_paths().await;
        assert_eq!(paths.len(), 6, "unexpected github calls: {paths:?}");
        assert_path_call_count(&paths, &installation_token_path(), 1);
        assert_path_call_count(&paths, &workflow_run_path(), 1);
        assert_path_call_count(&paths, &deployments_path(), 1);
        assert_path_call_count(&paths, &deployment_statuses_path(), 1);
        assert_path_call_count(&paths, &workflow_job_path(), 1);
        assert_path_call_count(&paths, &review_path(), 1);
    }

    #[tokio::test]
    async fn webhook_returns_bad_gateway_when_installation_token_request_fails() {
        let harness = Harness::new().await;

        harness.mock_installation_token(500).await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "github_access_token_request_failed",
                "error": "github access token request failed"
            })
        );
    }

    #[tokio::test]
    async fn webhook_returns_failed_dependency_when_installation_token_request_is_forbidden() {
        let harness = Harness::new().await;

        harness.mock_installation_token(403).await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::FAILED_DEPENDENCY);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "github_access_token_request_forbidden",
                "error": "github rejected access token request"
            })
        );
    }

    #[tokio::test]
    async fn webhook_treats_idempotent_422_review_submission_as_success() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;

        Mock::given(method("POST"))
            .and(path(review_path()))
            .and(body_json(json!({
                "environment_name": "release",
                "state": "approved",
                "comment": "release-gate deployment succeeded"
            })))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "message": "No pending deployment requests to approve or reject"
            })))
            .expect(1)
            .mount(&harness.server)
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_no_content(&response);
    }

    #[tokio::test]
    async fn webhook_returns_bad_gateway_when_review_submission_fails() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;
        harness.mock_review_response(500, None).await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "deployment_protection_review_failed",
                "error": "github deployment protection review failed"
            })
        );
    }

    #[tokio::test]
    async fn webhook_returns_bad_gateway_when_ambiguous_422_review_persists() {
        let harness = Harness::new().await;

        harness.mock_installation_token(201).await;
        harness
            .mock_workflow_run_path(".github/workflows/release.yml")
            .await;
        harness.mock_gate_deployment().await;
        harness.mock_gate_deployment_status("success").await;
        harness
            .mock_gate_workflow_job("release-gate", "success", RUN_ID, SHA)
            .await;

        Mock::given(method("POST"))
            .and(path(review_path()))
            .respond_with(ResponseTemplate::new(422).set_body_json(json!({
                "message": "There was a problem approving one of the gates"
            })))
            .expect(1)
            .mount(&harness.server)
            .await;

        let response = harness
            .dispatch(
                harness.webhook_request("deployment_protection_rule", &harness.requested_payload()),
            )
            .await;

        assert_eq!(response.status(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            response_json(&response),
            json!({
                "code": "deployment_protection_review_failed",
                "error": "github deployment protection review failed"
            })
        );
    }
}
