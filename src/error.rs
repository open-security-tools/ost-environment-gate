use lambda_http::http::StatusCode;

/// Describes the application-level failures that can be returned by the service.
#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("policy is not configured")]
    PolicyNotConfigured,
    #[error("policy is invalid")]
    InvalidPolicy,
    #[error("app id is not configured")]
    AppIdNotConfigured,
    #[error("app private key is not configured")]
    AppPrivateKeyNotConfigured,
    #[error("webhook secret is not configured")]
    WebhookSecretNotConfigured,
    #[error("github api url is invalid")]
    InvalidGithubApiUrl,
    #[error("missing or invalid webhook event header")]
    MissingWebhookEvent,
    #[error("not found")]
    NotFound,
    #[error("invalid github webhook signature")]
    InvalidGithubWebhookSignature,
    #[error("deployment protection payload is invalid")]
    DeploymentProtectionPayloadInvalid,
    #[error("deployment protection payload is missing a valid workflow run id")]
    DeploymentProtectionRunIdInvalid,
    #[error("github app authentication failed")]
    GithubAppAuthInvalid,
    #[error("github rejected access token request")]
    GithubAccessTokenRequestForbidden,
    #[error("repository installation is not available")]
    InstallationNotFound,
    #[error("repository or permissions are not allowed for this installation")]
    InstallationTokenRequestInvalid,
    #[error("github access token request failed")]
    GithubAccessTokenRequestFailed,
    #[error("github workflow run lookup failed")]
    WorkflowRunLookupFailed,
    #[error("github workflow job lookup failed")]
    WorkflowJobLookupFailed,
    #[error("github deployment lookup failed")]
    DeploymentLookupFailed,
    #[error("github deployment protection review failed")]
    DeploymentProtectionReviewFailed,
}

impl AppError {
    /// Returns the stable machine-readable error code for this failure.
    pub fn code(&self) -> &'static str {
        match self {
            Self::PolicyNotConfigured => "policy_not_configured",
            Self::InvalidPolicy => "invalid_policy",
            Self::AppIdNotConfigured => "app_id_not_configured",
            Self::AppPrivateKeyNotConfigured => "app_private_key_not_configured",
            Self::WebhookSecretNotConfigured => "webhook_secret_not_configured",
            Self::InvalidGithubApiUrl => "invalid_github_api_url",
            Self::MissingWebhookEvent => "missing_webhook_event",
            Self::NotFound => "not_found",
            Self::InvalidGithubWebhookSignature => "invalid_github_webhook_signature",
            Self::DeploymentProtectionPayloadInvalid => "deployment_protection_payload_invalid",
            Self::DeploymentProtectionRunIdInvalid => "deployment_protection_run_id_invalid",
            Self::GithubAppAuthInvalid => "github_app_auth_invalid",
            Self::GithubAccessTokenRequestForbidden => "github_access_token_request_forbidden",
            Self::InstallationNotFound => "installation_not_found",
            Self::InstallationTokenRequestInvalid => "installation_token_request_invalid",
            Self::GithubAccessTokenRequestFailed => "github_access_token_request_failed",
            Self::WorkflowRunLookupFailed => "workflow_run_lookup_failed",
            Self::WorkflowJobLookupFailed => "workflow_job_lookup_failed",
            Self::DeploymentLookupFailed => "deployment_lookup_failed",
            Self::DeploymentProtectionReviewFailed => "deployment_protection_review_failed",
        }
    }

    /// Maps this application error to the HTTP status code returned by the service.
    pub fn status(&self) -> StatusCode {
        match self {
            Self::PolicyNotConfigured
            | Self::InvalidPolicy
            | Self::AppIdNotConfigured
            | Self::AppPrivateKeyNotConfigured
            | Self::WebhookSecretNotConfigured
            | Self::InvalidGithubApiUrl => StatusCode::INTERNAL_SERVER_ERROR,
            Self::MissingWebhookEvent => StatusCode::BAD_REQUEST,
            Self::NotFound => StatusCode::NOT_FOUND,
            Self::InvalidGithubWebhookSignature => StatusCode::UNAUTHORIZED,
            Self::DeploymentProtectionPayloadInvalid => StatusCode::BAD_REQUEST,
            Self::DeploymentProtectionRunIdInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::GithubAppAuthInvalid | Self::GithubAccessTokenRequestForbidden => {
                StatusCode::FAILED_DEPENDENCY
            }
            Self::InstallationNotFound => StatusCode::FORBIDDEN,
            Self::InstallationTokenRequestInvalid => StatusCode::UNPROCESSABLE_ENTITY,
            Self::GithubAccessTokenRequestFailed
            | Self::WorkflowRunLookupFailed
            | Self::WorkflowJobLookupFailed
            | Self::DeploymentLookupFailed
            | Self::DeploymentProtectionReviewFailed => StatusCode::BAD_GATEWAY,
        }
    }
}
