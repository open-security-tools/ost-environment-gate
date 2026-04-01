use serde::{Deserialize, Serialize};

use crate::{
    config::{EnvironmentName, GitRef},
    error::AppError,
    github::{
        github_api_url, github_request, send_github_request, GithubApiBase, InstallationId,
        Repository, RepositoryId, RunId, Token,
    },
};

const REQUESTED_ACTION: &str = "requested";
const DEPLOYMENTS_PER_PAGE: usize = 100;
const DEPLOYMENTS_PER_PAGE_QUERY: &str = "100";
const MAX_ENVIRONMENT_DEPLOYMENT_PAGES: usize = 10;

/// Mirrors the inbound `deployment_protection_rule` webhook payload shape from GitHub.
///
/// See <https://docs.github.com/en/webhooks/webhook-events-and-payloads#deployment_protection_rule>.
#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentProtectionRulePayload {
    pub action: Option<String>,
    pub environment: Option<String>,
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
    pub sha: Option<String>,
    pub deployment_callback_url: Option<String>,
    pub installation: Option<InstallationRef>,
    pub repository: Option<RepositoryPayload>,
    pub workflow_run: Option<WorkflowRunRef>,
}

/// Captures the installation reference nested inside a webhook payload.
#[derive(Debug, Clone, Deserialize)]
pub struct InstallationRef {
    pub id: Option<u64>,
}

/// Captures the repository object nested inside a webhook payload.
#[derive(Debug, Clone, Deserialize)]
pub struct RepositoryPayload {
    pub id: Option<u64>,
    pub full_name: Option<String>,
    pub name: Option<String>,
    pub owner: Option<OwnerPayload>,
}

/// Captures the owner object nested inside a repository payload.
#[derive(Debug, Clone, Deserialize)]
pub struct OwnerPayload {
    pub login: Option<String>,
}

/// Captures the workflow run reference nested inside a webhook payload.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowRunRef {
    pub id: Option<u64>,
}

/// Stores the GitHub callback URL used to review a deployment protection rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeploymentCallbackUrl(reqwest::Url);

id_type!(DeploymentId);

/// Stores a deployment ref name in either short or fully qualified form.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RefName(String);

/// Stores a commit SHA from a deployment protection request.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct CommitSha(String);

/// Represents the possible states GitHub can report for a deployment status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentState {
    Error,
    Failure,
    Inactive,
    InProgress,
    Pending,
    Queued,
    Success,
    #[serde(other)]
    Unknown,
}

/// Captures the validated deployment protection request being evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedDeploymentProtection {
    pub environment: EnvironmentName,
    pub git_ref: Option<RefName>,
    pub sha: CommitSha,
    pub installation_id: InstallationId,
    pub repository: Repository,
    pub repository_id: RepositoryId,
    pub run_id: RunId,
    pub deployment_callback_url: DeploymentCallbackUrl,
    /// Prevents direct struct-literal construction outside this module.
    _private: (),
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
struct DeploymentSummary {
    id: DeploymentId,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct DeploymentStatusSummary {
    pub state: DeploymentState,
    pub target_url: Option<String>,
    pub log_url: Option<String>,
}

crate::impl_string_newtype!(
    RefName,
    AppError,
    AppError::DeploymentProtectionPayloadInvalid
);
crate::impl_string_newtype!(
    CommitSha,
    AppError,
    AppError::DeploymentProtectionPayloadInvalid
);

impl DeploymentCallbackUrl {
    /// Returns the underlying deployment callback URL.
    pub fn as_url(&self) -> &reqwest::Url {
        &self.0
    }

    /// Parses a deployment callback URL from the webhook payload.
    pub fn parse(value: String) -> Result<Self, AppError> {
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err(AppError::DeploymentProtectionPayloadInvalid);
        }
        let url = reqwest::Url::parse(&value)
            .map_err(|_| AppError::DeploymentProtectionPayloadInvalid)?;

        Ok(Self(url))
    }

    /// Extracts the workflow run id from the deployment callback URL path.
    pub fn run_id(&self) -> Option<RunId> {
        let segments = self.0.path_segments()?.collect::<Vec<_>>();

        segments.windows(7).find_map(|window| {
            (window[0] == "repos"
                && window[3] == "actions"
                && window[4] == "runs"
                && window[6] == "deployment_protection_rule")
                .then(|| window[5].parse::<u64>().ok().and_then(RunId::new))
                .flatten()
        })
    }

    /// Builds the exact deployment callback URL expected for the validated
    /// repository and workflow run.
    pub fn expected_for_run(
        github_api_base: &GithubApiBase,
        repository: &Repository,
        run_id: RunId,
    ) -> Result<Self, AppError> {
        let url = github_api_url(
            github_api_base,
            &format!(
                "repos/{}/{}/actions/runs/{run_id}/deployment_protection_rule",
                repository.owner().as_str(),
                repository.name().as_str(),
            ),
        )?;

        Ok(Self(url))
    }

    /// Returns whether this callback URL exactly matches the expected GitHub
    /// deployment protection review endpoint.
    pub fn matches_expected(&self, expected: &Self) -> bool {
        self.0 == expected.0
    }
}

impl RefName {
    /// Reports whether this ref matches the configured allowed ref in short or full form.
    pub fn matches_allowed_ref(&self, allowed_ref: &GitRef) -> bool {
        self.as_str() == allowed_ref.as_str() || self.as_str() == allowed_ref.name()
    }
}

impl DeploymentState {
    /// Returns the GitHub API string value for this deployment state.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Failure => "failure",
            Self::Inactive => "inactive",
            Self::InProgress => "in_progress",
            Self::Pending => "pending",
            Self::Queued => "queued",
            Self::Success => "success",
            Self::Unknown => "unknown",
        }
    }
}

impl std::fmt::Display for DeploymentState {
    /// Formats the deployment state using its GitHub API string value.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl RequestedDeploymentProtection {
    /// Validates a raw GitHub deployment protection payload into a rule request.
    pub fn parse(
        payload: DeploymentProtectionRulePayload,
        github_api_base: &GithubApiBase,
    ) -> Result<Self, AppError> {
        if payload.action.as_deref() != Some(REQUESTED_ACTION) {
            return Err(AppError::DeploymentProtectionPayloadInvalid);
        }

        let deployment_callback_url = payload
            .deployment_callback_url
            .ok_or(AppError::DeploymentProtectionPayloadInvalid)
            .and_then(DeploymentCallbackUrl::parse)?;

        let environment = payload
            .environment
            .ok_or(AppError::DeploymentProtectionPayloadInvalid)
            .and_then(EnvironmentName::try_from)?;
        let installation_id = payload
            .installation
            .and_then(|installation| installation.id)
            .and_then(InstallationId::new)
            .ok_or(AppError::DeploymentProtectionPayloadInvalid)?;
        let repository = payload
            .repository
            .ok_or(AppError::DeploymentProtectionPayloadInvalid)?;
        let repository_id = repository
            .id
            .and_then(RepositoryId::new)
            .ok_or(AppError::DeploymentProtectionPayloadInvalid)?;

        let repository = match (
            repository.owner.and_then(|owner| owner.login),
            repository.name,
            repository.full_name,
        ) {
            (Some(owner), Some(name), _) => Repository::try_from((owner, name))?,
            (_, _, Some(full_name)) => Repository::try_from(full_name)?,
            _ => return Err(AppError::DeploymentProtectionPayloadInvalid),
        };

        // For `deployment_protection_rule` webhooks, GitHub does not consistently
        // populate `workflow_run.id`. The callback URL always embeds the run id,
        // so treat that as the source of truth.
        let run_id = deployment_callback_url
            .run_id()
            .ok_or(AppError::DeploymentProtectionRunIdInvalid)?;

        let payload_workflow_run_id = payload
            .workflow_run
            .and_then(|workflow_run| workflow_run.id)
            .and_then(RunId::new);
        if payload_workflow_run_id.is_some_and(|payload_run_id| payload_run_id != run_id) {
            tracing::warn!(
                callback_run_id = %run_id,
                payload_run_id = ?payload_workflow_run_id,
                "workflow_run.id does not match callback URL run id"
            );
            return Err(AppError::DeploymentProtectionPayloadInvalid);
        }

        let expected_deployment_callback_url =
            DeploymentCallbackUrl::expected_for_run(github_api_base, &repository, run_id)?;
        if !deployment_callback_url.matches_expected(&expected_deployment_callback_url) {
            tracing::warn!(
                callback_url = %deployment_callback_url.as_url(),
                expected_callback_url = %expected_deployment_callback_url.as_url(),
                "deployment callback URL does not match expected workflow run review endpoint"
            );
            return Err(AppError::DeploymentProtectionPayloadInvalid);
        }

        Ok(Self {
            environment,
            git_ref: payload.git_ref.map(RefName::try_from).transpose()?,
            sha: payload
                .sha
                .ok_or(AppError::DeploymentProtectionPayloadInvalid)
                .and_then(CommitSha::try_from)?,
            installation_id,
            repository,
            repository_id,
            run_id,
            deployment_callback_url,
            _private: (),
        })
    }
}

#[cfg(test)]
impl TryFrom<&DeploymentCallbackUrl> for RunId {
    type Error = AppError;

    fn try_from(value: &DeploymentCallbackUrl) -> Result<Self, Self::Error> {
        let parts = value
            .as_url()
            .path_segments()
            .ok_or(AppError::DeploymentProtectionPayloadInvalid)?
            .filter(|part| !part.is_empty())
            .collect::<Vec<_>>();

        parts
            .windows(3)
            .find_map(|window| {
                if window[0] == "runs" && window[2] == "deployment_protection_rule" {
                    window[1].parse::<u64>().ok().and_then(RunId::new)
                } else {
                    None
                }
            })
            .ok_or(AppError::DeploymentProtectionPayloadInvalid)
    }
}

/// Represents the request body sent to GitHub's deployment-protection review endpoint.
///
/// See <https://docs.github.com/en/rest/actions/workflow-runs#review-custom-deployment-protection-rules-for-a-workflow-run>.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentProtectionRuleReviewState {
    Approved,
    Rejected,
}

#[derive(Debug, Serialize)]
pub struct DeploymentProtectionRuleReviewPayload<'a> {
    pub environment_name: &'a str,
    pub state: DeploymentProtectionRuleReviewState,
    pub comment: &'a str,
}

/// Fetches recent deployments for the provided environment and commit SHA.
pub async fn fetch_environment_deployments(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    installation_token: &Token,
    repository: &Repository,
    environment: &EnvironmentName,
    sha: &CommitSha,
) -> Result<Vec<DeploymentId>, AppError> {
    let url = github_api_url(github_api_base, &format!("repos/{repository}/deployments"))?;
    let mut page = 1;
    let mut deployment_ids = Vec::new();

    loop {
        let page_param = page.to_string();

        let response = send_github_request(
            github_request(http_client.get(url.clone()), installation_token).query(&[
                ("environment", environment.as_str()),
                ("sha", sha.as_str()),
                ("per_page", DEPLOYMENTS_PER_PAGE_QUERY),
                ("page", page_param.as_str()),
            ]),
            "deployment lookup",
        )
        .await
        .map_err(|error| {
            tracing::error!(
                ?error,
                %repository,
                %environment,
                %sha,
                page,
                "deployment lookup failed"
            );
            AppError::DeploymentLookupFailed
        })?;

        if !response.status().is_success() {
            tracing::error!(
                status = %response.status(),
                %repository,
                %environment,
                %sha,
                page,
                "unexpected deployment lookup status"
            );
            return Err(AppError::DeploymentLookupFailed);
        }

        let deployments = response
            .json::<Vec<DeploymentSummary>>()
            .await
            .map_err(|error| {
                tracing::error!(
                    ?error,
                    %repository,
                    %environment,
                    %sha,
                    page,
                    "failed to decode deployment lookup response"
                );
                AppError::DeploymentLookupFailed
            })?;

        let page_len = deployments.len();
        deployment_ids.extend(deployments.into_iter().map(|deployment| deployment.id));

        if page_len < DEPLOYMENTS_PER_PAGE {
            break;
        }

        page += 1;
        if page > MAX_ENVIRONMENT_DEPLOYMENT_PAGES {
            tracing::warn!(
                %repository,
                %environment,
                %sha,
                max_pages = MAX_ENVIRONMENT_DEPLOYMENT_PAGES,
                total_deployments = deployment_ids.len(),
                "deployment lookup pagination limit reached"
            );
            break;
        }
    }

    Ok(deployment_ids)
}

/// Fetches the latest status for a deployment.
pub async fn fetch_latest_deployment_status(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    installation_token: &Token,
    repository: &Repository,
    deployment_id: DeploymentId,
) -> Result<Option<DeploymentStatusSummary>, AppError> {
    let url = github_api_url(
        github_api_base,
        &format!("repos/{repository}/deployments/{deployment_id}/statuses"),
    )?;

    let response = send_github_request(
        github_request(http_client.get(url), installation_token).query(&[("per_page", "1")]),
        "deployment lookup",
    )
    .await
    .map_err(|error| {
        tracing::error!(?error, %repository, %deployment_id, "deployment status lookup failed");
        AppError::DeploymentLookupFailed
    })?;

    if !response.status().is_success() {
        tracing::error!(
            status = %response.status(),
            %repository,
            %deployment_id,
            "unexpected deployment status lookup status"
        );
        return Err(AppError::DeploymentLookupFailed);
    }

    response
        .json::<Vec<DeploymentStatusSummary>>()
        .await
        .map_err(|error| {
            tracing::error!(
                ?error,
                %repository,
                %deployment_id,
                "failed to decode deployment status response"
            );
            AppError::DeploymentLookupFailed
        })
        .map(|statuses| statuses.into_iter().next())
}

/// Submits a deployment protection rule review decision back to GitHub.
pub async fn review_deployment_protection_rule(
    http_client: &reqwest::Client,
    installation_token: &Token,
    deployment_callback_url: &DeploymentCallbackUrl,
    payload: &DeploymentProtectionRuleReviewPayload<'_>,
) -> Result<(), AppError> {
    let url = deployment_callback_url.as_url().clone();

    // TODO: Revisit retries here. This endpoint is also non-idempotent, so retrying
    // after an ambiguous transport failure can duplicate review side effects.
    let response = send_github_request(
        github_request(http_client.post(url), installation_token).json(payload),
        "deployment protection review",
    )
    .await
    .map_err(|error| {
        tracing::error!(?error, "deployment protection review failed");
        AppError::DeploymentProtectionReviewFailed
    })?;

    if response.status().is_success() {
        return Ok(());
    }

    let status = response.status();
    let response_body = response.text().await.map_err(|error| {
        tracing::error!(
            ?error,
            status = %status,
            "failed to read deployment protection review error response body"
        );
        AppError::DeploymentProtectionReviewFailed
    })?;

    if status == reqwest::StatusCode::UNPROCESSABLE_ENTITY {
        if let Some(reason) = idempotent_review_422_reason(&response_body) {
            tracing::warn!(
                status = %status,
                reason = %reason,
                response_body = %response_body,
                "deployment protection review already processed; treating status as success"
            );
            return Ok(());
        }
    }

    tracing::error!(
        status = %status,
        response_body = %response_body,
        "unexpected deployment protection review status"
    );
    Err(AppError::DeploymentProtectionReviewFailed)
}

#[derive(Debug, Deserialize)]
struct GithubApiErrorResponse {
    pub message: Option<String>,
    pub errors: Option<Vec<GithubApiErrorDetail>>,
}

#[derive(Debug, Deserialize)]
struct GithubApiErrorDetail {
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IdempotentReview422Reason {
    NoPendingDeploymentRequests,
    AlreadyReviewed,
}

impl std::fmt::Display for IdempotentReview422Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::NoPendingDeploymentRequests => "no_pending_deployment_requests",
            Self::AlreadyReviewed => "already_reviewed",
        })
    }
}

impl std::str::FromStr for IdempotentReview422Reason {
    type Err = ();

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match normalize_github_error_message(value).as_str() {
            "no pending deployment requests to approve or reject" => {
                Ok(Self::NoPendingDeploymentRequests)
            }
            "deployment protection rule has already been reviewed" => Ok(Self::AlreadyReviewed),
            _ => Err(()),
        }
    }
}

fn normalize_github_error_message(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn idempotent_review_422_reason(body: &str) -> Option<IdempotentReview422Reason> {
    let body = body.trim();
    if body.is_empty() {
        return None;
    }

    let payload: GithubApiErrorResponse = serde_json::from_str(body).ok()?;

    payload
        .message
        .iter()
        .map(String::as_str)
        .chain(
            payload
                .errors
                .iter()
                .flatten()
                .filter_map(|error| error.message.as_deref()),
        )
        .find_map(|message| message.parse::<IdempotentReview422Reason>().ok())
}

#[cfg(test)]
mod tests {
    use super::{
        fetch_environment_deployments, fetch_latest_deployment_status,
        idempotent_review_422_reason, CommitSha, DeploymentCallbackUrl, DeploymentId,
        DeploymentProtectionRulePayload, DeploymentState, RefName, RequestedDeploymentProtection,
    };
    use crate::config::{EnvironmentName, GitRef, Policy};
    use crate::error::AppError;
    use crate::github::{GithubApiBase, Repository, RunId, Token};
    use serde_json::json;
    use wiremock::{
        matchers::{header, method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    fn test_github_api_base() -> GithubApiBase {
        GithubApiBase::try_from(String::from("https://api.github.com")).unwrap()
    }

    fn test_repository() -> Repository {
        Repository::try_from(String::from("octo/tools")).unwrap()
    }

    fn test_environment() -> EnvironmentName {
        EnvironmentName::try_from(String::from("release-gate")).unwrap()
    }

    fn test_token() -> Token {
        serde_json::from_value(json!("installation-token")).unwrap()
    }

    fn test_policy() -> Policy {
        serde_json::from_value(json!({
            "allowed_ref": "refs/heads/main",
            "allowed_events": ["workflow_dispatch"],
            "release_environment_name": "release",
            "release_gate_environment_name": "release-gate",
            "release_workflow_path": ".github/workflows/release.yml"
        }))
        .unwrap()
    }

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn test_base_url(server: &MockServer) -> GithubApiBase {
        GithubApiBase::try_from(server.uri()).unwrap()
    }

    #[test]
    fn deployment_protection_payload_deserializes_nested_repository_shape() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "ref": "main",
            "sha": "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54",
            "deployment_callback_url": "https://api.github.com/repos/octo/tools/actions/runs/3/deployment_protection_rule",
            "installation": { "id": 1 },
            "repository": {
                "id": 2,
                "full_name": "octo/tools",
                "name": "tools",
                "owner": { "login": "octo" }
            },
            "workflow_run": { "id": 3 }
        }))
        .unwrap();

        assert_eq!(
            payload
                .repository
                .as_ref()
                .and_then(|repository| repository.id),
            Some(2)
        );
        assert_eq!(
            payload
                .repository
                .as_ref()
                .and_then(|repository| repository.owner.as_ref())
                .and_then(|owner| owner.login.as_deref()),
            Some("octo")
        );
    }

    #[test]
    fn deployment_callback_url_rejects_invalid_url() {
        assert!(DeploymentCallbackUrl::parse("not a url".to_string()).is_err());
        assert!(DeploymentCallbackUrl::parse(String::new()).is_err());
    }

    #[test]
    fn run_id_rejects_callback_url_without_run_id() {
        let url =
            DeploymentCallbackUrl::parse("https://api.github.com/repos/octo/tools".to_string())
                .unwrap();
        assert!(RunId::try_from(&url).is_err());
    }

    #[test]
    fn run_id_try_from_deployment_callback_url_extracts_run_id() {
        let callback_url = DeploymentCallbackUrl::parse(
            "https://api.github.com/repos/zaniebot/release-authenticator-example/actions/runs/23624826112/deployment_protection_rule".to_string(),
        )
        .unwrap();

        assert_eq!(*RunId::try_from(&callback_url).unwrap(), 23624826112);
    }

    #[test]
    fn requested_deployment_protection_rejects_wrong_action() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "completed",
            "environment": "release",
            "ref": "main",
            "sha": "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54",
            "deployment_callback_url": "https://api.github.com/repos/octo/tools/actions/runs/1/deployment_protection_rule",
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" },
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::parse(payload, &test_github_api_base()).is_err());
    }

    #[test]
    fn requested_deployment_protection_rejects_missing_environment() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "sha": "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54",
            "deployment_callback_url": "https://api.github.com/repos/octo/tools/actions/runs/1/deployment_protection_rule",
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" },
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::parse(payload, &test_github_api_base()).is_err());
    }

    #[test]
    fn requested_deployment_protection_rejects_missing_sha() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "deployment_callback_url": "https://api.github.com/repos/octo/tools/actions/runs/1/deployment_protection_rule",
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" },
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::parse(payload, &test_github_api_base()).is_err());
    }

    #[test]
    fn requested_deployment_protection_rejects_missing_repository() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "sha": "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54",
            "deployment_callback_url": "https://api.github.com/repos/octo/tools/actions/runs/1/deployment_protection_rule",
            "installation": { "id": 1 },
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::parse(payload, &test_github_api_base()).is_err());
    }

    #[test]
    fn requested_deployment_protection_uses_callback_url_run_id_when_workflow_run_is_missing() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "sha": "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54",
            "deployment_callback_url": "https://api.github.com/repos/octo/tools/actions/runs/1/deployment_protection_rule",
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" }
        }))
        .unwrap();

        let requested =
            RequestedDeploymentProtection::parse(payload, &test_github_api_base()).unwrap();
        assert_eq!(*requested.run_id, 1);
    }

    #[test]
    fn requested_deployment_protection_rejects_callback_url_without_valid_run_id() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" },
            "deployment_callback_url": "https://api.github.com/repos/octo/tools/actions/runs/not-a-number/deployment_protection_rule"
        }))
        .unwrap();

        let error =
            RequestedDeploymentProtection::parse(payload, &test_github_api_base()).unwrap_err();
        assert!(matches!(error, AppError::DeploymentProtectionRunIdInvalid));
    }

    #[test]
    fn requested_deployment_protection_parse_accepts_real_payload_shape() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_str(include_str!(
            "../../testdata/deployment-protection-requested.json"
        ))
        .unwrap();
        let requested =
            RequestedDeploymentProtection::parse(payload, &test_github_api_base()).unwrap();

        assert_eq!(requested.environment.as_str(), "release");
        assert_eq!(
            requested.git_ref.as_ref().map(RefName::as_str),
            Some("main")
        );
        assert_eq!(
            requested.sha,
            CommitSha::try_from("47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54").unwrap()
        );
        assert_eq!(
            requested.repository.to_string(),
            "zaniebot/release-authenticator-example"
        );
        assert_eq!(requested.repository.owner().as_str(), "zaniebot");
        assert_eq!(
            requested.repository.name().as_str(),
            "release-authenticator-example"
        );
        assert_eq!(*requested.run_id, 23625057533);
    }

    #[test]
    fn ref_name_matches_allowed_ref_accepts_full_and_short_branch_refs() {
        assert!(RefName::try_from("main")
            .unwrap()
            .matches_allowed_ref(test_policy().allowed_ref()));
        assert!(RefName::try_from("refs/heads/main")
            .unwrap()
            .matches_allowed_ref(test_policy().allowed_ref()));
        assert!(RefName::try_from("v1.2.3")
            .unwrap()
            .matches_allowed_ref(&GitRef::try_from(String::from("refs/tags/v1.2.3")).unwrap()));
        assert!(RefName::try_from("refs/tags/v1.2.3")
            .unwrap()
            .matches_allowed_ref(&GitRef::try_from(String::from("refs/tags/v1.2.3")).unwrap()));
        assert!(!RefName::try_from("develop")
            .unwrap()
            .matches_allowed_ref(test_policy().allowed_ref()));
    }

    #[test]
    fn callback_url_matches_expected_exact_review_endpoint() {
        let base = GithubApiBase::try_from(String::from("https://api.github.com")).unwrap();
        let repository = crate::github::Repository::try_from(String::from("octo/tools")).unwrap();
        let expected = DeploymentCallbackUrl::expected_for_run(
            &base,
            &repository,
            crate::github::RunId::new(1).unwrap(),
        )
        .unwrap();
        let provided = DeploymentCallbackUrl::parse(
            "https://api.github.com/repos/octo/tools/actions/runs/1/deployment_protection_rule"
                .to_string(),
        )
        .unwrap();

        assert!(provided.matches_expected(&expected));
    }

    #[test]
    fn callback_url_rejects_different_repo_in_requested_deployment_protection() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "sha": "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54",
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" },
            "deployment_callback_url": "https://api.github.com/repos/evil/tools/actions/runs/1/deployment_protection_rule",
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::parse(payload, &test_github_api_base()).is_err());
    }

    #[test]
    fn callback_url_rejects_different_run_id_in_requested_deployment_protection() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "sha": "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54",
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" },
            "deployment_callback_url": "https://api.github.com/repos/octo/tools/actions/runs/2/deployment_protection_rule",
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::parse(payload, &test_github_api_base()).is_err());
    }

    #[test]
    fn callback_url_rejects_non_review_endpoint_path() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "sha": "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54",
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" },
            "deployment_callback_url": "https://api.github.com/repos/octo/tools/actions/runs/1",
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::parse(payload, &test_github_api_base()).is_err());
    }

    #[test]
    fn callback_url_matches_expected_ghe_review_endpoint() {
        let base =
            GithubApiBase::try_from(String::from("https://ghe.corp.example.com/api/v3")).unwrap();
        let repository = crate::github::Repository::try_from(String::from("octo/tools")).unwrap();
        let expected = DeploymentCallbackUrl::expected_for_run(
            &base,
            &repository,
            crate::github::RunId::new(1).unwrap(),
        )
        .unwrap();
        let provided = DeploymentCallbackUrl::parse(
            "https://ghe.corp.example.com/api/v3/repos/octo/tools/actions/runs/1/deployment_protection_rule"
                .to_string(),
        )
        .unwrap();

        assert!(provided.matches_expected(&expected));
    }

    #[test]
    fn idempotent_422_detector_accepts_already_reviewed_errors() {
        let body = json!({
            "message": "Validation Failed",
            "errors": [
                {
                    "message": "Deployment protection rule has already been reviewed"
                }
            ]
        })
        .to_string();

        assert!(idempotent_review_422_reason(&body).is_some());
    }

    #[test]
    fn idempotent_422_detector_accepts_no_pending_deployments_errors() {
        let body = json!({
            "message": "No pending deployment requests to approve or reject"
        })
        .to_string();

        assert!(idempotent_review_422_reason(&body).is_some());
    }

    #[test]
    fn idempotent_422_detector_rejects_non_idempotent_validation_errors() {
        let body = json!({
            "message": "Validation Failed",
            "errors": [
                {
                    "message": "Environment name is invalid"
                }
            ]
        })
        .to_string();

        assert!(idempotent_review_422_reason(&body).is_none());
    }

    #[test]
    fn idempotent_422_detector_rejects_non_json_body() {
        assert!(idempotent_review_422_reason("unprocessable").is_none());
    }

    #[test]
    fn idempotent_422_detector_accepts_whitespace_and_case_differences() {
        let body = json!({
            "message": "  No  Pending   Deployment Requests To Approve Or Reject  "
        })
        .to_string();

        assert!(idempotent_review_422_reason(&body).is_some());
    }

    #[tokio::test]
    async fn fetch_environment_deployments_returns_matches_in_order() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/deployments"))
            .and(query_param("environment", "release-gate"))
            .and(query_param("sha", "abc123"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .and(header("authorization", "Bearer installation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                { "id": 42 },
                { "id": 41 }
            ])))
            .mount(&server)
            .await;

        let deployment_ids = fetch_environment_deployments(
            &test_http_client(),
            &test_base_url(&server),
            &test_token(),
            &test_repository(),
            &test_environment(),
            &CommitSha::try_from("abc123").unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(
            deployment_ids,
            vec![
                DeploymentId::new(42).unwrap(),
                DeploymentId::new(41).unwrap()
            ]
        );
    }

    #[tokio::test]
    async fn fetch_environment_deployments_follows_pagination() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/deployments"))
            .and(query_param("environment", "release-gate"))
            .and(query_param("sha", "abc123"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .respond_with(
                ResponseTemplate::new(200)
                    .set_body_json((1..=100).map(|id| json!({ "id": id })).collect::<Vec<_>>()),
            )
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/deployments"))
            .and(query_param("environment", "release-gate"))
            .and(query_param("sha", "abc123"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "2"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([{ "id": 101 }])))
            .mount(&server)
            .await;

        let deployment_ids = fetch_environment_deployments(
            &test_http_client(),
            &test_base_url(&server),
            &test_token(),
            &test_repository(),
            &test_environment(),
            &CommitSha::try_from("abc123").unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(deployment_ids.len(), 101);
        assert_eq!(deployment_ids.first(), Some(&DeploymentId::new(1).unwrap()));
        assert_eq!(
            deployment_ids.last(),
            Some(&DeploymentId::new(101).unwrap())
        );
    }

    #[tokio::test]
    async fn fetch_environment_deployments_returns_empty_when_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/deployments"))
            .and(query_param("environment", "release-gate"))
            .and(query_param("sha", "abc123"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let deployment_ids = fetch_environment_deployments(
            &test_http_client(),
            &test_base_url(&server),
            &test_token(),
            &test_repository(),
            &test_environment(),
            &CommitSha::try_from("abc123").unwrap(),
        )
        .await
        .unwrap();

        assert!(deployment_ids.is_empty());
    }

    #[tokio::test]
    async fn fetch_latest_deployment_status_returns_first_state() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/deployments/42/statuses"))
            .and(query_param("per_page", "1"))
            .and(header("authorization", "Bearer installation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([
                {
                    "state": "success",
                    "log_url": "https://github.com/octo/tools/actions/runs/999/job/123",
                    "target_url": "https://github.com/octo/tools/actions/runs/999/job/123"
                },
                { "state": "failure" }
            ])))
            .mount(&server)
            .await;

        let status = fetch_latest_deployment_status(
            &test_http_client(),
            &test_base_url(&server),
            &test_token(),
            &test_repository(),
            DeploymentId::new(42).unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(
            status.as_ref().map(|status| status.state),
            Some(DeploymentState::Success)
        );
        assert_eq!(
            status.as_ref().and_then(|status| status.log_url.as_deref()),
            Some("https://github.com/octo/tools/actions/runs/999/job/123")
        );
    }

    #[tokio::test]
    async fn fetch_latest_deployment_status_returns_none_when_absent() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/deployments/42/statuses"))
            .and(query_param("per_page", "1"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
            .mount(&server)
            .await;

        let state = fetch_latest_deployment_status(
            &test_http_client(),
            &test_base_url(&server),
            &test_token(),
            &test_repository(),
            DeploymentId::new(42).unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(state, None);
    }
}
