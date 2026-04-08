use std::{env, fmt, time::Duration};

use aws_config::BehaviorVersion;
use aws_sdk_secretsmanager::Client as SecretsManagerClient;
use aws_sdk_ssm::Client as SsmClient;
use lambda_http::Error;
use serde::Deserialize;

use crate::{error::AppError, github::GithubApiBase};

const WORKFLOWS_PREFIX: &str = ".github/workflows/";
const HTTP_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
const HTTP_REQUEST_TIMEOUT: Duration = Duration::from_secs(6);

#[derive(Clone, Debug, Deserialize)]
#[serde(try_from = "RawPolicy")]
pub struct Policy {
    allowed_ref: GitRef,
    allowed_events: Vec<WorkflowEventName>,
    release_environment_name: EnvironmentName,
    release_gate_job_name: JobName,
    release_workflow_path: WorkflowPath,
}

#[derive(Debug, Deserialize)]
struct RawPolicy {
    allowed_ref: String,
    allowed_events: Vec<String>,
    release_environment_name: String,
    release_gate_job_name: String,
    release_workflow_path: String,
}

/// Stores a validated fully qualified Git reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GitRef(String);

/// Enumerates GitHub Actions workflow event names that can trigger releases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkflowEventName {
    WorkflowDispatch,
    WorkflowCall,
    WorkflowRun,
    Push,
    PullRequest,
    PullRequestTarget,
    RepositoryDispatch,
    Release,
    Schedule,
    MergeGroup,
    Create,
    Delete,
}
/// Stores the name of the protected deployment environment.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct EnvironmentName(String);

/// Stores the name of the workflow job that acts as the release gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JobName(String);

/// Stores the path to the workflow file that is allowed to approve releases.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorkflowPath(String);

/// Stores the configured GitHub App identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AppId(String);

/// Stores the GitHub App private key while redacting debug output.
#[derive(Clone, PartialEq, Eq)]
pub struct AppPrivateKey(String);

/// Stores the shared secret used to validate GitHub webhook signatures.
#[derive(Clone, PartialEq, Eq)]
pub struct WebhookSecret(String);

fn is_valid_git_ref(value: &str) -> bool {
    value
        .strip_prefix("refs/heads/")
        .is_some_and(|suffix| !suffix.is_empty())
        || value
            .strip_prefix("refs/tags/")
            .is_some_and(|suffix| !suffix.is_empty())
}

fn is_valid_workflow_path(value: &str) -> bool {
    value
        .strip_prefix(WORKFLOWS_PREFIX)
        .is_some_and(|suffix| !suffix.is_empty())
        && (value.ends_with(".yml") || value.ends_with(".yaml"))
}

crate::impl_string_newtype!(
    GitRef,
    AppError,
    AppError::InvalidPolicy,
    validate = is_valid_git_ref
);
crate::impl_string_newtype!(EnvironmentName, AppError, AppError::InvalidPolicy);
crate::impl_string_newtype!(JobName, AppError, AppError::InvalidPolicy);
crate::impl_string_newtype!(
    WorkflowPath,
    AppError,
    AppError::InvalidPolicy,
    validate = is_valid_workflow_path
);
crate::impl_string_newtype!(AppId, AppError, AppError::AppIdNotConfigured);
crate::impl_string_newtype!(
    WebhookSecret,
    AppError,
    AppError::WebhookSecretNotConfigured
);

impl GitRef {
    pub fn name(&self) -> &str {
        self.as_str()
            .strip_prefix("refs/heads/")
            .or_else(|| self.as_str().strip_prefix("refs/tags/"))
            .expect("GitRef always has a refs/heads/ or refs/tags/ prefix")
    }
}

impl WorkflowEventName {
    /// Returns the canonical GitHub event name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::WorkflowDispatch => "workflow_dispatch",
            Self::WorkflowCall => "workflow_call",
            Self::WorkflowRun => "workflow_run",
            Self::Push => "push",
            Self::PullRequest => "pull_request",
            Self::PullRequestTarget => "pull_request_target",
            Self::RepositoryDispatch => "repository_dispatch",
            Self::Release => "release",
            Self::Schedule => "schedule",
            Self::MergeGroup => "merge_group",
            Self::Create => "create",
            Self::Delete => "delete",
        }
    }
}

impl TryFrom<String> for WorkflowEventName {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.trim() {
            "workflow_dispatch" => Ok(Self::WorkflowDispatch),
            "workflow_call" => Ok(Self::WorkflowCall),
            "workflow_run" => Ok(Self::WorkflowRun),
            "push" => Ok(Self::Push),
            "pull_request" => Ok(Self::PullRequest),
            "pull_request_target" => Ok(Self::PullRequestTarget),
            "repository_dispatch" => Ok(Self::RepositoryDispatch),
            "release" => Ok(Self::Release),
            "schedule" => Ok(Self::Schedule),
            "merge_group" => Ok(Self::MergeGroup),
            "create" => Ok(Self::Create),
            "delete" => Ok(Self::Delete),
            _ => Err(AppError::InvalidPolicy),
        }
    }
}

impl TryFrom<&str> for WorkflowEventName {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_owned().try_into()
    }
}

impl fmt::Display for WorkflowEventName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl fmt::Debug for AppPrivateKey {
    /// Formats the private key using a redacted debug representation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("AppPrivateKey").field(&"<redacted>").finish()
    }
}

impl AppPrivateKey {
    /// Returns the underlying private key string.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn from_env() -> Result<Self, AppError> {
        env::var("APP_PRIVATE_KEY")
            .map_err(|_| AppError::AppPrivateKeyNotConfigured)
            .and_then(Self::try_from)
    }

    async fn from_secrets_manager(secrets: &SecretsManagerClient) -> Result<Self, Error> {
        let secret_id = env::var("APP_PRIVATE_KEY_SECRET_NAME")
            .or_else(|_| env::var("APP_PRIVATE_KEY_SECRET_ARN"))
            .map_err(|_| AppError::AppPrivateKeyNotConfigured)?;
        let response = secrets
            .get_secret_value()
            .secret_id(secret_id)
            .send()
            .await?;
        let value = response
            .secret_string()
            .ok_or(AppError::AppPrivateKeyNotConfigured)?;

        Self::try_from(value.to_owned()).map_err(Into::into)
    }
}

impl AsRef<str> for AppPrivateKey {
    /// Borrows the private key as a string slice.
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Debug for WebhookSecret {
    /// Formats the webhook secret using a redacted debug representation.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("WebhookSecret").field(&"<redacted>").finish()
    }
}

impl WebhookSecret {
    fn from_env() -> Result<Self, AppError> {
        env::var("GITHUB_WEBHOOK_SECRET")
            .map_err(|_| AppError::WebhookSecretNotConfigured)
            .and_then(Self::try_from)
    }

    async fn from_ssm(ssm: &SsmClient) -> Result<Self, Error> {
        let parameter_name = env::var("WEBHOOK_SECRET_PARAMETER")
            .map_err(|_| AppError::WebhookSecretNotConfigured)?;
        let response = ssm
            .get_parameter()
            .name(parameter_name)
            .with_decryption(true)
            .send()
            .await?;
        let value = response
            .parameter()
            .and_then(|parameter| parameter.value())
            .ok_or(AppError::WebhookSecretNotConfigured)?;

        Self::try_from(value.to_owned()).map_err(Into::into)
    }
}

impl Policy {
    /// Returns the fully qualified ref that is allowed to pass the release gate.
    pub fn allowed_ref(&self) -> &GitRef {
        &self.allowed_ref
    }

    /// Returns whether the workflow run event is allowed to request release approval.
    pub fn allows_event(&self, event: &str) -> bool {
        let Ok(event_name) = WorkflowEventName::try_from(event) else {
            return false;
        };

        self.allowed_events.contains(&event_name)
    }

    pub fn release_environment_name(&self) -> &EnvironmentName {
        &self.release_environment_name
    }

    pub fn release_gate_job_name(&self) -> &JobName {
        &self.release_gate_job_name
    }

    /// Returns the workflow file path that is allowed to request approval.
    pub fn release_workflow_path(&self) -> &WorkflowPath {
        &self.release_workflow_path
    }

    pub fn from_env() -> Result<Self, AppError> {
        let policy_json = env::var("POLICY_JSON").map_err(|_| AppError::PolicyNotConfigured)?;
        policy_json.parse()
    }
}

impl std::str::FromStr for Policy {
    type Err = AppError;

    /// Parses and validates a policy from its JSON string representation.
    fn from_str(policy_json: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(policy_json).map_err(|_| AppError::InvalidPolicy)
    }
}

impl TryFrom<RawPolicy> for Policy {
    type Error = AppError;

    /// Converts an unvalidated raw policy into validated policy fields.
    fn try_from(raw: RawPolicy) -> Result<Self, Self::Error> {
        let allowed_events = raw
            .allowed_events
            .into_iter()
            .map(WorkflowEventName::try_from)
            .collect::<Result<Vec<_>, _>>()?;
        if allowed_events.is_empty() {
            return Err(AppError::InvalidPolicy);
        }

        Ok(Self {
            allowed_ref: raw.allowed_ref.try_into()?,
            allowed_events,
            release_environment_name: raw.release_environment_name.try_into()?,
            release_gate_job_name: raw.release_gate_job_name.try_into()?,
            release_workflow_path: raw.release_workflow_path.try_into()?,
        })
    }
}

impl AppId {
    fn from_env() -> Result<Self, AppError> {
        env::var("APP_ID")
            .map_err(|_| AppError::AppIdNotConfigured)
            .and_then(Self::try_from)
    }

    async fn from_ssm(ssm: &SsmClient) -> Result<Self, Error> {
        let parameter_name =
            env::var("APP_ID_PARAMETER").map_err(|_| AppError::AppIdNotConfigured)?;
        let response = ssm
            .get_parameter()
            .name(parameter_name)
            .with_decryption(true)
            .send()
            .await?;
        let value = response
            .parameter()
            .and_then(|parameter| parameter.value())
            .ok_or(AppError::AppIdNotConfigured)?;

        Self::try_from(value.to_owned()).map_err(Into::into)
    }
}

impl TryFrom<String> for AppPrivateKey {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = value.replace("\\n", "\n").trim().to_string();
        if value.is_empty() {
            return Err(AppError::AppPrivateKeyNotConfigured);
        }
        Ok(Self(value))
    }
}

impl TryFrom<&str> for AppPrivateKey {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_owned().try_into()
    }
}

#[derive(Clone)]
pub struct Config {
    pub policy: Policy,
    pub app_id: AppId,
    pub app_private_key: AppPrivateKey,
    pub webhook_secret: WebhookSecret,
    pub github_api_base: GithubApiBase,
    pub http_client: reqwest::Client,
}

pub(crate) fn build_http_client() -> Result<reqwest::Client, reqwest::Error> {
    reqwest::Client::builder()
        .user_agent("ost-environment-gate")
        .connect_timeout(HTTP_CONNECT_TIMEOUT)
        .timeout(HTTP_REQUEST_TIMEOUT)
        .build()
}

impl Config {
    /// Loads and assembles the runtime configuration from AWS and environment sources.
    pub async fn load() -> Result<Self, Error> {
        let policy = Policy::from_env()?;
        let shared_config = aws_config::load_defaults(BehaviorVersion::latest()).await;
        let ssm = SsmClient::new(&shared_config);
        let secrets = SecretsManagerClient::new(&shared_config);

        let app_id = match AppId::from_env() {
            Ok(app_id) => app_id,
            Err(AppError::AppIdNotConfigured) => AppId::from_ssm(&ssm).await?,
            Err(error) => return Err(error.into()),
        };
        let app_private_key = match AppPrivateKey::from_env() {
            Ok(app_private_key) => app_private_key,
            Err(AppError::AppPrivateKeyNotConfigured) => {
                AppPrivateKey::from_secrets_manager(&secrets).await?
            }
            Err(error) => return Err(error.into()),
        };
        let webhook_secret = match WebhookSecret::from_env() {
            Ok(webhook_secret) => webhook_secret,
            Err(AppError::WebhookSecretNotConfigured) => WebhookSecret::from_ssm(&ssm).await?,
            Err(error) => return Err(error.into()),
        };
        let github_api_base = GithubApiBase::from_env()?;
        let http_client = build_http_client()?;

        Ok(Self {
            policy,
            app_id,
            app_private_key,
            webhook_secret,
            github_api_base,
            http_client,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::{GitRef, Policy, WorkflowPath};
    use serde_json::json;

    #[test]
    fn policy_deserializes_into_validated_types() {
        let policy: Policy = serde_json::from_value(json!({
            "allowed_ref": "refs/heads/main",
            "allowed_events": ["workflow_dispatch"],
            "release_environment_name": "release",
            "release_gate_job_name": "release-gate",
            "release_workflow_path": ".github/workflows/release.yml"
        }))
        .unwrap();

        assert_eq!(policy.allowed_ref().as_str(), "refs/heads/main");
        assert!(policy.allows_event("workflow_dispatch"));
        assert!(!policy.allows_event("push"));
        assert_eq!(policy.release_environment_name().as_str(), "release");
        assert_eq!(policy.release_gate_job_name().as_str(), "release-gate");
        assert_eq!(
            policy.release_workflow_path().as_str(),
            ".github/workflows/release.yml"
        );
    }

    #[test]
    fn policy_from_str_deserializes_into_validated_types() {
        let policy: Policy = r#"{
            "allowed_ref": "refs/heads/main",
            "allowed_events": ["workflow_dispatch"],
            "release_environment_name": "release",
            "release_gate_job_name": "release-gate",
            "release_workflow_path": ".github/workflows/release.yml"
        }"#
        .parse()
        .unwrap();

        assert_eq!(policy.allowed_ref().as_str(), "refs/heads/main");
        assert!(policy.allows_event("workflow_dispatch"));
        assert!(!policy.allows_event("push"));
        assert_eq!(policy.release_environment_name().as_str(), "release");
    }

    #[test]
    fn policy_rejects_empty_allowed_events() {
        let result: Result<Policy, _> = serde_json::from_value(json!({
            "allowed_ref": "refs/heads/main",
            "allowed_events": [],
            "release_environment_name": "release",
            "release_gate_job_name": "release-gate",
            "release_workflow_path": ".github/workflows/release.yml"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn policy_rejects_empty_strings() {
        let result: Result<Policy, _> = serde_json::from_value(json!({
            "allowed_ref": "refs/heads/main",
            "allowed_events": ["workflow_dispatch"],
            "release_environment_name": "",
            "release_gate_job_name": "release-gate",
            "release_workflow_path": ".github/workflows/release.yml"
        }));

        assert!(result.is_err());
    }

    #[test]
    fn git_ref_rejects_non_canonical_refs() {
        assert!(GitRef::try_from(String::from("main")).is_err());
        assert!(GitRef::try_from(String::from("refs/pull/1/head")).is_err());
        assert!(GitRef::try_from(String::from("refs/heads/main")).is_ok());
    }

    #[test]
    fn workflow_path_requires_github_workflows_prefix() {
        assert!(WorkflowPath::try_from(String::from("release.yml")).is_err());
        assert!(WorkflowPath::try_from(String::from(".github/workflows/release.yml")).is_ok());
    }
}
