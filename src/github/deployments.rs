use serde::{Deserialize, Serialize};

use crate::{
    config::{EnvironmentName, GitRef},
    error::AppError,
    github::{
        github_api_url, github_request, send_github_request, GithubApiBase, InstallationId,
        Repository, RepositoryId, RunId,
    },
};

const REQUESTED_ACTION: &str = "requested";

/// Mirrors the inbound `deployment_protection_rule` webhook payload shape from GitHub.
///
/// See <https://docs.github.com/en/webhooks/webhook-events-and-payloads#deployment_protection_rule>.
#[derive(Debug, Clone, Deserialize)]
pub struct DeploymentProtectionRulePayload {
    pub action: Option<String>,
    pub environment: Option<String>,
    #[serde(rename = "ref")]
    pub git_ref: Option<String>,
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

/// Stores a deployment ref name in either short or fully qualified form.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct RefName(String);

/// Captures the validated deployment protection request being evaluated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestedDeploymentProtection {
    pub environment: EnvironmentName,
    pub git_ref: Option<RefName>,
    pub installation_id: InstallationId,
    pub repository: Repository,
    pub repository_id: RepositoryId,
    pub run_id: RunId,
}

crate::impl_string_newtype!(
    RefName,
    AppError,
    AppError::DeploymentProtectionPayloadInvalid
);

impl DeploymentCallbackUrl {
    /// Returns the underlying deployment callback URL.
    pub fn as_url(&self) -> &reqwest::Url {
        &self.0
    }
}

impl RefName {
    /// Reports whether this ref matches the configured allowed ref in short or full form.
    pub fn matches_allowed_ref(&self, allowed_ref: &GitRef) -> bool {
        self.as_str() == allowed_ref.as_str() || self.as_str() == allowed_ref.name()
    }
}

impl TryFrom<DeploymentProtectionRulePayload> for RequestedDeploymentProtection {
    type Error = AppError;

    /// Validates a raw GitHub deployment protection payload into a rule request.
    fn try_from(payload: DeploymentProtectionRulePayload) -> Result<Self, Self::Error> {
        if payload.action.as_deref() != Some(REQUESTED_ACTION) {
            return Err(AppError::DeploymentProtectionPayloadInvalid);
        }

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

        let run_id = match payload
            .workflow_run
            .and_then(|workflow_run| workflow_run.id)
            .and_then(RunId::new)
        {
            Some(run_id) => run_id,
            None => {
                let deployment_callback_url = payload
                    .deployment_callback_url
                    .ok_or(AppError::DeploymentProtectionPayloadInvalid)
                    .and_then(DeploymentCallbackUrl::try_from)?;
                RunId::try_from(&deployment_callback_url)?
            }
        };

        Ok(Self {
            environment,
            git_ref: payload.git_ref.map(RefName::try_from).transpose()?,
            installation_id,
            repository,
            repository_id,
            run_id,
        })
    }
}

impl TryFrom<String> for DeploymentCallbackUrl {
    type Error = AppError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let value = value.trim().to_string();
        if value.is_empty() {
            return Err(AppError::DeploymentProtectionPayloadInvalid);
        }
        let url = reqwest::Url::parse(&value)
            .map_err(|_| AppError::DeploymentProtectionPayloadInvalid)?;
        Ok(Self(url))
    }
}

impl TryFrom<&str> for DeploymentCallbackUrl {
    type Error = AppError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        value.to_owned().try_into()
    }
}

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

/// Submits a deployment protection rule review decision back to GitHub.
pub async fn review_deployment_protection_rule(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    installation_token: &str,
    owner: &str,
    repo: &str,
    run_id: u64,
    payload: &DeploymentProtectionRuleReviewPayload<'_>,
) -> Result<(), AppError> {
    let url = github_api_url(
        github_api_base,
        &format!("repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule"),
    )?;

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

    if !response.status().is_success() {
        tracing::error!(status = %response.status(), "unexpected deployment protection review status");
        return Err(AppError::DeploymentProtectionReviewFailed);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        DeploymentCallbackUrl, DeploymentProtectionRulePayload, RefName,
        RequestedDeploymentProtection,
    };
    use crate::config::{GitRef, Policy};
    use crate::github::RunId;
    use serde_json::json;

    fn test_policy() -> Policy {
        serde_json::from_value(json!({
            "allowed_ref": "refs/heads/main",
            "release_environment_name": "release",
            "release_gate_job_name": "release-gate",
            "release_workflow_path": ".github/workflows/release.yml"
        }))
        .unwrap()
    }

    #[test]
    fn deployment_protection_payload_deserializes_nested_repository_shape() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "ref": "main",
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
        assert!(DeploymentCallbackUrl::try_from("not a url").is_err());
        assert!(DeploymentCallbackUrl::try_from("").is_err());
    }

    #[test]
    fn run_id_rejects_callback_url_without_run_id() {
        let url =
            DeploymentCallbackUrl::try_from("https://api.github.com/repos/octo/tools").unwrap();
        assert!(RunId::try_from(&url).is_err());
    }

    #[test]
    fn run_id_try_from_deployment_callback_url_extracts_run_id() {
        let callback_url = DeploymentCallbackUrl::try_from(
            "https://api.github.com/repos/zaniebot/release-authenticator-example/actions/runs/23624826112/deployment_protection_rule",
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
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" },
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::try_from(payload).is_err());
    }

    #[test]
    fn requested_deployment_protection_rejects_missing_environment() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "installation": { "id": 1 },
            "repository": { "id": 1, "full_name": "octo/tools" },
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::try_from(payload).is_err());
    }

    #[test]
    fn requested_deployment_protection_rejects_missing_repository() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(json!({
            "action": "requested",
            "environment": "release",
            "installation": { "id": 1 },
            "workflow_run": { "id": 1 }
        }))
        .unwrap();

        assert!(RequestedDeploymentProtection::try_from(payload).is_err());
    }

    #[test]
    fn requested_deployment_protection_try_from_accepts_real_payload_shape() {
        let payload: DeploymentProtectionRulePayload = serde_json::from_str(include_str!(
            "../../testdata/deployment-protection-requested.json"
        ))
        .unwrap();
        let requested = RequestedDeploymentProtection::try_from(payload).unwrap();

        assert_eq!(requested.environment.as_str(), "release");
        assert_eq!(
            requested.git_ref.as_ref().map(RefName::as_str),
            Some("main")
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
}
