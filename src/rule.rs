use crate::{
    config::{Config, EnvironmentName, Policy},
    error::AppError,
    github::{
        self, Conclusion, DeploymentProtectionRulePayload, DeploymentProtectionRuleReviewPayload,
        DeploymentProtectionRuleReviewState, DeploymentState, DeploymentStatusSummary,
        GithubApiBase, RefName, Repository, RequestedDeploymentProtection, RunId,
        WorkflowJobUrlReference, WorkflowRunSummary,
    },
};

const REQUESTED_ACTION: &str = "requested";

/// Represents the approval state sent back to GitHub for a release gate decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReleaseProtectionState {
    Approved,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct ReleaseProtectionDecision {
    pub state: ReleaseProtectionState,
    pub comment: String,
}

impl ReleaseProtectionDecision {
    pub fn approved(comment: impl Into<String>) -> Self {
        Self {
            state: ReleaseProtectionState::Approved,
            comment: comment.into(),
        }
    }

    /// Creates a rejection decision with the provided comment.
    pub fn rejected(comment: impl Into<String>) -> Self {
        Self {
            state: ReleaseProtectionState::Rejected,
            comment: comment.into(),
        }
    }
}

#[derive(Debug)]
pub enum DeploymentProtectionRuleOutcome {
    Ignored {
        action: String,
    },
    Reviewed {
        repository: Repository,
        run_id: RunId,
        environment: EnvironmentName,
        decision: ReleaseProtectionDecision,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum GateDeploymentValidation {
    Matched,
    Rejected(String),
}

impl ReleaseProtectionState {
    /// Returns the string value expected by the GitHub deployments API.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Approved => "approved",
            Self::Rejected => "rejected",
        }
    }
}

impl std::fmt::Display for ReleaseProtectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Evaluates a deployment protection webhook and submits the resulting review to GitHub.
pub async fn handle_deployment_protection_rule_webhook(
    config: Config,
    body: &[u8],
) -> Result<DeploymentProtectionRuleOutcome, AppError> {
    let payload: DeploymentProtectionRulePayload =
        serde_json::from_slice(body).map_err(|_| AppError::DeploymentProtectionPayloadInvalid)?;

    let action = payload.action.as_deref().unwrap_or_default();
    if action != REQUESTED_ACTION {
        return Ok(DeploymentProtectionRuleOutcome::Ignored {
            action: action.to_string(),
        });
    }

    let requested = RequestedDeploymentProtection::parse(payload, &config.github_api_base)?;
    let app_jwt = github::create_app_jwt(&config.app_id, &config.app_private_key)?;

    let installation_token = github::mint_installation_token(
        &config.http_client,
        &config.github_api_base,
        &app_jwt,
        *requested.installation_id,
        &[*requested.repository_id],
        serde_json::json!({
            "actions": "read",
            "deployments": "write",
        }),
    )
    .await?;

    let decision = if requested.environment.as_str()
        != config.policy.release_environment_name().as_str()
        || !requested
            .git_ref
            .as_ref()
            .is_some_and(|git_ref| git_ref.matches_allowed_ref(config.policy.allowed_ref()))
    {
        evaluate_release_protection(
            &requested,
            &WorkflowRunSummary {
                path: None,
                event: None,
                head_repository: None,
            },
            None,
            &config.policy,
        )
    } else {
        let workflow_run = github::fetch_workflow_run(
            &config.http_client,
            &config.github_api_base,
            installation_token.token.as_str(),
            requested.repository.owner().as_str(),
            requested.repository.name().as_str(),
            *requested.run_id,
        )
        .await?;

        let workflow_head_repository = workflow_run
            .head_repository
            .as_ref()
            .and_then(|repository| repository.full_name.as_deref())
            .map(str::to_owned)
            .map(Repository::try_from)
            .transpose()
            .ok()
            .flatten();
        let workflow_event = workflow_run.event.as_deref();

        if workflow_run.path.as_deref() != Some(config.policy.release_workflow_path().as_str())
            || workflow_head_repository.as_ref() != Some(&requested.repository)
            || !workflow_event.is_some_and(|event| config.policy.allows_event(event))
        {
            evaluate_release_protection(&requested, &workflow_run, None, &config.policy)
        } else {
            evaluate_gate_deployment_candidates(
                &config.http_client,
                &config.github_api_base,
                &installation_token.token,
                &requested,
                &config.policy,
            )
            .await?
        }
    };

    github::review_deployment_protection_rule(
        &config.http_client,
        &installation_token.token,
        &requested.deployment_callback_url,
        &DeploymentProtectionRuleReviewPayload {
            environment_name: requested.environment.as_str(),
            state: match decision.state {
                ReleaseProtectionState::Approved => DeploymentProtectionRuleReviewState::Approved,
                ReleaseProtectionState::Rejected => DeploymentProtectionRuleReviewState::Rejected,
            },
            comment: decision.comment.as_str(),
        },
    )
    .await?;

    Ok(DeploymentProtectionRuleOutcome::Reviewed {
        repository: requested.repository,
        run_id: requested.run_id,
        environment: requested.environment,
        decision,
    })
}

async fn evaluate_gate_deployment_candidates(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    installation_token: &github::Token,
    requested: &RequestedDeploymentProtection,
    policy: &Policy,
) -> Result<ReleaseProtectionDecision, AppError> {
    let deployment_ids = github::fetch_environment_deployments(
        http_client,
        github_api_base,
        installation_token,
        &requested.repository,
        policy.release_gate_environment_name(),
        &requested.sha,
    )
    .await?;

    let mut rejection_comment = None;

    for deployment_id in deployment_ids {
        let Some(status) = github::fetch_latest_deployment_status(
            http_client,
            github_api_base,
            installation_token,
            &requested.repository,
            deployment_id,
        )
        .await?
        else {
            continue;
        };

        if status.state != DeploymentState::Success {
            rejection_comment.get_or_insert_with(|| {
                format!(
                    "{} deployment status is {}",
                    policy.release_gate_environment_name(),
                    status.state
                )
            });
            continue;
        }

        match validate_successful_gate_deployment_job(
            http_client,
            github_api_base,
            installation_token,
            requested,
            policy,
            &status,
        )
        .await?
        {
            GateDeploymentValidation::Matched => {
                return Ok(ReleaseProtectionDecision::approved(format!(
                    "{} deployment succeeded",
                    policy.release_gate_environment_name()
                )));
            }
            GateDeploymentValidation::Rejected(comment) => {
                rejection_comment.get_or_insert(comment);
            }
        }
    }

    Ok(rejection_comment.map_or_else(
        || {
            ReleaseProtectionDecision::rejected(format!(
                "no successful deployment to {} was found",
                policy.release_gate_environment_name()
            ))
        },
        ReleaseProtectionDecision::rejected,
    ))
}

async fn validate_successful_gate_deployment_job(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    installation_token: &github::Token,
    requested: &RequestedDeploymentProtection,
    policy: &Policy,
    status: &DeploymentStatusSummary,
) -> Result<GateDeploymentValidation, AppError> {
    let log_reference = match status.log_url.as_deref() {
        Some(url) => match WorkflowJobUrlReference::parse(url) {
            Some(reference) => Some(reference),
            None => {
                return Ok(GateDeploymentValidation::Rejected(format!(
                    "{} deployment status is missing a valid actions job url",
                    policy.release_gate_environment_name()
                )));
            }
        },
        None => None,
    };
    let target_reference = match status.target_url.as_deref() {
        Some(url) => match WorkflowJobUrlReference::parse(url) {
            Some(reference) => Some(reference),
            None => {
                return Ok(GateDeploymentValidation::Rejected(format!(
                    "{} deployment status is missing a valid actions job url",
                    policy.release_gate_environment_name()
                )));
            }
        },
        None => None,
    };

    let reference = match (log_reference, target_reference) {
        (Some(log_reference), Some(target_reference)) if log_reference != target_reference => {
            return Ok(GateDeploymentValidation::Rejected(format!(
                "{} deployment status URLs are inconsistent",
                policy.release_gate_environment_name()
            )));
        }
        (Some(reference), Some(_)) | (Some(reference), None) | (None, Some(reference)) => reference,
        (None, None) => {
            return Ok(GateDeploymentValidation::Rejected(format!(
                "{} deployment status is missing a valid actions job url",
                policy.release_gate_environment_name()
            )));
        }
    };

    if reference.repository != requested.repository {
        return Ok(GateDeploymentValidation::Rejected(format!(
            "{} deployment status references repository {}, expected {}",
            policy.release_gate_environment_name(),
            reference.repository,
            requested.repository
        )));
    }

    if reference.run_id != requested.run_id {
        return Ok(GateDeploymentValidation::Rejected(format!(
            "{} deployment status references workflow run {}, expected {}",
            policy.release_gate_environment_name(),
            reference.run_id,
            requested.run_id
        )));
    }

    let Some(job) = github::fetch_workflow_job(
        http_client,
        github_api_base,
        installation_token.as_ref(),
        requested.repository.owner().as_str(),
        requested.repository.name().as_str(),
        reference.job_id,
    )
    .await?
    else {
        return Ok(GateDeploymentValidation::Rejected(format!(
            "{} deployment status references missing workflow job {}",
            policy.release_gate_environment_name(),
            reference.job_id
        )));
    };

    if job.run_id != requested.run_id {
        return Ok(GateDeploymentValidation::Rejected(format!(
            "{} deployment job belongs to workflow run {}, expected {}",
            policy.release_gate_environment_name(),
            job.run_id,
            requested.run_id
        )));
    }

    if job.head_sha != requested.sha.as_str() {
        return Ok(GateDeploymentValidation::Rejected(format!(
            "{} deployment job sha {} does not match {}",
            policy.release_gate_environment_name(),
            job.head_sha,
            requested.sha.as_str()
        )));
    }

    if job.conclusion != Some(Conclusion::Success) {
        return Ok(GateDeploymentValidation::Rejected(format!(
            "{} deployment job {} concluded with {}",
            policy.release_gate_environment_name(),
            job.name,
            job.conclusion
                .map(|conclusion| conclusion.as_str())
                .unwrap_or("no conclusion")
        )));
    }

    if let Some(expected_job_name) = policy.release_gate_job_name() {
        if job.name != expected_job_name.as_str() {
            return Ok(GateDeploymentValidation::Rejected(format!(
                "{} deployment job {} does not match expected {}",
                policy.release_gate_environment_name(),
                job.name,
                expected_job_name
            )));
        }
    }

    Ok(GateDeploymentValidation::Matched)
}

pub fn evaluate_release_protection(
    requested: &RequestedDeploymentProtection,
    workflow_run: &WorkflowRunSummary,
    gate_deployment_state: Option<DeploymentState>,
    policy: &Policy,
) -> ReleaseProtectionDecision {
    if requested.environment.as_str() != policy.release_environment_name().as_str() {
        return ReleaseProtectionDecision::rejected(format!(
            "environment {} is not allowed",
            requested.environment
        ));
    }

    if !requested
        .git_ref
        .as_ref()
        .is_some_and(|git_ref| git_ref.matches_allowed_ref(policy.allowed_ref()))
    {
        return ReleaseProtectionDecision::rejected(format!(
            "ref {} is not allowed",
            requested
                .git_ref
                .as_ref()
                .map(RefName::as_str)
                .unwrap_or("<missing>")
        ));
    }

    let head_repository_name = workflow_run
        .head_repository
        .as_ref()
        .and_then(|repository| repository.full_name.as_deref());
    let head_repository = head_repository_name
        .map(str::to_owned)
        .map(Repository::try_from)
        .transpose()
        .ok()
        .flatten();
    if head_repository.as_ref() != Some(&requested.repository) {
        return ReleaseProtectionDecision::rejected(format!(
            "workflow run head repository {} is not allowed",
            head_repository_name.unwrap_or("<missing>")
        ));
    }

    let workflow_event = workflow_run.event.as_deref();
    if !workflow_event.is_some_and(|event| policy.allows_event(event)) {
        return ReleaseProtectionDecision::rejected(format!(
            "workflow run event {} is not allowed",
            workflow_event.unwrap_or("<missing>")
        ));
    }

    if workflow_run.path.as_deref() != Some(policy.release_workflow_path().as_str()) {
        return ReleaseProtectionDecision::rejected(format!(
            "workflow path {} is not allowed",
            workflow_run.path.as_deref().unwrap_or("<missing>")
        ));
    }

    match gate_deployment_state {
        Some(DeploymentState::Success) => ReleaseProtectionDecision::approved(format!(
            "{} deployment succeeded",
            policy.release_gate_environment_name()
        )),
        Some(state) => ReleaseProtectionDecision::rejected(format!(
            "{} deployment status is {}",
            policy.release_gate_environment_name(),
            state
        )),
        None => ReleaseProtectionDecision::rejected(format!(
            "no successful deployment to {} was found",
            policy.release_gate_environment_name()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::{evaluate_release_protection, ReleaseProtectionState};
    use crate::{
        config::{GitRef, Policy},
        github::{
            DeploymentProtectionRulePayload, DeploymentState, GithubApiBase,
            RequestedDeploymentProtection, WorkflowRunSummary,
        },
    };
    use serde_json::json;

    fn test_policy() -> Policy {
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

    fn test_github_api_base() -> GithubApiBase {
        GithubApiBase::try_from(String::from("https://api.github.com")).unwrap()
    }

    fn test_requested(environment: &str, git_ref: Option<&str>) -> RequestedDeploymentProtection {
        let mut payload = json!({
            "action": "requested",
            "environment": environment,
            "sha": "47efb7196c2a1a2fd3f52f2c59f0e2dd3d0e4d54",
            "installation": { "id": 1 },
            "repository": {
                "id": 1192056896,
                "full_name": "zaniebot/release-authenticator-example",
                "name": "release-authenticator-example",
                "owner": { "login": "zaniebot" }
            },
            "deployment_callback_url": "https://api.github.com/repos/zaniebot/release-authenticator-example/actions/runs/23625057533/deployment_protection_rule",
            "workflow_run": { "id": 23625057533_u64 }
        });
        if let Some(r) = git_ref {
            payload["ref"] = json!(r);
        }
        let payload: DeploymentProtectionRulePayload = serde_json::from_value(payload).unwrap();
        RequestedDeploymentProtection::parse(payload, &test_github_api_base()).unwrap()
    }

    fn workflow_run(path: &str) -> WorkflowRunSummary {
        workflow_run_from_repo_and_event(
            path,
            "zaniebot/release-authenticator-example",
            Some("workflow_dispatch"),
        )
    }

    fn workflow_run_from_repo(path: &str, full_name: &str) -> WorkflowRunSummary {
        workflow_run_from_repo_and_event(path, full_name, Some("workflow_dispatch"))
    }

    fn workflow_run_from_repo_and_event(
        path: &str,
        full_name: &str,
        event: Option<&str>,
    ) -> WorkflowRunSummary {
        serde_json::from_value(json!({
            "path": path,
            "event": event,
            "head_repository": {
                "full_name": full_name,
            },
        }))
        .unwrap()
    }

    #[test]
    fn git_ref_name_extracts_branch_and_tag_names() {
        assert_eq!(
            GitRef::try_from(String::from("refs/heads/main"))
                .unwrap()
                .name(),
            "main"
        );
        assert_eq!(
            GitRef::try_from(String::from("refs/tags/v1.0"))
                .unwrap()
                .name(),
            "v1.0"
        );
    }

    #[test]
    fn release_protection_decision_constructors() {
        let approved = super::ReleaseProtectionDecision::approved("ok");
        assert_eq!(approved.state, ReleaseProtectionState::Approved);
        assert_eq!(approved.comment, "ok");

        let rejected = super::ReleaseProtectionDecision::rejected("bad");
        assert_eq!(rejected.state, ReleaseProtectionState::Rejected);
        assert_eq!(rejected.comment, "bad");
    }

    #[test]
    fn evaluate_release_protection_rejects_missing_ref() {
        let decision = evaluate_release_protection(
            &test_requested("release", None),
            &workflow_run(".github/workflows/release.yml"),
            Some(DeploymentState::Success),
            &test_policy(),
        );

        assert_eq!(decision.state, ReleaseProtectionState::Rejected);
        assert!(decision.comment.contains("<missing>"));
    }

    #[test]
    fn evaluate_release_protection_rejects_missing_gate_deployment() {
        let decision = evaluate_release_protection(
            &test_requested("release", Some("main")),
            &workflow_run(".github/workflows/release.yml"),
            None,
            &test_policy(),
        );

        assert_eq!(decision.state, ReleaseProtectionState::Rejected);
        assert_eq!(
            decision.comment,
            "no successful deployment to release-gate was found"
        );
    }

    #[test]
    fn evaluate_release_protection_approves_after_gate_deployment_succeeds() {
        let decision = evaluate_release_protection(
            &test_requested("release", Some("main")),
            &workflow_run(".github/workflows/release.yml"),
            Some(DeploymentState::Success),
            &test_policy(),
        );

        assert_eq!(decision.state, ReleaseProtectionState::Approved);
        assert_eq!(decision.comment, "release-gate deployment succeeded");
    }

    #[test]
    fn evaluate_release_protection_rejects_fork_repository() {
        let decision = evaluate_release_protection(
            &test_requested("release", Some("main")),
            &workflow_run_from_repo(
                ".github/workflows/release.yml",
                "evil/release-authenticator-example",
            ),
            Some(DeploymentState::Success),
            &test_policy(),
        );

        assert_eq!(decision.state, ReleaseProtectionState::Rejected);
        assert_eq!(
            decision.comment,
            "workflow run head repository evil/release-authenticator-example is not allowed"
        );
    }

    #[test]
    fn evaluate_release_protection_rejects_unexpected_workflow_event() {
        let decision = evaluate_release_protection(
            &test_requested("release", Some("main")),
            &workflow_run_from_repo_and_event(
                ".github/workflows/release.yml",
                "zaniebot/release-authenticator-example",
                Some("push"),
            ),
            Some(DeploymentState::Success),
            &test_policy(),
        );

        assert_eq!(decision.state, ReleaseProtectionState::Rejected);
        assert_eq!(decision.comment, "workflow run event push is not allowed");
    }

    #[test]
    fn evaluate_release_protection_rejects_wrong_workflow_path() {
        let decision = evaluate_release_protection(
            &test_requested("release", Some("main")),
            &workflow_run(".github/workflows/ci.yml"),
            Some(DeploymentState::Success),
            &test_policy(),
        );

        assert_eq!(decision.state, ReleaseProtectionState::Rejected);
        assert!(decision.comment.contains("workflow path"));
    }

    #[test]
    fn evaluate_release_protection_rejects_failed_gate_deployment() {
        let decision = evaluate_release_protection(
            &test_requested("release", Some("main")),
            &workflow_run(".github/workflows/release.yml"),
            Some(DeploymentState::Failure),
            &test_policy(),
        );

        assert_eq!(decision.state, ReleaseProtectionState::Rejected);
        assert_eq!(
            decision.comment,
            "release-gate deployment status is failure"
        );
    }

    #[test]
    fn evaluate_release_protection_rejects_wrong_environment() {
        let decision = evaluate_release_protection(
            &test_requested("staging", Some("main")),
            &workflow_run(".github/workflows/release.yml"),
            Some(DeploymentState::Success),
            &test_policy(),
        );

        assert_eq!(decision.state, ReleaseProtectionState::Rejected);
        assert_eq!(decision.comment, "environment staging is not allowed");
    }

    #[test]
    fn evaluate_release_protection_rejects_wrong_ref() {
        let decision = evaluate_release_protection(
            &test_requested("release", Some("refs/tags/v1.2.3")),
            &workflow_run(".github/workflows/release.yml"),
            Some(DeploymentState::Success),
            &test_policy(),
        );

        assert_eq!(decision.state, ReleaseProtectionState::Rejected);
        assert_eq!(decision.comment, "ref refs/tags/v1.2.3 is not allowed");
    }
}
