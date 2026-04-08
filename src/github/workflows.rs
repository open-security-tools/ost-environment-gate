use std::fmt;

use crate::{
    error::AppError,
    github::{github_api_url, github_request, send_github_request, GithubApiBase, Repository},
};
use reqwest::StatusCode;
use serde::Deserialize;

id_type!(RunId);
id_type!(WorkflowJobId);

/// Captures the repository that a workflow run executed from.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowRunRepositorySummary {
    pub full_name: Option<String>,
}

/// Captures the subset of workflow run metadata needed by the release rule.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowRunSummary {
    pub path: Option<String>,
    pub event: Option<String>,
    pub head_repository: Option<WorkflowRunRepositorySummary>,
}

/// Represents the possible conclusions GitHub can report for a workflow job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Conclusion {
    Success,
    Failure,
    Cancelled,
    Skipped,
    TimedOut,
    ActionRequired,
    Neutral,
    #[serde(other)]
    Unknown,
}

impl Conclusion {
    /// Returns the GitHub API string value for this conclusion.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Failure => "failure",
            Self::Cancelled => "cancelled",
            Self::Skipped => "skipped",
            Self::TimedOut => "timed_out",
            Self::ActionRequired => "action_required",
            Self::Neutral => "neutral",
            Self::Unknown => "unknown",
        }
    }
}

impl fmt::Display for Conclusion {
    /// Formats the conclusion using its GitHub API string value.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl WorkflowJobUrlReference {
    /// Parses a GitHub Actions job URL like `/owner/repo/actions/runs/<run>/job/<job>`.
    pub fn parse(value: &str, github_web_origin: &reqwest::Url) -> Option<Self> {
        let url = reqwest::Url::parse(value).ok()?;
        if !matches_github_web_origin(&url, github_web_origin) {
            return None;
        }

        let segments = url.path_segments()?.collect::<Vec<_>>();

        segments.windows(7).find_map(|window| {
            if window[2] != "actions" || window[3] != "runs" || window[5] != "job" {
                return None;
            }

            Some(Self {
                repository: Repository::try_from((window[0].to_string(), window[1].to_string()))
                    .ok()?,
                run_id: window[4].parse::<u64>().ok().and_then(RunId::new)?,
                job_id: window[6].parse::<u64>().ok().and_then(WorkflowJobId::new)?,
            })
        })
    }
}

fn matches_github_web_origin(url: &reqwest::Url, github_web_origin: &reqwest::Url) -> bool {
    url.scheme() == github_web_origin.scheme()
        && url.host_str() == github_web_origin.host_str()
        && url.port_or_known_default() == github_web_origin.port_or_known_default()
}

/// Identifies a GitHub Actions job URL and the workflow/job ids it references.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkflowJobUrlReference {
    pub repository: Repository,
    pub run_id: RunId,
    pub job_id: WorkflowJobId,
}

/// Captures the subset of workflow job metadata needed by the release rule.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WorkflowJobSummary {
    pub run_id: RunId,
    pub head_sha: String,
    pub name: String,
    pub conclusion: Option<Conclusion>,
}

/// Fetches the workflow run metadata needed to validate a release request.
pub async fn fetch_workflow_run(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    installation_token: &str,
    owner: &str,
    repo: &str,
    run_id: u64,
) -> Result<WorkflowRunSummary, AppError> {
    let url = github_api_url(
        github_api_base,
        &format!("repos/{owner}/{repo}/actions/runs/{run_id}"),
    )?;

    let response = send_github_request(
        github_request(http_client.get(url), installation_token),
        "workflow run lookup",
    )
    .await
    .map_err(|error| {
        tracing::error!(?error, "workflow run lookup failed");
        AppError::WorkflowRunLookupFailed
    })?;

    if !response.status().is_success() {
        tracing::error!(status = %response.status(), "unexpected workflow run status");
        return Err(AppError::WorkflowRunLookupFailed);
    }

    response
        .json::<WorkflowRunSummary>()
        .await
        .map_err(|error| {
            tracing::error!(?error, "failed to decode workflow run response");
            AppError::WorkflowRunLookupFailed
        })
}

/// Fetches a workflow job by id so deployment status URLs can be validated against Actions data.
pub async fn fetch_workflow_job(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    installation_token: &str,
    owner: &str,
    repo: &str,
    job_id: WorkflowJobId,
) -> Result<Option<WorkflowJobSummary>, AppError> {
    let url = github_api_url(
        github_api_base,
        &format!("repos/{owner}/{repo}/actions/jobs/{job_id}"),
    )?;

    let response = send_github_request(
        github_request(http_client.get(url), installation_token),
        "workflow job lookup",
    )
    .await
    .map_err(|error| {
        tracing::error!(?error, %job_id, "workflow job lookup failed");
        AppError::WorkflowJobLookupFailed
    })?;

    if response.status() == StatusCode::NOT_FOUND {
        tracing::warn!(%job_id, "workflow job was not found");
        return Ok(None);
    }

    if !response.status().is_success() {
        tracing::error!(status = %response.status(), %job_id, "unexpected workflow job status");
        return Err(AppError::WorkflowJobLookupFailed);
    }

    response
        .json::<WorkflowJobSummary>()
        .await
        .map(Some)
        .map_err(|error| {
            tracing::error!(?error, %job_id, "failed to decode workflow job response");
            AppError::WorkflowJobLookupFailed
        })
}

#[cfg(test)]
mod tests {
    use super::{
        fetch_workflow_job, fetch_workflow_run, Conclusion, WorkflowJobId, WorkflowJobUrlReference,
    };
    use crate::github::GithubApiBase;
    use serde_json::json;
    use wiremock::{
        matchers::{header, method, path},
        Mock, MockServer, ResponseTemplate,
    };

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn test_base_url(server: &MockServer) -> GithubApiBase {
        GithubApiBase::try_from(server.uri()).unwrap()
    }

    #[test]
    fn workflow_job_url_reference_parses_actions_job_urls() {
        let github_web_origin = reqwest::Url::parse("https://github.com/").unwrap();
        let reference = WorkflowJobUrlReference::parse(
            "https://github.com/zaniebot/release-authenticator-example/actions/runs/23625057533/job/69582278191",
            &github_web_origin,
        )
        .unwrap();

        assert_eq!(
            reference.repository.to_string(),
            "zaniebot/release-authenticator-example"
        );
        assert_eq!(*reference.run_id, 23625057533);
        assert_eq!(*reference.job_id, 69582278191);
    }

    #[test]
    fn workflow_job_url_reference_rejects_wrong_origin() {
        let github_web_origin = reqwest::Url::parse("https://github.com/").unwrap();

        let reference = WorkflowJobUrlReference::parse(
            "https://attacker.invalid/zaniebot/release-authenticator-example/actions/runs/23625057533/job/69582278191",
            &github_web_origin,
        );

        assert_eq!(reference, None);
    }

    #[tokio::test]
    async fn fetch_workflow_run_decodes_workflow_path() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/actions/runs/999"))
            .and(header("authorization", "Bearer installation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "path": ".github/workflows/release.yml"
            })))
            .mount(&server)
            .await;

        let workflow_run = fetch_workflow_run(
            &test_http_client(),
            &test_base_url(&server),
            "installation-token",
            "octo",
            "tools",
            999,
        )
        .await
        .unwrap();

        assert_eq!(
            workflow_run.path.as_deref(),
            Some(".github/workflows/release.yml")
        );
    }

    #[tokio::test]
    async fn fetch_workflow_job_decodes_job_summary() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/actions/jobs/123"))
            .and(header("authorization", "Bearer installation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "run_id": 999,
                "head_sha": "abc123",
                "name": "release-gate",
                "conclusion": "success"
            })))
            .mount(&server)
            .await;

        let job = fetch_workflow_job(
            &test_http_client(),
            &test_base_url(&server),
            "installation-token",
            "octo",
            "tools",
            WorkflowJobId::new(123).unwrap(),
        )
        .await
        .unwrap()
        .expect("workflow job should be present");

        assert_eq!(*job.run_id, 999);
        assert_eq!(job.head_sha, "abc123");
        assert_eq!(job.name, "release-gate");
        assert_eq!(job.conclusion, Some(Conclusion::Success));
    }

    #[tokio::test]
    async fn fetch_workflow_run_rejects_non_success() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/actions/runs/999"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let error = fetch_workflow_run(
            &test_http_client(),
            &test_base_url(&server),
            "tok",
            "octo",
            "tools",
            999,
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            crate::error::AppError::WorkflowRunLookupFailed
        ));
    }

    #[tokio::test]
    async fn fetch_workflow_job_returns_none_when_not_found() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/actions/jobs/123"))
            .respond_with(ResponseTemplate::new(404))
            .mount(&server)
            .await;

        let job = fetch_workflow_job(
            &test_http_client(),
            &test_base_url(&server),
            "tok",
            "octo",
            "tools",
            WorkflowJobId::new(123).unwrap(),
        )
        .await
        .unwrap();

        assert_eq!(job, None);
    }

    #[tokio::test]
    async fn fetch_workflow_job_rejects_server_errors() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/actions/jobs/123"))
            .respond_with(ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let error = fetch_workflow_job(
            &test_http_client(),
            &test_base_url(&server),
            "tok",
            "octo",
            "tools",
            WorkflowJobId::new(123).unwrap(),
        )
        .await
        .unwrap_err();

        assert!(matches!(
            error,
            crate::error::AppError::WorkflowJobLookupFailed
        ));
    }
}
