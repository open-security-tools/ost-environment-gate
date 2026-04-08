use std::fmt;

use serde::{Deserialize, Serialize};

use crate::{
    error::AppError,
    github::{github_api_url, github_request, send_github_request, GithubApiBase},
};

id_type!(RunId);

/// Captures the repository that a workflow run executed from.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowRunRepositorySummary {
    pub full_name: Option<String>,
}

/// Captures the subset of workflow run metadata needed by the release rule.
#[derive(Debug, Clone, Deserialize)]
pub struct WorkflowRunSummary {
    pub path: Option<String>,
    pub head_repository: Option<WorkflowRunRepositorySummary>,
}

/// Represents the possible conclusions GitHub can report for a workflow job.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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

/// Captures the subset of workflow job metadata needed by the release rule.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct WorkflowJobSummary {
    pub name: String,
    pub conclusion: Option<Conclusion>,
}

/// Represents one page of workflow jobs returned by the GitHub API.
#[derive(Debug, Deserialize)]
struct WorkflowJobsPage {
    jobs: Vec<WorkflowJobSummary>,
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

/// Maximum number of pages to fetch when listing workflow jobs.
///
/// Each page contains up to 100 jobs, so this caps the total at 1 000 jobs per
/// run — well above any legitimate workflow while preventing unbounded pagination
/// from consuming Lambda memory and execution time.
const MAX_WORKFLOW_JOBS_PAGES: u32 = 10;

/// Fetches all workflow jobs for a run by following GitHub pagination.
pub async fn fetch_workflow_jobs(
    http_client: &reqwest::Client,
    github_api_base: &GithubApiBase,
    installation_token: &str,
    owner: &str,
    repo: &str,
    run_id: u64,
) -> Result<Vec<WorkflowJobSummary>, AppError> {
    let mut page = 1_u32;
    let mut jobs = Vec::new();

    loop {
        if page > MAX_WORKFLOW_JOBS_PAGES {
            tracing::warn!(
                max_pages = MAX_WORKFLOW_JOBS_PAGES,
                total_jobs = jobs.len(),
                "workflow jobs pagination limit reached"
            );
            break;
        }
        let url = github_api_url(
            github_api_base,
            &format!("repos/{owner}/{repo}/actions/runs/{run_id}/jobs?per_page=100&page={page}"),
        )?;

        let response = send_github_request(
            github_request(http_client.get(url), installation_token),
            "workflow jobs lookup",
        )
        .await
        .map_err(|error| {
            tracing::error!(?error, "workflow jobs lookup failed");
            AppError::WorkflowJobsLookupFailed
        })?;

        if !response.status().is_success() {
            tracing::error!(status = %response.status(), page, "unexpected workflow jobs status");
            return Err(AppError::WorkflowJobsLookupFailed);
        }

        let page_response = response.json::<WorkflowJobsPage>().await.map_err(|error| {
            tracing::error!(?error, page, "failed to decode workflow jobs response");
            AppError::WorkflowJobsLookupFailed
        })?;

        let page_len = page_response.jobs.len();
        jobs.extend(page_response.jobs);

        if page_len < 100 {
            break;
        }
        page += 1;
    }

    Ok(jobs)
}

#[cfg(test)]
mod tests {
    use super::{fetch_workflow_jobs, fetch_workflow_run};
    use crate::github::GithubApiBase;
    use serde_json::{json, Value};
    use wiremock::{
        matchers::{header, method, path, query_param},
        Mock, MockServer, ResponseTemplate,
    };

    fn test_http_client() -> reqwest::Client {
        reqwest::Client::builder().build().unwrap()
    }

    fn test_base_url(server: &MockServer) -> GithubApiBase {
        GithubApiBase::try_from(server.uri()).unwrap()
    }

    fn workflow_jobs(count: usize, offset: usize) -> Vec<Value> {
        (0..count)
            .map(|index| {
                json!({
                    "name": format!("job-{}", offset + index),
                    "conclusion": if index % 2 == 0 { "success" } else { "failure" },
                })
            })
            .collect()
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
    async fn fetch_workflow_jobs_follows_pagination() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/actions/runs/999/jobs"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "1"))
            .and(header("authorization", "Bearer installation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jobs": workflow_jobs(100, 0)
            })))
            .mount(&server)
            .await;

        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/actions/runs/999/jobs"))
            .and(query_param("per_page", "100"))
            .and(query_param("page", "2"))
            .and(header("authorization", "Bearer installation-token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jobs": workflow_jobs(1, 100)
            })))
            .mount(&server)
            .await;

        let jobs = fetch_workflow_jobs(
            &test_http_client(),
            &test_base_url(&server),
            "installation-token",
            "octo",
            "tools",
            999,
        )
        .await
        .unwrap();

        assert_eq!(jobs.len(), 101);
        assert_eq!(jobs.first().map(|job| job.name.as_str()), Some("job-0"));
        assert_eq!(jobs.last().map(|job| job.name.as_str()), Some("job-100"));
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
    async fn fetch_workflow_jobs_stops_at_page_limit() {
        let server = MockServer::start().await;

        for page in 1..=super::MAX_WORKFLOW_JOBS_PAGES {
            Mock::given(method("GET"))
                .and(path("/repos/octo/tools/actions/runs/999/jobs"))
                .and(query_param("per_page", "100"))
                .and(query_param("page", page.to_string()))
                .and(header("authorization", "Bearer installation-token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "jobs": workflow_jobs(100, ((page - 1) * 100) as usize)
                })))
                .expect(1)
                .mount(&server)
                .await;
        }

        // Page beyond the limit should never be requested.
        Mock::given(method("GET"))
            .and(path("/repos/octo/tools/actions/runs/999/jobs"))
            .and(query_param(
                "page",
                (super::MAX_WORKFLOW_JOBS_PAGES + 1).to_string(),
            ))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "jobs": workflow_jobs(1, 9999)
            })))
            .expect(0)
            .mount(&server)
            .await;

        let jobs = fetch_workflow_jobs(
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
            jobs.len(),
            (super::MAX_WORKFLOW_JOBS_PAGES * 100) as usize,
            "should return exactly MAX_WORKFLOW_JOBS_PAGES * 100 jobs"
        );
    }
}
