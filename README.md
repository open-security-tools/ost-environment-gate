# ost-environment-gate

GitHub's environments allow adding required reviewers as a deployment protection rule. When applied
to a release environment, this allows for 2-factor release workflows where a second team member must
approve the workflow before it can access the release secrets.

Unfortunately GitHub applies the deployment protection to every job that runs in the workflow. If a
release process has multiple steps, then each step needs to be approved as it starts.

To work around this issue, we make use of the `deployment_protection_rule` webhook which a GitHub
App can subscribe to. The GitHub App can then be used to approve or deny deployments to an
environment. The human approval in a 2-factor release workflow is retained by having two
environments.

1. `release-gate`: This requires approval by a human
2. `release`: This requires approval from the GitHub App

The GitHub App has a simple purpose: approve the `release` deployment if the `release-gate`
deployment was approved.

## GitHub Actions workflow

A minimal workflow would look like this:

```yaml
name: Release

on:
  workflow_dispatch:
    inputs:
      version:
        required: true
        type: string

permissions: {}

jobs:
  release-gate:
    name: release-gate
    runs-on: ubuntu-latest
    environment: release-gate
    steps:
      - run: echo "Release approved"

  release:
    name: Publish release
    runs-on: ubuntu-latest
    needs: [release-gate]
    environment: release
    permissions:
      contents: write
    steps:
      - run: echo "Use a secret from release!"
```

## GitHub App

The minimal manifest for the GitHub App is:

```json
{
  "name": "ost-environment-gate",
  "url": "https://github.com/open-security-tools/ost-environment-gate/",
  "public": false,
  "hook_attributes": {
    "url": "https://example.execute-api.us-east-2.amazonaws.com/github/webhook",
    "active": true
  },
  "default_permissions": {
    "actions": "read",
    "deployments": "write"
  },
  "default_events": [
    "deployment_protection_rule"
  ]
}
```

The GitHub App requires the minimum permissions to perform this action.


## Webhook

The webhook API is implemented in Rust and deployed as a Lambda via AWS SAM.

The GitHub App ID and webhook secret are stored in AWS SSM Parameter Store. The GitHub App's private
key is stored in AWS Secrets Manager.

The webhook lifecycle is roughly:

1. Receive a `deployment_protection_rule` event from GitHub (other events are discarded)
1. Validate the event is authentic using the webhook secret
1. Use the private key to mint a JWT then exchange JWT for a GitHub access token
1. Extract the workflow run id from the event
1. Look up deployments for the configured environment and the same commit SHA
1. Read the latest status for the matching deployment
1. Extract the job run from the deployment status
1. Approve or deny the deployment according to the policy
1. Return an HTTP 204 indicating successful event receipt

Requests to the following GitHub routes are expected:

- `POST /app/installations/{id}/access_tokens`
- `GET /repos/{owner}/{repo}/actions/runs/{run_id}`
- `GET /repos/{owner}/{repo}/deployments`
- `GET /repos/{owner}/{repo}/deployments/{deployment_id}/statuses`
- `GET /repos/{owner}/{repo}/actions/jobs/{job_id}`
- `POST /repos/{owner}/{repo}/actions/runs/{run_id}/deployment_protection_rule`

## Policy

The deployment protection rule approves `release` only when all of these checks pass:

1. The requested environment matches `release_environment_name`
1. The requested Git ref matches `allowed_ref`
1. The workflow run event is included in `allowed_events`
1. The workflow run path matches `release_workflow_path`
1. The workflow run head repository matches the requesting repository (forks are rejected)
1. There is a successful deployment to `release_gate_environment_name` for the commit
1. The deployment status includes a valid GitHub Actions job URL
1. The referenced job belongs to the same repository, workflow run, and commit
1. The referenced job completed successfully
1. If `release_gate_job_name` is configured, the referenced job name matches it

An example policy is as follows:

```json
{
  "allowed_ref": "refs/heads/main",
  "allowed_events": ["workflow_dispatch"],
  "release_environment_name": "release",
  "release_gate_environment_name": "release-gate",
  "release_gate_job_name": "release-gate",
  "release_workflow_path": ".github/workflows/release.yml"
}
```
