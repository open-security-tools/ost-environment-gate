# ost-environment-gate

Rust AWS Lambda that handles GitHub App `deployment_protection_rule` webhooks
and approves or rejects the protected release environment based on a
configurable policy.

## How it works

When a workflow run requests a deployment to a protected environment, GitHub
sends a `deployment_protection_rule` webhook. This Lambda:

1. Verifies the webhook signature
2. Mints a scoped GitHub App installation token
3. Fetches the workflow run and its jobs
4. Evaluates the policy (ref, environment, workflow path, gate job)
5. Posts an approval or rejection back to GitHub

## Endpoints

- `GET /health` — liveness check
- `POST /github/webhook` — GitHub App webhook receiver

## Policy

The gate evaluates four conditions, all of which must pass:

| Field | Description |
|---|---|
| `allowed_ref` | Canonical git ref (e.g. `refs/heads/main`) |
| `release_environment_name` | GitHub environment name to protect |
| `release_gate_job_name` | Job that must succeed before approval |
| `release_workflow_path` | Workflow file path that must match |

Example `policy.json`:

```json
{
  "allowed_ref": "refs/heads/main",
  "release_environment_name": "release",
  "release_gate_job_name": "release-gate",
  "release_workflow_path": ".github/workflows/release.yml"
}
```

## GitHub App setup

### Permissions

- **Actions**: read-only
- **Deployments**: read and write
- **Metadata**: read-only

### Webhook events

- `deployment_protection_rule`

### Installation

Install the app on the target repository. The app must be added as a
**custom deployment protection rule** on the environment specified in the
policy (e.g. `release`).

## Deployment

### Prerequisites

- [cargo-lambda](https://www.cargo-lambda.info/)
- [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html)
- [jq](https://jqlang.github.io/jq/)
- AWS credentials configured

### First deployment

```bash
# 1. Create the env file
cp .env.example .env

# 2. Fill in .env with your values (see below)

# 3. Place the GitHub App private key
mkdir -p .secrets
cp /path/to/your-app.private-key.pem .secrets/github-app-private-key.pem

# 4. Create the policy file
#    Edit policy.json with your repo's settings
cp policy-example.json policy.json

# 5. Sync secrets to AWS
make deploy-secrets

# 6. Deploy the stack
make deploy
```

### .env reference

```bash
STACK_NAME=ost-environment-gate
POLICY_FILE=policy.json

# GitHub App credentials
APP_ID=your-app-id          # numeric App ID or Client ID
APP_ID_PARAMETER=/ost/app-id
APP_PRIVATE_KEY_FILE=.secrets/github-app-private-key.pem
APP_PRIVATE_KEY_SECRET_NAME=ost/app-private-key

# Webhook secret (must match the secret configured in the GitHub App)
GITHUB_WEBHOOK_SECRET=your-webhook-secret
WEBHOOK_SECRET_PARAMETER=/ost/webhook-secret
```

> **Note**: The GitHub App Client ID (e.g. `Iv23livJGL0RUXC4JUfC`) can be
> used in place of the numeric App ID for installation token requests.

### What `make deploy-secrets` does

Syncs three values from `.env` into AWS:

| Source | Destination | Service |
|---|---|---|
| `APP_ID` | `APP_ID_PARAMETER` | SSM SecureString |
| `GITHUB_WEBHOOK_SECRET` | `WEBHOOK_SECRET_PARAMETER` | SSM SecureString |
| `APP_PRIVATE_KEY_FILE` | `APP_PRIVATE_KEY_SECRET_NAME` | Secrets Manager |

### What `make deploy` does

1. Compacts `policy.json` with `jq -c`
2. Runs `sam build --beta-features --no-use-container`
3. Runs `sam deploy` against `.aws-sam/build/template.yaml` with:
   - `--resolve-s3`
   - `--capabilities CAPABILITY_IAM`
   - `--no-fail-on-empty-changeset`
   - policy and parameter overrides from `.env`

### IAM permissions

The SAM template grants the Lambda:

- `ssm:GetParameter` on the app ID and webhook secret parameters
- `secretsmanager:GetSecretValue` on the private key secret

SSM parameter names must include the leading `/` (e.g. `/ost/app-id`). The
template constructs IAM ARNs correctly from these names.

### After deployment

The stack outputs:

- **ApiUrl** — base URL for the API Gateway
- **WebhookUrl** — the full URL to configure as the GitHub App webhook endpoint

Configure the `WebhookUrl` as your GitHub App's webhook URL with the same
secret you set in `GITHUB_WEBHOOK_SECRET`.

## Example workflow

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
    environment:
      name: release-gate
      deployment: false
    steps:
      - run: echo "Release approved"

  release:
    name: Create release
    runs-on: ubuntu-latest
    needs: [release-gate]
    environment: release
    permissions:
      contents: write
    steps:
      - uses: actions/checkout@v4
      - run: gh release create "v${{ inputs.version }}" --generate-notes
        env:
          GH_TOKEN: ${{ github.token }}
```

The `release-gate` environment requires manual approval. The `release`
environment is protected by the deployment protection rule, which the gate
Lambda evaluates automatically.

## Local development

```bash
cargo test       # run tests
cargo fmt        # format code
```

### Running tests

The test suite includes:

- Policy deserialization and validation
- Deployment protection payload parsing
- Release protection evaluation logic
- GitHub API client tests using wiremock
- Webhook signature verification

## Configuration reference

### Runtime environment variables

| Variable | Source | Description |
|---|---|---|
| `POLICY_JSON` | SAM parameter | Compacted policy JSON |
| `APP_ID_PARAMETER` | SAM parameter | SSM parameter name for the App ID |
| `APP_PRIVATE_KEY_SECRET_NAME` | SAM parameter | Secrets Manager secret name |
| `WEBHOOK_SECRET_PARAMETER` | SAM parameter | SSM parameter name for webhook secret |
| `GITHUB_API_URL` | Optional | Override GitHub API base URL (default: `https://api.github.com/`) |

### Direct environment variables (for local development)

| Variable | Description |
|---|---|
| `APP_ID` | GitHub App ID or Client ID |
| `APP_PRIVATE_KEY` | PEM private key (escaped newlines supported) |
| `GITHUB_WEBHOOK_SECRET` | Webhook secret string |
