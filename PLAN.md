# Plan: make deployment protection approvals resilient

## Problem

Large matrix release workflows can create many deployments to the protected `release` environment at nearly the same time. GitHub then sends many `deployment_protection_rule` webhooks concurrently.

In production, some approval requests succeeded, but many concurrent review calls returned GitHub's generic 422 response:

```text
There was a problem approving one of the gates
```

The service currently treats that response as an unexpected GitHub API failure and returns 502 to GitHub. Those webhook deliveries show as failed in the GitHub App UI, and some jobs can remain stuck waiting for app approval.

This appears to be a GitHub-side concurrency/race behavior, but the service should be resilient to it.

## Immediate mitigation

1. Redeliver the failed `deployment_protection_rule` webhooks from the GitHub App delivery UI.
2. If redelivery still returns 502 and the release is blocked, temporarily bypass/disable the app gate if acceptable for the release.

## Durable fix

### 1. Serialize reviews per run/environment

Add a short-lived distributed lock keyed by:

- repository
- workflow run id
- protected environment

For production, use DynamoDB with TTL. Each webhook should:

1. Acquire the lock for `(repository, run_id, environment)` with a short TTL, e.g. 30–60 seconds.
2. Evaluate the existing policy checks.
3. Submit the deployment protection review.
4. Release the lock.

This prevents many Lambda invocations from reviewing gates for the same workflow run/environment concurrently.

### 2. Make ambiguous 422 handling resilient

Keep the current idempotent 422 handling for:

- `No pending deployment requests to approve or reject`
- `Deployment protection rule has already been reviewed`

For GitHub's generic response:

```text
There was a problem approving one of the gates
```

handle it as an ambiguous/racy response:

1. Retry once after a short delay while still holding the lock, or
2. Re-check the run's pending deployments before deciding whether to return an error.

Only return 502 if the gate is still pending and the retry/re-check cannot resolve it.

### 3. Improve observability

Log the GitHub delivery id (`X-GitHub-Delivery`) for every webhook request, along with:

- repository
- workflow run id
- environment
- decision state/comment
- GitHub review API status and response body for non-success responses

This makes it possible to correlate CloudWatch logs with GitHub App deliveries and redeliver specific failed events.

## Expected outcome

- Concurrent matrix deployments no longer race through the GitHub review API.
- Generic GitHub 422s do not strand jobs unnecessarily.
- Failed deliveries can be traced and redelivered precisely.
