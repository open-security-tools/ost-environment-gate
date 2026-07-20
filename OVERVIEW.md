┌──────────────────────────────────────────────────────────────────────┐
│                         ost-environment-gate                        │
└──────────────────────────────────────────────────────────────────────┘

 GitHub webhook                         AWS
       │                                 │
       ▼                                 ▼
┌────────────────────┐         ┌─────────────────────────┐
│ Webhook Lambda     │────────▶│ Deployment-review FIFO  │
│ src/main.rs        │         │ + FIFO dead-letter queue│
│--------------------│         └────────────┬────────────┘
│ verify signature   │                      │
│ validate payload   │                      │ group: repository/run/environment
│ enqueue + HTTP 204 │                      │ dedup: delivery id
└────────────────────┘                      ▼
                               ┌─────────────────────────┐
                               │ Worker Lambda           │
                               │ src/worker.rs           │
                               │-------------------------│
                               │ coalesce FIFO batch     │
                               │ evaluate policy         │
                               │ submit one review       │
                               │ verify pending state    │
                               └────────────┬────────────┘
                                            │
                                            ▼
                               ┌─────────────────────────┐
                               │ GitHub API layer        │
                               │ src/github/*            │
                               │-------------------------│
                               │ installation token      │
                               │ run/deployment/job      │
                               │ protection review       │
                               │ pending deployments     │
                               └─────────────────────────┘

The webhook Lambda has permission only to read its shared secret and enqueue a
validated request. The worker holds the GitHub App credentials and evaluates
the policy. FIFO ordering permits unrelated runs to progress concurrently
while ensuring only one worker evaluates and reviews a given environment at a
time. Independent FIFO groups in the same batch can progress concurrently; a
failed group is returned for retry without blocking unrelated releases.
