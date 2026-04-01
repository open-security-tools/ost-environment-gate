┌──────────────────────────────────────────────────────────────────────┐
│                           ost-environment-gate                      │
└──────────────────────────────────────────────────────────────────────┘

                                 HTTP / Lambda
                                       │
                                       ▼
                              ┌────────────────┐
                              │   src/main.rs  │
                              │----------------│
                              │ route request  │
                              │ read body      │
                              │ build response │
                              └───────┬────────┘
                                      │
                     ┌────────────────┴────────────────┐
                     │                                 │
                     ▼                                 ▼
        ┌────────────────────────┐        ┌──────────────────────────┐
        │ github::WebhookEvent   │        │ github::WebhookSignature │
        │ github/webhooks.rs     │        │ github/webhooks.rs       │
        │------------------------│        │--------------------------│
        │ x-github-event header  │        │ x-hub-signature-256      │
        └────────────┬───────────┘        └────────────┬─────────────┘
                     │                                 │
                     └────────────────┬────────────────┘
                                      ▼
                             ┌────────────────┐
                             │ src/rule.rs    │
                             │----------------│
                   │ handle_deployment_protection_rule_webhook │
                             │ evaluate rule  │
                             └───────┬────────┘
                                     │
           raw GitHub payload        │        validated domain input
                                     │
                 ▼                   │                   ▼
   ┌──────────────────────────────┐  │   ┌──────────────────────────────────┐
   │ DeploymentProtectionRulePayload│──┼──▶ RequestedDeploymentProtection   │
   │ github/deployments.rs        │  │   │ github/deployments.rs            │
   │------------------------------│  │   │----------------------------------│
   │ installation                 │  │   │ environment: EnvironmentName     │
   │ repository payload           │  │   │ git_ref: Option<RefName>         │
   │ workflow_run                 │  │   │ installation_id: InstallationId  │
   └──────────────────────────────┘  │   │ repository: Repository           │
                                     │   │ repository_id: RepositoryId      │
                                     │   │ run_id: RunId                    │
                                     │   └──────────────────────────────────┘
                                     │
                                     ▼
                    ┌───────────────────────────────────────┐
                    │       config / validated inputs       │
                    └───────────────────────────────────────┘
                                     │
             ┌───────────────────────┼────────────────────────┬──────────────────────┐
             ▼                       ▼                        ▼                      ▼
 ┌──────────────────┐   ┌──────────────────────┐  ┌──────────────────┐  ┌────────────────────┐
 │ Policy           │   │ Config               │                          │ AppError           │
 │ src/config.rs    │   │ src/config.rs        │                          │ src/error.rs       │
 │------------------│   │----------------------│                          │--------------------│
 │ allowed_ref      │   │ app_id               │                          │ shared error enum  │
 │ allowed_events   │   │ app_private_key      │                          │ + http status/code │
 │ env name         │   │ webhook_secret       │                          └────────────────────┘
 │ gate env         │   │ github_api_base      │
 │ gate job         │   │ http_client          │
 │ workflow path    │   └──────────────────────┘
 └──────────────────┘

                                     GitHub API layer
                                           │
          ┌────────────────────────────────┼────────────────────────────────┐
          ▼                                ▼                                ▼
┌──────────────────────┐      ┌──────────────────────┐       ┌────────────────────────┐
│ github/tokens.rs     │      │ github/workflows.rs  │       │ github/repositories.rs │
│----------------------│      │----------------------│       │------------------------│
│ create_app_jwt       │      │ fetch_workflow_run   │       │ RepositoryOwner        │
│ mint_installation... │      │ RunId                │       │ RepositoryName         │
│ InstallationId       │      │ WorkflowRunSummary   │       │ Repository             │
│ Token                │      └───────────┬──────────┘       │ RepositoryId           │
│ InstallationToken    │                  │                  └────────────────────────┘
└───────────┬──────────┘                  │
            │                 ┌───────────▼──────────┐
            │                 │ github/deployments.rs│
            │                 │----------------------│
            │                 │ fetch_latest_env...  │
            │                 │ fetch_latest_deploy...│
            │                 │ DeploymentState      │
            └───────────────┬─┴──────────────────────┘
                            ▼
              ┌─────────────────────────────────┐
              │ ReleaseProtectionDecision       │
              │ rule.rs                         │
              │---------------------------------│
              │ state: Approved | Rejected      │
              │ comment: String                 │
              └─────────────────┬───────────────┘
                                │
                                ▼
              ┌─────────────────────────────────┐
              │ review_deployment_protection... │
              │ github/deployments.rs           │
              └─────────────────┬───────────────┘
                                │
                                ▼
                    ┌───────────────────────────┐
                    │ DeploymentProtectionRuleOutcome │
                    │ rule.rs                   │
                    │---------------------------│
                    │ Ignored { action }        │
                    │ Reviewed { ... }          │
                    └──────────────┬────────────┘
                                   │
                                   ▼
                           ┌────────────────┐
                           │   src/main.rs  │
                           │ JSON response  │
                           └────────────────┘


Legend
======
[raw payload]     = GitHub JSON shape
[validated type]  = app-level checked abstraction
[API helper]      = outbound GitHub call
