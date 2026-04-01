macro_rules! id_type {
    ($name:ident) => {
        /// Wraps a non-zero GitHub identifier value.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, serde::Serialize)]
        pub struct $name(u64);

        impl $name {
            /// Creates a new identifier when the provided value is non-zero.
            pub fn new(value: u64) -> Option<Self> {
                (value != 0).then_some(Self(value))
            }
        }

        impl std::ops::Deref for $name {
            type Target = u64;

            fn deref(&self) -> &u64 {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                self.0.fmt(f)
            }
        }

        impl<'de> serde::Deserialize<'de> for $name {
            fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                struct Visitor;

                impl serde::de::Visitor<'_> for Visitor {
                    type Value = $name;

                    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                        write!(f, "a non-zero {} as a number or string", stringify!($name))
                    }

                    fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<Self::Value, E> {
                        $name::new(v).ok_or_else(|| {
                            E::custom(concat!(stringify!($name), " must be non-zero"))
                        })
                    }

                    fn visit_str<E: serde::de::Error>(self, v: &str) -> Result<Self::Value, E> {
                        let n = v.parse::<u64>().map_err(E::custom)?;
                        $name::new(n).ok_or_else(|| {
                            E::custom(concat!(stringify!($name), " must be non-zero"))
                        })
                    }
                }

                deserializer.deserialize_any(Visitor)
            }
        }
    };
}

mod api;
mod deployments;
mod repositories;
mod tokens;
mod webhooks;
mod workflows;

pub use api::{github_api_url, github_request, send_github_request, GithubApiBase};
pub use deployments::{
    review_deployment_protection_rule, DeploymentProtectionRulePayload,
    DeploymentProtectionRuleReviewPayload, DeploymentProtectionRuleReviewState, RefName,
    RequestedDeploymentProtection,
};
pub use repositories::{Repository, RepositoryId};
pub use tokens::{create_app_jwt, mint_installation_token, InstallationId};
pub use webhooks::{WebhookEvent, WebhookSignature};
pub use workflows::{
    fetch_workflow_jobs, fetch_workflow_run, Conclusion, RunId, WorkflowJobSummary,
    WorkflowRunSummary,
};
