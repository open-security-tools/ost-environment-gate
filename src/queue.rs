use std::env;

use aws_sdk_sqs::Client as SqsClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    error::AppError,
    github::{DeploymentProtectionRulePayload, RequestedDeploymentProtection},
};

#[derive(Clone)]
pub struct DeploymentReviewQueue {
    backend: QueueBackend,
}

#[derive(Clone)]
enum QueueBackend {
    Sqs {
        client: SqsClient,
        queue_url: String,
    },
    #[cfg(test)]
    InMemory {
        messages: std::sync::Arc<std::sync::Mutex<Vec<QueuedDeploymentReview>>>,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DeploymentReviewMessage {
    pub delivery_id: String,
    pub payload: DeploymentProtectionRulePayload,
}

#[cfg(test)]
#[derive(Clone, Debug)]
pub struct QueuedDeploymentReview {
    pub body: String,
    pub group_id: String,
    pub deduplication_id: String,
}

impl DeploymentReviewQueue {
    pub fn from_env(client: SqsClient) -> Result<Self, AppError> {
        let queue_url = env::var("DEPLOYMENT_REVIEW_QUEUE_URL")
            .map_err(|_| AppError::DeploymentReviewQueueNotConfigured)?;
        if queue_url.trim().is_empty() {
            return Err(AppError::DeploymentReviewQueueNotConfigured);
        }

        Ok(Self {
            backend: QueueBackend::Sqs { client, queue_url },
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            backend: QueueBackend::InMemory {
                messages: std::sync::Arc::new(std::sync::Mutex::new(Vec::new())),
            },
        }
    }

    pub async fn enqueue(
        &self,
        delivery_id: &str,
        payload: DeploymentProtectionRulePayload,
        requested: &RequestedDeploymentProtection,
    ) -> Result<(), AppError> {
        let delivery_id = canonical_delivery_id(delivery_id)?;
        let message = DeploymentReviewMessage {
            delivery_id: delivery_id.clone(),
            payload,
        };
        let body = serde_json::to_string(&message)
            .map_err(|_| AppError::DeploymentProtectionPayloadInvalid)?;
        let group_id = deployment_review_group_id(requested);
        let deduplication_id = hash_identifier(&delivery_id);

        match &self.backend {
            QueueBackend::Sqs { client, queue_url } => client
                .send_message()
                .queue_url(queue_url)
                .message_body(body)
                .message_group_id(group_id)
                .message_deduplication_id(deduplication_id)
                .send()
                .await
                .map(|_| ())
                .map_err(|error| {
                    tracing::error!(?error, delivery_id = %delivery_id, "failed to enqueue deployment review");
                    AppError::DeploymentReviewQueueUnavailable
                }),
            #[cfg(test)]
            QueueBackend::InMemory { messages } => {
                let mut messages = messages.lock().expect("deployment review queue poisoned");
                if !messages
                    .iter()
                    .any(|message| message.deduplication_id == deduplication_id)
                {
                    messages.push(QueuedDeploymentReview {
                        body,
                        group_id,
                        deduplication_id,
                    });
                }
                Ok(())
            }
        }
    }

    #[cfg(test)]
    pub fn take_messages(&self) -> Vec<QueuedDeploymentReview> {
        match &self.backend {
            QueueBackend::Sqs { .. } => unreachable!("tests use the in-memory queue"),
            QueueBackend::InMemory { messages } => {
                std::mem::take(&mut *messages.lock().expect("deployment review queue poisoned"))
            }
        }
    }
}

pub fn deployment_review_group_id(requested: &RequestedDeploymentProtection) -> String {
    hash_identifier(&format!(
        "{}/{}/{}",
        *requested.repository_id,
        *requested.run_id,
        requested.environment.as_str().to_ascii_lowercase()
    ))
}

pub(crate) fn canonical_delivery_id(value: &str) -> Result<String, AppError> {
    let delivery_id = Uuid::parse_str(value).map_err(|_| AppError::InvalidGithubDelivery)?;
    if delivery_id.is_nil() || delivery_id.to_string() != value {
        return Err(AppError::InvalidGithubDelivery);
    }

    Ok(delivery_id.to_string())
}

fn hash_identifier(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[cfg(test)]
mod tests {
    use aws_sdk_sqs::config::{retry::RetryConfig, BehaviorVersion, Credentials, Region};
    use serde_json::{json, Value};
    use wiremock::{matchers::method, Mock, MockServer, ResponseTemplate};

    use super::{
        deployment_review_group_id, hash_identifier, DeploymentReviewMessage,
        DeploymentReviewQueue, QueueBackend,
    };
    use crate::{
        error::AppError,
        github::{DeploymentProtectionRulePayload, GithubApiBase, RequestedDeploymentProtection},
    };

    fn requested_payload() -> (
        DeploymentProtectionRulePayload,
        RequestedDeploymentProtection,
    ) {
        let payload: DeploymentProtectionRulePayload = serde_json::from_str(include_str!(
            "../testdata/deployment-protection-requested.json"
        ))
        .unwrap();
        let requested = RequestedDeploymentProtection::parse(
            payload.clone(),
            &GithubApiBase::try_from(String::from("https://api.github.com")).unwrap(),
        )
        .unwrap();
        (payload, requested)
    }

    fn sqs_queue(server: &MockServer, queue_url: &str) -> DeploymentReviewQueue {
        let config = aws_sdk_sqs::config::Builder::new()
            .behavior_version(BehaviorVersion::latest())
            .credentials_provider(Credentials::new(
                "test-key",
                "test-secret",
                None,
                None,
                "test",
            ))
            .region(Region::new("us-east-2"))
            .endpoint_url(server.uri())
            .retry_config(RetryConfig::standard().with_max_attempts(1))
            .build();
        DeploymentReviewQueue {
            backend: QueueBackend::Sqs {
                client: aws_sdk_sqs::Client::from_conf(config),
                queue_url: queue_url.to_string(),
            },
        }
    }

    #[tokio::test]
    async fn sqs_send_message_sets_the_fifo_group_deduplication_and_compact_body() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "MessageId": "message-1",
                "SequenceNumber": "1"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let queue_url = format!("{}/123456789012/deployment-reviews.fifo", server.uri());
        let queue = sqs_queue(&server, &queue_url);
        let (payload, requested) = requested_payload();
        let delivery_id = "00000000-0000-4000-8000-000000000001";

        queue
            .enqueue(delivery_id, payload, &requested)
            .await
            .unwrap();

        let requests = server.received_requests().await.unwrap();
        let request = requests.first().unwrap();
        let body: Value = serde_json::from_slice(&request.body).unwrap();
        assert_eq!(body["QueueUrl"], queue_url);
        assert_eq!(
            body["MessageGroupId"],
            deployment_review_group_id(&requested)
        );
        assert_eq!(body["MessageDeduplicationId"], hash_identifier(delivery_id));
        let queued: DeploymentReviewMessage =
            serde_json::from_str(body["MessageBody"].as_str().unwrap()).unwrap();
        assert_eq!(queued.delivery_id, delivery_id);
        assert_eq!(queued.payload.deployment.unwrap().id, Some(4189575565));
    }

    #[tokio::test]
    async fn sqs_send_message_maps_queue_failures_to_service_unavailable() {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .respond_with(ResponseTemplate::new(503).set_body_json(json!({
                "__type": "ServiceUnavailable",
                "message": "temporarily unavailable"
            })))
            .expect(1)
            .mount(&server)
            .await;
        let queue = sqs_queue(
            &server,
            "https://sqs.us-east-2.amazonaws.com/123/reviews.fifo",
        );
        let (payload, requested) = requested_payload();

        let error = queue
            .enqueue("00000000-0000-4000-8000-000000000001", payload, &requested)
            .await
            .unwrap_err();

        assert!(matches!(error, AppError::DeploymentReviewQueueUnavailable));
        assert_eq!(
            error.status(),
            lambda_http::http::StatusCode::SERVICE_UNAVAILABLE
        );
    }
}
