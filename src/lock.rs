use std::{
    env,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use aws_sdk_dynamodb::{types::AttributeValue, Client as DynamoDbClient};
use sha2::{Digest, Sha256};
use tokio::time::sleep;
use uuid::Uuid;

use crate::{
    config::EnvironmentName,
    error::AppError,
    github::{Repository, RunId},
};

const LOCK_TABLE_ENV: &str = "DEPLOYMENT_REVIEW_LOCK_TABLE";
const LOCK_LEASE_SECONDS: u64 = 90;
const LOCK_MAX_WAIT: Duration = Duration::from_secs(25);
const LOCK_INITIAL_BACKOFF_MS: u64 = 100;
const LOCK_MAX_BACKOFF_MS: u64 = 1_000;
const LOCK_MAX_JITTER_MS: u64 = 250;

#[derive(Clone)]
pub struct DeploymentReviewLock {
    backend: DeploymentReviewLockBackend,
}

#[derive(Clone)]
enum DeploymentReviewLockBackend {
    DynamoDb {
        client: DynamoDbClient,
        table_name: String,
    },
    #[cfg(test)]
    InMemory {
        locks: std::sync::Arc<
            tokio::sync::Mutex<
                std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>,
            >,
        >,
    },
}

pub struct DeploymentReviewLockGuard {
    backend: DeploymentReviewLockGuardBackend,
}

enum DeploymentReviewLockGuardBackend {
    DynamoDb {
        client: DynamoDbClient,
        table_name: String,
        lock_key: String,
        owner: String,
    },
    #[cfg(test)]
    InMemory(tokio::sync::OwnedMutexGuard<()>),
}

impl DeploymentReviewLock {
    pub fn from_env(client: DynamoDbClient) -> Result<Self, AppError> {
        let table_name = env::var(LOCK_TABLE_ENV)
            .map_err(|_| AppError::DeploymentReviewLockNotConfigured)?
            .trim()
            .to_string();
        if table_name.is_empty() {
            return Err(AppError::DeploymentReviewLockNotConfigured);
        }

        Ok(Self {
            backend: DeploymentReviewLockBackend::DynamoDb { client, table_name },
        })
    }

    #[cfg(test)]
    pub fn in_memory() -> Self {
        Self {
            backend: DeploymentReviewLockBackend::InMemory {
                locks: std::sync::Arc::default(),
            },
        }
    }

    pub async fn acquire(
        &self,
        repository: &Repository,
        run_id: RunId,
        environment: &EnvironmentName,
    ) -> Result<DeploymentReviewLockGuard, AppError> {
        let lock_key = deployment_review_lock_key(repository, run_id, environment);

        match &self.backend {
            DeploymentReviewLockBackend::DynamoDb { client, table_name } => {
                acquire_dynamodb_lock(client, table_name, lock_key).await
            }
            #[cfg(test)]
            DeploymentReviewLockBackend::InMemory { locks } => {
                let lock = {
                    let mut locks = locks.lock().await;
                    locks
                        .entry(lock_key)
                        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
                        .clone()
                };
                let guard = tokio::time::timeout(LOCK_MAX_WAIT, lock.lock_owned())
                    .await
                    .map_err(|_| AppError::DeploymentReviewLockTimeout)?;

                Ok(DeploymentReviewLockGuard {
                    backend: DeploymentReviewLockGuardBackend::InMemory(guard),
                })
            }
        }
    }
}

impl DeploymentReviewLockGuard {
    pub async fn release(self) -> Result<(), AppError> {
        match self.backend {
            DeploymentReviewLockGuardBackend::DynamoDb {
                client,
                table_name,
                lock_key,
                owner,
            } => client
                .delete_item()
                .table_name(table_name)
                .key("lock_key", AttributeValue::S(lock_key))
                .condition_expression("#owner = :owner")
                .expression_attribute_names("#owner", "owner")
                .expression_attribute_values(":owner", AttributeValue::S(owner))
                .send()
                .await
                .map(|_| ())
                .map_err(|error| {
                    tracing::error!(?error, "failed to release deployment review lock");
                    AppError::DeploymentReviewLockFailed
                }),
            #[cfg(test)]
            DeploymentReviewLockGuardBackend::InMemory(guard) => {
                drop(guard);
                Ok(())
            }
        }
    }
}

async fn acquire_dynamodb_lock(
    client: &DynamoDbClient,
    table_name: &str,
    lock_key: String,
) -> Result<DeploymentReviewLockGuard, AppError> {
    let owner = Uuid::new_v4().to_string();
    let started = Instant::now();
    let mut attempt = 0;

    loop {
        attempt += 1;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| {
                tracing::error!(
                    ?error,
                    "failed to read system clock for deployment review lock"
                );
                AppError::DeploymentReviewLockFailed
            })?
            .as_secs();
        let expires_at = now.saturating_add(LOCK_LEASE_SECONDS);

        match client
            .put_item()
            .table_name(table_name)
            .item("lock_key", AttributeValue::S(lock_key.clone()))
            .item("owner", AttributeValue::S(owner.clone()))
            .item("expires_at", AttributeValue::N(expires_at.to_string()))
            .condition_expression("attribute_not_exists(lock_key) OR expires_at <= :now")
            .expression_attribute_values(":now", AttributeValue::N(now.to_string()))
            .send()
            .await
        {
            Ok(_) => {
                tracing::debug!(attempt, "acquired deployment review lock");
                return Ok(DeploymentReviewLockGuard {
                    backend: DeploymentReviewLockGuardBackend::DynamoDb {
                        client: client.clone(),
                        table_name: table_name.to_string(),
                        lock_key,
                        owner,
                    },
                });
            }
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|error| error.is_conditional_check_failed_exception()) =>
            {
                let elapsed = started.elapsed();
                if elapsed >= LOCK_MAX_WAIT {
                    tracing::error!(attempt, "timed out waiting for deployment review lock");
                    return Err(AppError::DeploymentReviewLockTimeout);
                }

                let delay = lock_retry_delay(attempt, &owner).min(LOCK_MAX_WAIT - elapsed);
                tracing::debug!(
                    attempt,
                    retry_delay_ms = delay.as_millis(),
                    "deployment review lock is held"
                );
                sleep(delay).await;
            }
            Err(error) => {
                tracing::error!(?error, attempt, "failed to acquire deployment review lock");
                return Err(AppError::DeploymentReviewLockFailed);
            }
        }
    }
}

fn deployment_review_lock_key(
    repository: &Repository,
    run_id: RunId,
    environment: &EnvironmentName,
) -> String {
    let repository = repository.to_string().to_ascii_lowercase();
    let environment = environment.as_str().to_ascii_lowercase();
    let mut digest = Sha256::new();
    digest.update(repository.as_bytes());
    digest.update([0]);
    digest.update(run_id.to_string().as_bytes());
    digest.update([0]);
    digest.update(environment.as_bytes());

    hex::encode(digest.finalize())
}

fn lock_retry_delay(attempt: u64, owner: &str) -> Duration {
    let exponent = attempt.saturating_sub(1).min(4) as u32;
    let base = LOCK_INITIAL_BACKOFF_MS
        .saturating_mul(1_u64 << exponent)
        .min(LOCK_MAX_BACKOFF_MS);
    let jitter_seed = owner.bytes().fold(attempt, |seed, byte| {
        seed.wrapping_mul(31).wrapping_add(u64::from(byte))
    });
    let jitter = jitter_seed % (LOCK_MAX_JITTER_MS + 1);

    Duration::from_millis(base + jitter)
}

#[cfg(test)]
mod tests {
    use super::{deployment_review_lock_key, lock_retry_delay, DeploymentReviewLock};
    use crate::{config::EnvironmentName, error::AppError, github::Repository, github::RunId};
    use aws_sdk_dynamodb::{
        config::{BehaviorVersion, Credentials, Region},
        Client as DynamoDbClient, Config as DynamoDbConfig,
    };
    use serde_json::{json, Value};
    use std::time::Duration;
    use wiremock::{matchers::header, Mock, MockServer, ResponseTemplate};

    fn dynamodb_lock(server: &MockServer) -> DeploymentReviewLock {
        let client = DynamoDbClient::from_conf(
            DynamoDbConfig::builder()
                .behavior_version(BehaviorVersion::latest())
                .region(Region::new("us-east-1"))
                .credentials_provider(Credentials::new("key", "secret", None, None, "test"))
                .endpoint_url(server.uri())
                .build(),
        );

        DeploymentReviewLock {
            backend: super::DeploymentReviewLockBackend::DynamoDb {
                client,
                table_name: "deployment-review-locks".to_string(),
            },
        }
    }

    #[test]
    fn lock_key_is_case_insensitive_for_repository_and_environment() {
        let upper_repository = Repository::try_from(String::from("Octo/Tools")).unwrap();
        let lower_repository = Repository::try_from(String::from("octo/tools")).unwrap();
        let upper_environment = EnvironmentName::try_from("Release").unwrap();
        let lower_environment = EnvironmentName::try_from("release").unwrap();
        let run_id = RunId::new(42).unwrap();

        assert_eq!(
            deployment_review_lock_key(&upper_repository, run_id, &upper_environment),
            deployment_review_lock_key(&lower_repository, run_id, &lower_environment)
        );
    }

    #[test]
    fn lock_key_separates_runs_and_environments() {
        let repository = Repository::try_from(String::from("octo/tools")).unwrap();
        let release = EnvironmentName::try_from("release").unwrap();
        let staging = EnvironmentName::try_from("staging").unwrap();
        let run_a = RunId::new(42).unwrap();
        let run_b = RunId::new(43).unwrap();

        assert_ne!(
            deployment_review_lock_key(&repository, run_a, &release),
            deployment_review_lock_key(&repository, run_b, &release)
        );
        assert_ne!(
            deployment_review_lock_key(&repository, run_a, &release),
            deployment_review_lock_key(&repository, run_a, &staging)
        );
    }

    #[test]
    fn lock_retry_delay_is_bounded_and_jittered() {
        let first = lock_retry_delay(1, "owner-a");
        let later = lock_retry_delay(20, "owner-a");

        assert!(first >= Duration::from_millis(100));
        assert!(first <= Duration::from_millis(350));
        assert!(later >= Duration::from_millis(1_000));
        assert!(later <= Duration::from_millis(1_250));
        assert_ne!(first, lock_retry_delay(1, "owner-b"));
    }

    #[tokio::test]
    async fn in_memory_lock_serializes_the_same_run_and_environment() {
        let lock = DeploymentReviewLock::in_memory();
        let repository = Repository::try_from(String::from("octo/tools")).unwrap();
        let environment = EnvironmentName::try_from("release").unwrap();
        let run_id = RunId::new(42).unwrap();
        let first = lock
            .acquire(&repository, run_id, &environment)
            .await
            .unwrap();

        let other_lock = lock.clone();
        let other_repository = repository.clone();
        let other_environment = environment.clone();
        let second = tokio::spawn(async move {
            other_lock
                .acquire(&other_repository, run_id, &other_environment)
                .await
                .unwrap()
        });

        tokio::task::yield_now().await;
        assert!(!second.is_finished());

        first.release().await.unwrap();
        second.await.unwrap().release().await.unwrap();
    }

    #[tokio::test]
    async fn dynamodb_lock_uses_an_expiring_conditional_put_and_owner_checked_delete() {
        let server = MockServer::start().await;
        Mock::given(header("x-amz-target", "DynamoDB_20120810.PutItem"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(header("x-amz-target", "DynamoDB_20120810.DeleteItem"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let lock = dynamodb_lock(&server);
        let repository = Repository::try_from(String::from("octo/tools")).unwrap();
        let environment = EnvironmentName::try_from("release").unwrap();

        let guard = lock
            .acquire(&repository, RunId::new(42).unwrap(), &environment)
            .await
            .unwrap();
        guard.release().await.unwrap();

        let requests = server.received_requests().await.unwrap();
        let put: Value = serde_json::from_slice(&requests[0].body).unwrap();
        let delete: Value = serde_json::from_slice(&requests[1].body).unwrap();
        let lock_key = put["Item"]["lock_key"]["S"].as_str().unwrap();
        let owner = put["Item"]["owner"]["S"].as_str().unwrap();
        let expires_at = put["Item"]["expires_at"]["N"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();
        let now = put["ExpressionAttributeValues"][":now"]["N"]
            .as_str()
            .unwrap()
            .parse::<u64>()
            .unwrap();

        assert_eq!(put["TableName"], "deployment-review-locks");
        assert_eq!(
            put["ConditionExpression"],
            "attribute_not_exists(lock_key) OR expires_at <= :now"
        );
        assert_eq!(lock_key.len(), 64);
        assert_eq!(expires_at - now, 90);
        assert_eq!(delete["Key"]["lock_key"]["S"], lock_key);
        assert_eq!(delete["ConditionExpression"], "#owner = :owner");
        assert_eq!(delete["ExpressionAttributeNames"]["#owner"], "owner");
        assert_eq!(delete["ExpressionAttributeValues"][":owner"]["S"], owner);
    }

    #[tokio::test]
    async fn dynamodb_lock_retries_a_contended_conditional_put() {
        let server = MockServer::start().await;
        Mock::given(header("x-amz-target", "DynamoDB_20120810.PutItem"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("x-amzn-errortype", "ConditionalCheckFailedException")
                    .set_body_json(json!({
                        "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                        "message": "The conditional request failed"
                    })),
            )
            .up_to_n_times(1)
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(header("x-amz-target", "DynamoDB_20120810.PutItem"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(header("x-amz-target", "DynamoDB_20120810.DeleteItem"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        let lock = dynamodb_lock(&server);

        let guard = lock
            .acquire(
                &Repository::try_from(String::from("octo/tools")).unwrap(),
                RunId::new(42).unwrap(),
                &EnvironmentName::try_from("release").unwrap(),
            )
            .await
            .unwrap();
        guard.release().await.unwrap();

        assert_eq!(server.received_requests().await.unwrap().len(), 3);
    }

    #[tokio::test]
    async fn dynamodb_lock_surfaces_owner_check_failures_on_release() {
        let server = MockServer::start().await;
        Mock::given(header("x-amz-target", "DynamoDB_20120810.PutItem"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
            .expect(1)
            .mount(&server)
            .await;
        Mock::given(header("x-amz-target", "DynamoDB_20120810.DeleteItem"))
            .respond_with(
                ResponseTemplate::new(400)
                    .insert_header("x-amzn-errortype", "ConditionalCheckFailedException")
                    .set_body_json(json!({
                        "__type": "com.amazonaws.dynamodb.v20120810#ConditionalCheckFailedException",
                        "message": "The conditional request failed"
                    })),
            )
            .expect(1)
            .mount(&server)
            .await;
        let lock = dynamodb_lock(&server);

        let guard = lock
            .acquire(
                &Repository::try_from(String::from("octo/tools")).unwrap(),
                RunId::new(42).unwrap(),
                &EnvironmentName::try_from("release").unwrap(),
            )
            .await
            .unwrap();

        assert!(matches!(
            guard.release().await,
            Err(AppError::DeploymentReviewLockFailed)
        ));
    }
}
