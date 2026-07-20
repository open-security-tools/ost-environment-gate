use std::collections::HashSet;

use lambda_runtime::Error;
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use crate::{
    config::Config,
    error::AppError,
    github::RequestedDeploymentProtection,
    queue::{canonical_delivery_id, deployment_review_group_id, DeploymentReviewMessage},
    rule::{self, DeploymentProtectionRuleOutcome},
};

#[derive(Debug, Deserialize)]
pub struct SqsEvent {
    #[serde(rename = "Records")]
    records: Vec<SqsRecord>,
}

#[derive(Debug, Deserialize)]
struct SqsRecord {
    #[serde(rename = "messageId")]
    message_id: String,
    body: Option<String>,
    attributes: Option<SqsAttributes>,
}

#[derive(Debug, Deserialize)]
struct SqsAttributes {
    #[serde(rename = "MessageGroupId")]
    message_group_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SqsBatchResponse {
    #[serde(rename = "batchItemFailures")]
    batch_item_failures: Vec<SqsBatchItemFailure>,
}

#[derive(Debug, Serialize)]
struct SqsBatchItemFailure {
    #[serde(rename = "itemIdentifier")]
    item_identifier: String,
}

struct DeploymentReviewGroup {
    group_id: String,
    requested: RequestedDeploymentProtection,
    messages: Vec<(String, DeploymentReviewMessage)>,
}

pub async fn handle_batch(config: Config, event: SqsEvent) -> Result<SqsBatchResponse, Error> {
    let all_message_ids = event
        .records
        .iter()
        .map(|record| record.message_id.clone())
        .collect::<Vec<_>>();
    let mut groups: Vec<DeploymentReviewGroup> = Vec::new();
    let mut failed_group_ids = HashSet::new();
    let mut failed_message_ids = Vec::new();

    for record in event.records {
        let actual_group_id = record
            .attributes
            .and_then(|attributes| attributes.message_group_id);
        let Some(body) = record.body else {
            tracing::error!(message_id = %record.message_id, "deployment review message is missing a body");
            if !mark_failed_group(
                &record.message_id,
                actual_group_id,
                &mut failed_group_ids,
                &mut failed_message_ids,
            ) {
                return Ok(failed_batch(all_message_ids));
            }
            continue;
        };
        let message: DeploymentReviewMessage = match serde_json::from_str(&body) {
            Ok(message) => message,
            Err(error) => {
                tracing::error!(?error, message_id = %record.message_id, "deployment review message is invalid");
                if !mark_failed_group(
                    &record.message_id,
                    actual_group_id,
                    &mut failed_group_ids,
                    &mut failed_message_ids,
                ) {
                    return Ok(failed_batch(all_message_ids));
                }
                continue;
            }
        };
        if canonical_delivery_id(&message.delivery_id).is_err() {
            tracing::error!(
                message_id = %record.message_id,
                delivery_id = %message.delivery_id,
                "deployment review message has an invalid delivery id"
            );
            if !mark_failed_group(
                &record.message_id,
                actual_group_id,
                &mut failed_group_ids,
                &mut failed_message_ids,
            ) {
                return Ok(failed_batch(all_message_ids));
            }
            continue;
        }
        let requested = match RequestedDeploymentProtection::parse(
            message.payload.clone(),
            &config.github_api_base,
        ) {
            Ok(requested) => requested,
            Err(error) => {
                tracing::error!(
                    message_id = %record.message_id,
                    delivery_id = %message.delivery_id,
                    code = error.code(),
                    "deployment review message failed validation"
                );
                if !mark_failed_group(
                    &record.message_id,
                    actual_group_id,
                    &mut failed_group_ids,
                    &mut failed_message_ids,
                ) {
                    return Ok(failed_batch(all_message_ids));
                }
                continue;
            }
        };
        let group_id = deployment_review_group_id(&requested);
        if actual_group_id.as_deref() != Some(group_id.as_str()) {
            tracing::error!(
                message_id = %record.message_id,
                delivery_id = %message.delivery_id,
                expected_group_id = %group_id,
                "deployment review message has an invalid FIFO group id"
            );
            if !mark_failed_group(
                &record.message_id,
                actual_group_id,
                &mut failed_group_ids,
                &mut failed_message_ids,
            ) {
                return Ok(failed_batch(all_message_ids));
            }
            continue;
        }

        if let Some(group) = groups.iter_mut().find(|group| group.group_id == group_id) {
            if !same_review_context(&group.requested, &requested) {
                tracing::error!(
                    message_id = %record.message_id,
                    delivery_id = %message.delivery_id,
                    group_id = %group_id,
                    "deployment review messages disagree on review context"
                );
                failed_group_ids.insert(group_id);
                failed_message_ids.push(record.message_id);
                continue;
            }
            group.messages.push((record.message_id, message));
        } else {
            groups.push(DeploymentReviewGroup {
                group_id,
                requested,
                messages: vec![(record.message_id, message)],
            });
        }
    }

    let mut tasks = tokio::task::JoinSet::new();
    for group in groups {
        if failed_group_ids.contains(&group.group_id) {
            failed_message_ids.extend(group.messages.into_iter().map(|(message_id, _)| message_id));
            continue;
        }
        let config = config.clone();
        tasks.spawn(async move { process_group(config, group).await });
    }
    while let Some(result) = tasks.join_next().await {
        failed_message_ids.extend(result?);
    }

    let failed_message_ids = failed_message_ids.into_iter().collect::<HashSet<_>>();
    let failed_message_ids = all_message_ids
        .into_iter()
        .filter(|message_id| failed_message_ids.contains(message_id))
        .collect();

    Ok(failed_batch(failed_message_ids))
}

async fn process_group(config: Config, group: DeploymentReviewGroup) -> Vec<String> {
    let DeploymentReviewGroup {
        group_id, messages, ..
    } = group;
    let (message_id, message) = messages
        .last()
        .expect("deployment review groups cannot be empty");
    let span = tracing::info_span!(
        "deployment_review_worker",
        message_id = %message_id,
        delivery_id = %message.delivery_id,
        group_id = %group_id,
        coalesced_messages = messages.len()
    );
    let result = async {
        let body = serde_json::to_vec(&message.payload)
            .map_err(|_| AppError::DeploymentProtectionPayloadInvalid)?;
        rule::handle_queued_deployment_protection_rule(config, &body).await
    }
    .instrument(span.clone())
    .await;

    match result {
        Ok(DeploymentProtectionRuleOutcome::Reviewed {
            repository,
            run_id,
            environment,
            decision,
        }) => {
            span.in_scope(|| {
                tracing::info!(
                    outcome = "reviewed",
                    repository = %repository,
                    run_id = *run_id,
                    environment = %environment,
                    state = %decision.state,
                    comment = %decision.comment
                );
            });
            Vec::new()
        }
        Ok(DeploymentProtectionRuleOutcome::Ignored { action }) => {
            span.in_scope(|| tracing::info!(outcome = "ignored", action = %action));
            Vec::new()
        }
        Err(error) => {
            span.in_scope(|| {
                tracing::error!(
                    outcome = "retry",
                    code = error.code(),
                    error = %error,
                    "deployment review worker failed; returning messages for retry"
                );
            });
            messages
                .into_iter()
                .map(|(message_id, _)| message_id)
                .collect()
        }
    }
}

fn mark_failed_group(
    message_id: &str,
    group_id: Option<String>,
    failed_group_ids: &mut HashSet<String>,
    failed_message_ids: &mut Vec<String>,
) -> bool {
    let Some(group_id) = group_id else {
        return false;
    };
    failed_group_ids.insert(group_id);
    failed_message_ids.push(message_id.to_string());
    true
}

fn same_review_context(
    first: &RequestedDeploymentProtection,
    second: &RequestedDeploymentProtection,
) -> bool {
    first.repository_id == second.repository_id
        && first.repository == second.repository
        && first.run_id == second.run_id
        && first
            .environment
            .as_str()
            .eq_ignore_ascii_case(second.environment.as_str())
        && first.git_ref == second.git_ref
        && first.sha == second.sha
        && first.installation_id == second.installation_id
        && first.deployment_callback_url == second.deployment_callback_url
}

fn failed_batch(message_ids: Vec<String>) -> SqsBatchResponse {
    SqsBatchResponse {
        batch_item_failures: message_ids
            .into_iter()
            .map(|item_identifier| SqsBatchItemFailure { item_identifier })
            .collect(),
    }
}
