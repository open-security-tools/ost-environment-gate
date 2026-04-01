use hmac::{Hmac, Mac};
use lambda_http::Request;
use sha2::Sha256;

use crate::error::AppError;

/// Names the HMAC algorithm used for GitHub webhook signature verification.
type HmacSha256 = Hmac<Sha256>;

/// Represents the GitHub webhook event type extracted from request headers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookEvent {
    Ping,
    DeploymentProtectionRule,
    Other(String),
}

impl TryFrom<&Request> for WebhookEvent {
    type Error = AppError;

    /// Extracts the webhook event type from the incoming request headers.
    fn try_from(request: &Request) -> Result<Self, Self::Error> {
        let value = request
            .headers()
            .get("x-github-event")
            .and_then(|value| value.to_str().ok())
            .ok_or(AppError::MissingWebhookEvent)?;

        Ok(match value {
            "ping" => Self::Ping,
            "deployment_protection_rule" => Self::DeploymentProtectionRule,
            other => Self::Other(other.to_string()),
        })
    }
}

/// Wraps a parsed GitHub webhook signature header for later verification.
pub struct WebhookSignature<'a> {
    encoded: &'a str,
}

impl<'a> TryFrom<&'a Request> for WebhookSignature<'a> {
    type Error = AppError;

    /// Extracts and parses the webhook signature header from an incoming request.
    fn try_from(request: &'a Request) -> Result<Self, Self::Error> {
        let header = request
            .headers()
            .get("x-hub-signature-256")
            .and_then(|value| value.to_str().ok())
            .ok_or(AppError::InvalidGithubWebhookSignature)?;
        let encoded = header
            .strip_prefix("sha256=")
            .ok_or(AppError::InvalidGithubWebhookSignature)?;

        Ok(Self { encoded })
    }
}

impl WebhookSignature<'_> {
    /// Verifies the parsed webhook signature against the provided secret and body.
    pub fn verify(self, secret: impl AsRef<str>, body: &[u8]) -> Result<(), AppError> {
        let provided =
            hex::decode(self.encoded).map_err(|_| AppError::InvalidGithubWebhookSignature)?;

        let mut mac = HmacSha256::new_from_slice(secret.as_ref().as_bytes())
            .map_err(|_| AppError::InvalidGithubWebhookSignature)?;
        mac.update(body);
        mac.verify_slice(&provided)
            .map_err(|_| AppError::InvalidGithubWebhookSignature)
    }
}

#[cfg(test)]
mod tests {
    use super::{WebhookEvent, WebhookSignature};
    use lambda_http::{http, Body, Request};

    fn sign_payload(secret: &str, body: &[u8]) -> String {
        use hmac::Mac;

        let mut mac = super::HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
        mac.update(body);
        let signature = mac.finalize().into_bytes();
        format!("sha256={}", hex::encode(signature))
    }

    fn test_request() -> Request {
        http::Request::builder()
            .uri("https://example.com/github/webhook")
            .header("x-github-event", "deployment_protection_rule")
            .header("x-hub-signature-256", "sha256=deadbeef")
            .body(Body::Empty)
            .unwrap()
    }

    #[test]
    fn webhook_event_reads_header_from_request() {
        assert_eq!(
            WebhookEvent::try_from(&test_request()).unwrap(),
            WebhookEvent::DeploymentProtectionRule
        );
    }

    #[test]
    fn webhook_signature_accepts_valid_signature() {
        let body = br#"{"hello":"world"}"#;
        let signature = sign_payload("super-secret", body);
        let request = http::Request::builder()
            .header("x-hub-signature-256", signature)
            .body(Body::Empty)
            .unwrap();

        assert!(WebhookSignature::try_from(&request)
            .unwrap()
            .verify("super-secret", body)
            .is_ok());
    }

    #[test]
    fn webhook_signature_rejects_missing_signature() {
        let request = http::Request::builder().body(Body::Empty).unwrap();
        assert!(WebhookSignature::try_from(&request).is_err());
    }

    #[test]
    fn webhook_signature_rejects_invalid_signature() {
        assert!(WebhookSignature::try_from(&test_request())
            .unwrap()
            .verify("super-secret", b"{}")
            .is_err());
    }
}
