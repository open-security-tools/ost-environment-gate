use lambda_http::http::StatusCode;
use lambda_http::{Body, Response};
use serde::Serialize;

use crate::error::AppError;

#[derive(Debug)]
pub(crate) enum AppResponse {
    Health(HealthResponse),
    StatusOnly(StatusCode),
}

impl AppResponse {
    pub(crate) fn health(service: &'static str) -> Self {
        Self::Health(HealthResponse { ok: true, service })
    }

    pub(crate) fn status(status: StatusCode) -> Self {
        Self::StatusOnly(status)
    }

    pub(crate) fn into_response(self) -> Response<Body> {
        match self {
            Self::Health(body) => json_response(StatusCode::OK, &body),
            Self::StatusOnly(status) => empty_response(status),
        }
    }
}

#[derive(Debug, Serialize)]
pub(crate) struct HealthResponse {
    ok: bool,
    service: &'static str,
}

#[derive(Debug, Serialize)]
struct ErrorResponse {
    code: &'static str,
    error: String,
}

impl AppError {
    pub(crate) fn into_response(self) -> Response<Body> {
        let status = self.status();
        let body = ErrorResponse {
            code: self.code(),
            error: self.to_string(),
        };

        json_response(status, &body)
    }
}

// GitHub only requires the webhook handler to return an appropriate HTTP status.
// We return empty bodies for successful webhook responses and rely on structured
// application logs for debugging and auditability.
fn empty_response(status: StatusCode) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .body(Body::Empty)
        .expect("failed to construct empty response")
}

fn json_response<T: Serialize>(status: StatusCode, body: &T) -> Response<Body> {
    match serde_json::to_vec(body) {
        Ok(body) => build_json_response(status, body),
        Err(_) => internal_server_error_response(),
    }
}

fn build_json_response(status: StatusCode, body: Vec<u8>) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("cache-control", "no-store")
        .header("content-type", "application/json; charset=utf-8")
        .header("x-content-type-options", "nosniff")
        .body(Body::Binary(body))
        .expect("failed to construct JSON response")
}

fn internal_server_error_response() -> Response<Body> {
    let body = ErrorResponse {
        code: "response_encoding_failed",
        error: "response encoding failed".to_string(),
    };

    let body = serde_json::to_vec(&body).unwrap_or_else(|_| {
        b"{\"code\":\"internal_server_error\",\"error\":\"internal server error\"}".to_vec()
    });

    build_json_response(StatusCode::INTERNAL_SERVER_ERROR, body)
}
