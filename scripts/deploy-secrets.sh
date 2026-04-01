#!/usr/bin/env bash
#
# Sync secrets from .env into AWS SSM Parameter Store and Secrets Manager.
#
# Usage:
#   ./scripts/deploy-secrets.sh              # uses .env in project root
#   ENV_FILE=/path/to/.env ./scripts/deploy-secrets.sh
#
# Required .env variables:
#   APP_ID                      GitHub App ID or Client ID
#   APP_ID_PARAMETER            SSM parameter name (e.g. /ost/app-id)
#   APP_PRIVATE_KEY_FILE        Path to a PEM file
#   APP_PRIVATE_KEY_SECRET_NAME Secrets Manager secret name (e.g. ost/app-private-key)
#   GITHUB_WEBHOOK_SECRET       Webhook secret string
#   WEBHOOK_SECRET_PARAMETER    SSM parameter name (e.g. /ost/webhook-secret)
#
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ENV_FILE:-$ROOT_DIR/.env}"

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    exit 1
  }
}

require_var() {
  local name="$1"
  if [[ -z "${!name:-}" ]]; then
    echo "$name is required" >&2
    exit 1
  fi
}

upsert_ssm_parameter() {
  local name="$1"
  local value="$2"

  aws ssm put-parameter \
    --name "$name" \
    --type SecureString \
    --overwrite \
    --value "$value" \
    >/dev/null
}

upsert_secret_from_file() {
  local secret_name="$1"
  local file_path="$2"

  if aws secretsmanager describe-secret --secret-id "$secret_name" >/dev/null 2>&1; then
    aws secretsmanager put-secret-value \
      --secret-id "$secret_name" \
      --secret-string "file://$file_path" \
      >/dev/null
  else
    aws secretsmanager create-secret \
      --name "$secret_name" \
      --secret-string "file://$file_path" \
      >/dev/null
  fi
}

require_command aws

if [[ ! -f "$ENV_FILE" ]]; then
  echo "env file not found: $ENV_FILE" >&2
  exit 1
fi

set -a
# shellcheck disable=SC1090
source "$ENV_FILE"
set +a

require_var APP_ID
require_var APP_ID_PARAMETER
require_var APP_PRIVATE_KEY_FILE
require_var APP_PRIVATE_KEY_SECRET_NAME
require_var GITHUB_WEBHOOK_SECRET
require_var WEBHOOK_SECRET_PARAMETER

if [[ ! -f "$APP_PRIVATE_KEY_FILE" ]]; then
  echo "private key file not found: $APP_PRIVATE_KEY_FILE" >&2
  exit 1
fi

upsert_ssm_parameter "$APP_ID_PARAMETER" "$APP_ID"
upsert_ssm_parameter "$WEBHOOK_SECRET_PARAMETER" "$GITHUB_WEBHOOK_SECRET"
upsert_secret_from_file "$APP_PRIVATE_KEY_SECRET_NAME" "$APP_PRIVATE_KEY_FILE"

echo "Deployed application id, webhook secret, and private key to AWS SSM"
