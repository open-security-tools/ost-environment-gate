# /// script
# requires-python = ">=3.12"
# dependencies = []
# ///
"""Create a GitHub App via the manifest flow and store its credentials in AWS.

The stack must already be deployed so the webhook URL exists. This script reads
the webhook URL from the CloudFormation stack, opens the browser for the user to
confirm app creation, exchanges the temporary code for credentials, writes them
to .env and the PEM file, then delegates to deploy-secrets.sh to push them to
SSM Parameter Store and Secrets Manager.

Usage:
    uv run scripts/setup-github-app.py                 # personal account
    uv run scripts/setup-github-app.py --org my-org    # organization
    ENV_FILE=.env.prod uv run scripts/setup-github-app.py
"""

from __future__ import annotations

import argparse
import http.server
import json
import os
import subprocess
import sys
import urllib.parse
import urllib.request
import webbrowser
from pathlib import Path
from typing import Any

ROOT_DIR = Path(__file__).resolve().parent.parent
SCRIPTS_DIR = ROOT_DIR / "scripts"
DEFAULT_ENV_FILE = ROOT_DIR / ".env"
APP_HOMEPAGE_URL = "https://github.com/open-security-tools/ost-environment-gate/"
APP_DESCRIPTION = "This application provides a deployment protection rule which approves deployments after a successful deployment to the release-gate environment."


class SetupError(Exception):
    """Raised when the setup process cannot continue."""


def load_env(path: Path) -> dict[str, str]:
    """Read a KEY=VALUE env file into a dict (no shell expansion)."""
    if not path.is_file():
        raise SetupError(f"env file not found: {path}")
    env: dict[str, str] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, _, value = line.partition("=")
        env[key.strip()] = value.strip()
    return env


def require_env(env: dict[str, str], key: str) -> str:
    value = env.get(key, "")
    if not value:
        raise SetupError(f"{key} is required in the env file")
    return value


def run(*args: str) -> str:
    """Run a command and return its stdout."""
    result = subprocess.run(args, capture_output=True, text=True)
    if result.returncode != 0:
        raise SetupError(f"{' '.join(args[:3])}... failed:\n{result.stderr.strip()}")
    return result.stdout.strip()


def find_free_port() -> int:
    import socket

    with socket.socket() as s:
        s.bind(("", 0))
        return s.getsockname()[1]


class _ManifestHandler(http.server.BaseHTTPRequestHandler):
    """Serves the manifest form submission page and receives the callback.

    GET /           → auto-submitting form that POSTs the manifest to GitHub
    GET /callback   → receives the redirect with the temporary code
    """

    manifest_json: str = ""
    github_url: str = ""
    code: str | None = None

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)

        if parsed.path == "/callback":
            params = urllib.parse.parse_qs(parsed.query)
            code = params.get("code", [None])[0]
            if code:
                _ManifestHandler.code = code
                self.send_response(200)
                self.send_header("content-type", "text/html")
                self.end_headers()
                self.wfile.write(
                    b"<h2>GitHub App created.</h2><p>You can close this tab.</p>"
                )
            else:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(b"missing code parameter")
            return

        manifest_escaped = (
            _ManifestHandler.manifest_json
            .replace("&", "&amp;")
            .replace('"', "&quot;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
        )
        html = (
            f'<html><body><p>Redirecting to GitHub...</p>'
            f'<form id="m" method="post" action="{_ManifestHandler.github_url}">'
            f'<input type="hidden" name="manifest" value="{manifest_escaped}">'
            f'</form><script>document.getElementById("m").submit()</script>'
            f'</body></html>'
        )
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.end_headers()
        self.wfile.write(html.encode())

    def log_message(self, format: str, *args: Any) -> None:
        pass


def wait_for_callback(port: int, manifest_json: str, github_url: str) -> str:
    """Serve the manifest form, then block until the callback arrives."""
    _ManifestHandler.manifest_json = manifest_json
    _ManifestHandler.github_url = github_url
    _ManifestHandler.code = None

    server = http.server.HTTPServer(("127.0.0.1", port), _ManifestHandler)
    # First request: serve the auto-submitting form
    server.handle_request()
    # Second request: receive the callback from GitHub
    if _ManifestHandler.code is None:
        server.handle_request()
    if _ManifestHandler.code is None:
        raise SetupError("did not receive a code from GitHub")
    return _ManifestHandler.code


def exchange_code(code: str) -> dict[str, Any]:
    """POST /app-manifests/{code}/conversions → app credentials."""
    url = f"https://api.github.com/app-manifests/{code}/conversions"
    req = urllib.request.Request(
        url,
        method="POST",
        headers={"Accept": "application/vnd.github+json"},
    )
    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        body = exc.read().decode(errors="replace")
        raise SetupError(f"code exchange failed ({exc.code}):\n{body}") from exc


def update_env_file(path: Path, updates: dict[str, str]) -> None:
    """Update or append KEY=VALUE pairs in an env file."""
    lines = path.read_text().splitlines() if path.is_file() else []
    for key, value in updates.items():
        found = False
        for i, line in enumerate(lines):
            if line.startswith(f"{key}="):
                lines[i] = f"{key}={value}"
                found = True
                break
        if not found:
            lines.append(f"{key}={value}")
    path.write_text("\n".join(lines) + "\n")


def setup(args: argparse.Namespace) -> None:
    env_path = Path(os.environ.get("ENV_FILE", DEFAULT_ENV_FILE))
    env = load_env(env_path)

    stack_name = require_env(env, "STACK_NAME")
    pem_path = Path(env.get("APP_PRIVATE_KEY_FILE", ".secrets/github-app-private-key.pem"))
    if not pem_path.is_absolute():
        pem_path = ROOT_DIR / pem_path

    print(f"Reading webhook URL from AWS stack {stack_name}...")
    webhook_url = run(
        "aws", "cloudformation", "describe-stacks",
        "--stack-name", stack_name,
        "--query", "Stacks[0].Outputs[?OutputKey==`WebhookUrl`].OutputValue",
        "--output", "text",
    )
    if not webhook_url or webhook_url == "None":
        raise SetupError(
            f"could not read WebhookUrl from stack {stack_name} — is it deployed?"
        )
    print(f"Using {webhook_url}")

    port = find_free_port()
    manifest = {
        "name": "ost-environment-gate",
        "description": APP_DESCRIPTION,
        "url": APP_HOMEPAGE_URL,
        "public": False,
        "hook_attributes": {
            "url": webhook_url,
            "active": True,
        },
        "redirect_url": f"http://localhost:{port}/callback",
        "default_permissions": {
            "actions": "read",
            "deployments": "write",
        },
        "default_events": [
            "deployment_protection_rule",
        ],
    }

    if args.org:
        github_url = f"https://github.com/organizations/{args.org}/settings/apps/new"
    else:
        github_url = "https://github.com/settings/apps/new"

    print("Creating GitHub App...")
    print(json.dumps(manifest, indent=4))
    print("Waiting for approval in browser...")
    webbrowser.open(f"http://localhost:{port}")
    code = wait_for_callback(port, json.dumps(manifest), github_url)
    
    creds = exchange_code(code)
    app_client_id = creds.get("client_id", "")
    app_slug = creds.get("slug", "")
    pem = creds.get("pem", "")
    webhook_secret = creds.get("webhook_secret", "")

    if not app_client_id or not pem or not webhook_secret:
        raise SetupError(
            f"incomplete credentials from GitHub:\n{json.dumps(creds, indent=2)}"
        )

    print(f"Created GitHub App {app_slug}")

   
    pem_path.parent.mkdir(parents=True, exist_ok=True)
    pem_path.write_text(pem)
    pem_path.chmod(0o600)
    print(f"Wrote private key to {pem_path.relative_to(ROOT_DIR)}")

    update_env_file(env_path, {
        "APP_ID": app_client_id,
        "GITHUB_WEBHOOK_SECRET": webhook_secret,
    })
    print(f"Updated APP_ID and GITHUB_WEBHOOK_SECRET in {env_path.name}")

    print("Deploying secrets to AWS...")
    subprocess.run(
        [str(SCRIPTS_DIR / "deploy-secrets.sh")],
        check=True,
        env={**os.environ, "ENV_FILE": str(env_path)},
    )

    print("Done!")
    print("Visit https://github.com/settings/apps/ost-environment-gate/installations to install the app")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--org",
        help="Create the app under a GitHub organization instead of your personal account",
    )
    args = parser.parse_args()

    try:
        setup(args)
    except SetupError as exc:
        print(f"error: {exc}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\ninterrupted", file=sys.stderr)
        sys.exit(130)


if __name__ == "__main__":
    main()
