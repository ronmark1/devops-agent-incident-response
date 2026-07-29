"""
Shared helpers for the DevOps Agent incident-response workflow.

Only the Python standard library + boto3 (present in the Lambda runtime) are used,
so no `pip install` / build step is required for these functions.
"""
import base64
import hashlib
import hmac
import json
import os
import time
import urllib.error
import urllib.request

import boto3

_secrets_cache = {}
_sm = boto3.client("secretsmanager")


# --------------------------------------------------------------------------- #
# Secrets Manager
# --------------------------------------------------------------------------- #
def get_secret(secret_arn):
    """Return a parsed JSON secret, cached for the life of the execution env."""
    if secret_arn in _secrets_cache:
        return _secrets_cache[secret_arn]
    resp = _sm.get_secret_value(SecretId=secret_arn)
    value = json.loads(resp["SecretString"])
    _secrets_cache[secret_arn] = value
    return value


def config():
    """Load the single integration secret referenced by INTEGRATION_SECRET_ARN."""
    return get_secret(os.environ["INTEGRATION_SECRET_ARN"])


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #
def http_post(url, body, headers=None, timeout=15):
    """POST `body` (dict) as JSON. Returns (status_code, parsed_or_text)."""
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8")
            return r.status, _maybe_json(raw)
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        return e.code, _maybe_json(raw)


def http_put(url, body, headers=None, timeout=15):
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="PUT")
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, _maybe_json(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        return e.code, _maybe_json(raw)


def _maybe_json(text):
    try:
        return json.loads(text)
    except Exception:
        return text


# --------------------------------------------------------------------------- #
# DevOps Agent webhook signing (HMAC-SHA256)
# --------------------------------------------------------------------------- #
def post_signed_webhook(url, secret, payload):
    """
    POST a JSON payload to the AWS DevOps Agent webhook with an HMAC-SHA256
    signature over the raw body, matching the Agent Space webhook contract.
    """
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    timestamp = str(int(time.time()))
    signed_content = f"{timestamp}.".encode("utf-8") + body
    signature = hmac.new(secret.encode("utf-8"), signed_content, hashlib.sha256).hexdigest()

    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-Amz-Devops-Agent-Timestamp", timestamp)
    req.add_header("X-Amz-Devops-Agent-Signature", f"sha256={signature}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, _maybe_json(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        return e.code, _maybe_json(raw)


# --------------------------------------------------------------------------- #
# Freshservice
# --------------------------------------------------------------------------- #
def fs_auth_header(api_key):
    token = base64.b64encode(f"{api_key}:X".encode("utf-8")).decode("utf-8")
    return {"Authorization": f"Basic {token}"}


def freshservice_create_ticket(domain, api_key, subject, description, priority=2, urgency=2):
    url = f"https://{domain}/api/v2/tickets"
    body = {
        "subject": subject,
        "description": description,
        "priority": priority,   # 1 Low 2 Medium 3 High 4 Urgent
        "urgency": urgency,
        "status": 2,            # Open
        "source": 2,            # Portal / integration
        "email": os.environ.get("FRESHSERVICE_REQUESTER_EMAIL", "aws-devops-agent@example.com"),
        "tags": ["aws", "cloudwatch", "devops-agent", "automated"],
    }
    return http_post(url, body, headers=fs_auth_header(api_key))


def freshservice_update_ticket(domain, api_key, ticket_id, note=None, status=None):
    if note is not None:
        url = f"https://{domain}/api/v2/tickets/{ticket_id}/notes"
        return http_post(url, {"body": note, "private": False}, headers=fs_auth_header(api_key))
    url = f"https://{domain}/api/v2/tickets/{ticket_id}"
    return http_put(url, {"status": status}, headers=fs_auth_header(api_key))


# --------------------------------------------------------------------------- #
# RingCentral Glip (incoming webhook + adaptive cards)
# --------------------------------------------------------------------------- #
def glip_post_text(webhook_url, title, text):
    """Simple Glip message via incoming webhook."""
    return http_post(webhook_url, {"title": title, "activity": "AWS DevOps Agent", "text": text})


def glip_post_card(webhook_url, card):
    """Post an adaptive card (attachments) via Glip incoming webhook."""
    return http_post(webhook_url, {"attachments": [card]})
