"""
Retrieve the AWS DevOps Agent investigation result (root cause + mitigation plan).

The Agent produces a *hypothesis*, not an applied fix, so this pulls that
hypothesis for the Glip message + approval gate. It calls the configurable
investigation-retrieval endpoint; if the investigation is not yet complete it
returns status='PENDING' so the state machine can wait and retry.
"""
import json
import os
import urllib.error
import urllib.request

from helpers import config, _maybe_json


class InvestigationPending(Exception):
    """Raised while the DevOps Agent investigation is still running (Step Functions retries)."""


def _get(url, api_key):
    req = urllib.request.Request(url, method="GET")
    req.add_header("Authorization", f"Bearer {api_key}")
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, _maybe_json(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8") if e.fp else ""
        return e.code, _maybe_json(raw)


def _normalise(raw):
    """Map the agent response to a stable shape the rest of the flow relies on."""
    if not isinstance(raw, dict):
        raw = {}
    return {
        "status": raw.get("status", "COMPLETED"),
        "summary": raw.get("summary", "No summary returned by DevOps Agent."),
        "rootCause": raw.get("rootCause", raw.get("root_cause", "Root cause not determined.")),
        "confidence": raw.get("confidence", "n/a"),
        "mitigation": {
            # runbookName lets the Agent pick which SSM runbook to run
            "runbookName": (raw.get("mitigation", {}) or {}).get("runbookName", ""),
            "runbookParameters": (raw.get("mitigation", {}) or {}).get("runbookParameters", {}),
            "plan": (raw.get("mitigation", {}) or {}).get("plan", "See DevOps Agent console."),
            "manualSteps": (raw.get("mitigation", {}) or {}).get("manualSteps", []),
            "risk": (raw.get("mitigation", {}) or {}).get("risk", "unknown"),
        },
        "investigationUrl": raw.get("investigationUrl", ""),
    }


def handler(event, _context):
    cfg = config()
    inv_id = event.get("investigationId", "")
    api_base = cfg.get("devopsAgentApiBase", "").rstrip("/")

    if not (inv_id and api_base):
        # Endpoint not configured: fall back to a safe, explicit placeholder so
        # the workflow still exercises the human-approval path.
        findings = _normalise(
            {
                "status": "COMPLETED",
                "summary": "DevOps Agent investigation reference unavailable; "
                           "review the investigation in the DevOps Agent console.",
                "mitigation": {"runbookName": os.environ.get("DEFAULT_RUNBOOK_NAME", "")},
            }
        )
        return {**event, "findings": findings}

    status, body = _get(f"{api_base}/investigations/{inv_id}", cfg["devopsAgentApiKey"])
    print(json.dumps({"fetchFindingsStatus": status}))
    findings = _normalise(body)
    if findings["status"] in ("PENDING", "IN_PROGRESS", "RUNNING"):
        raise InvestigationPending(f"Investigation {inv_id} still running")
    if not findings["mitigation"]["runbookName"]:
        findings["mitigation"]["runbookName"] = os.environ.get("DEFAULT_RUNBOOK_NAME", "")
    return {**event, "findings": findings}
