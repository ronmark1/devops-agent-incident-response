"""
API Gateway (HTTP API) handler for the Glip Approve / Reject links.
Validates the HMAC signature, resolves the Step Functions task token stored by
request_approval, and sends the human decision back into the state machine.
"""
import hashlib
import hmac
import json
import os

import boto3

ddb = boto3.client("dynamodb")
sfn = boto3.client("stepfunctions")
TABLE = os.environ["APPROVALS_TABLE"]
SIGNING_KEY = os.environ["APPROVAL_SIGNING_KEY"].encode("utf-8")


def _sign(incident_id, decision):
    return hmac.new(SIGNING_KEY, f"{incident_id}:{decision}".encode("utf-8"),
                    hashlib.sha256).hexdigest()


def _html(status_code, title, body):
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "text/html"},
        "body": f"<html><body style='font-family:sans-serif;padding:40px'>"
                f"<h2>{title}</h2><p>{body}</p></body></html>",
    }


def handler(event, _context):
    params = event.get("queryStringParameters") or {}
    inc = params.get("incident", "")
    decision = params.get("decision", "")
    sig = params.get("sig", "")

    if decision not in ("approve", "reject") or not inc:
        return _html(400, "Invalid request", "Missing or bad parameters.")
    if not hmac.compare_digest(sig, _sign(inc, decision)):
        return _html(403, "Signature invalid", "This approval link could not be verified.")

    item = ddb.get_item(TableName=TABLE, Key={"pk": {"S": f"APPROVAL#{inc}"}}).get("Item")
    if not item:
        return _html(404, "Not found", f"No pending approval for {inc} (already actioned?).")

    token = item["taskToken"]["S"]
    approver = (event.get("requestContext", {}).get("http", {}).get("sourceIp")
                or "glip-approver")
    payload = json.dumps({"decision": decision, "approver": approver})

    try:
        sfn.send_task_success(taskToken=token, output=payload)
    except sfn.exceptions.TaskTimedOut:
        return _html(410, "Expired", "This approval has already been resolved or timed out.")
    finally:
        ddb.delete_item(TableName=TABLE, Key={"pk": {"S": f"APPROVAL#{inc}"}})

    verb = "approved — remediation will run" if decision == "approve" else "rejected — manual handling"
    return _html(200, f"{inc} {decision}d", f"Recorded. The incident was {verb}. You can close this tab.")
