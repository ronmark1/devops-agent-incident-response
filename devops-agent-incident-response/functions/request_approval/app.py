"""
Human-approval gate. Invoked by Step Functions with `.waitForTaskToken`, so the
event carries a `taskToken`. This:
  1. Persists (incidentId -> taskToken) in DynamoDB.
  2. Posts a RingCentral Glip approval card with signed Approve / Reject links
     that call the API Gateway callback.
The state machine stays paused until approval_callback resolves the token.
"""
import hashlib
import hmac
import os
import time
import urllib.parse

import boto3
from helpers import config, glip_post_card

ddb = boto3.client("dynamodb")
TABLE = os.environ["APPROVALS_TABLE"]
CALLBACK_BASE = os.environ["APPROVAL_CALLBACK_URL"].rstrip("/")
SIGNING_KEY = os.environ["APPROVAL_SIGNING_KEY"].encode("utf-8")


def _sign(incident_id, decision):
    msg = f"{incident_id}:{decision}".encode("utf-8")
    return hmac.new(SIGNING_KEY, msg, hashlib.sha256).hexdigest()


def _url(incident_id, decision):
    q = urllib.parse.urlencode(
        {"incident": incident_id, "decision": decision, "sig": _sign(incident_id, decision)}
    )
    return f"{CALLBACK_BASE}/approval?{q}"


def handler(event, _context):
    cfg = config()
    inc = event["incidentId"]
    token = event["taskToken"]
    f = event["findings"]
    m = f["mitigation"]

    ddb.put_item(
        TableName=TABLE,
        Item={
            "pk": {"S": f"APPROVAL#{inc}"},
            "taskToken": {"S": token},
            "runbookName": {"S": m.get("runbookName") or ""},
            "ttl": {"N": str(int(time.time()) + 7 * 24 * 3600)},
        },
    )

    card = {
        "contentType": "application/vnd.microsoft.card.adaptive",
        "content": {
            "type": "AdaptiveCard",
            "version": "1.3",
            "body": [
                {"type": "TextBlock", "size": "Large", "weight": "Bolder",
                 "text": f"Approval needed — {inc}"},
                {"type": "TextBlock", "wrap": True,
                 "text": f"**Root cause:** {f['rootCause']}"},
                {"type": "TextBlock", "wrap": True,
                 "text": f"**Proposed fix ({m.get('risk','unknown')} risk):** {m['plan']}"},
                {"type": "TextBlock", "wrap": True, "isSubtle": True,
                 "text": f"Runbook: {m.get('runbookName') or 'n/a'} · "
                         f"Freshservice #{event.get('ticketId','?')}"},
            ],
            "actions": [
                {"type": "Action.OpenUrl", "title": "✅ Approve & remediate",
                 "url": _url(inc, "approve")},
                {"type": "Action.OpenUrl", "title": "⛔ Reject (manual)",
                 "url": _url(inc, "reject")},
            ],
            "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        },
    }
    status, _ = glip_post_card(cfg["glipWebhookUrl"], card)
    print({"approvalCardStatus": status, "incidentId": inc})
    # No return value needed; the token is resolved out-of-band by the callback.
    return {"posted": True}
