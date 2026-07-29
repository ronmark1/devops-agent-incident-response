"""
Webhook Bridge (the 'Lambda (webhook bridge)' in the workflow).

Triggered by the SNS topic that CloudWatch alarms publish to. For every alarm
that transitions to ALARM it:
  1. Fires the AWS DevOps Agent investigation via HMAC-signed webhook.
  2. Starts the Step Functions incident-response state machine, which owns the
     rest of the orchestration (ticket -> Glip -> approval -> remediation).
"""
import json
import os
import uuid

import boto3
from helpers import config, post_signed_webhook

sfn = boto3.client("stepfunctions")


def _parse_alarm(record):
    msg = json.loads(record["Sns"]["Message"])
    trigger = msg.get("Trigger", {})
    return {
        "alarmName": msg.get("AlarmName", "UnknownAlarm"),
        "alarmArn": msg.get("AlarmArn", ""),
        "accountId": msg.get("AWSAccountId", ""),
        "region": msg.get("Region", os.environ.get("AWS_REGION", "")),
        "newState": msg.get("NewStateValue", ""),
        "reason": msg.get("NewStateReason", ""),
        "timestamp": msg.get("StateChangeTime", ""),
        "namespace": trigger.get("Namespace", ""),
        "metricName": trigger.get("MetricName", ""),
        "dimensions": trigger.get("Dimensions", []),
        "threshold": trigger.get("Threshold"),
    }


def handler(event, _context):
    cfg = config()
    started = []

    for record in event.get("Records", []):
        alarm = _parse_alarm(record)
        if alarm["newState"] != "ALARM":
            continue

        incident_id = f"INC-{uuid.uuid4().hex[:10].upper()}"

        # 1) Kick the DevOps Agent investigation (async; the agent will also be
        #    polled inside the state machine for the resulting hypothesis).
        agent_payload = {
            "eventType": "cloudwatch.alarm",
            "incidentId": incident_id,
            "title": f"[{alarm['alarmName']}] entered ALARM",
            "source": "aws.cloudwatch",
            "alarm": alarm,
            "callbackContext": {"incidentId": incident_id},
        }
        status, body = post_signed_webhook(
            cfg["devopsAgentWebhookUrl"], cfg["devopsAgentWebhookSecret"], agent_payload
        )
        investigation_id = ""
        if isinstance(body, dict):
            investigation_id = body.get("investigationId") or body.get("id", "")
        print(json.dumps({"devopsAgentStatus": status, "investigationId": investigation_id}))

        # 2) Start orchestration.
        sfn.start_execution(
            stateMachineArn=os.environ["STATE_MACHINE_ARN"],
            name=incident_id,
            input=json.dumps(
                {
                    "incidentId": incident_id,
                    "alarm": alarm,
                    "investigationId": investigation_id,
                }
            ),
        )
        started.append(incident_id)

    return {"started": started}
