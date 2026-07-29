"""
Register the Step Functions task token that pauses the workflow until the
CloudWatch alarm returns to OK. Invoked with `.waitForTaskToken`.
Keyed by alarm name so the EventBridge-driven alarm_clear handler can resolve it.
"""
import os
import time

import boto3

ddb = boto3.client("dynamodb")
TABLE = os.environ["APPROVALS_TABLE"]


def handler(event, _context):
    alarm_name = event["alarm"]["alarmName"]
    ddb.put_item(
        TableName=TABLE,
        Item={
            "pk": {"S": f"CLEAR#{alarm_name}"},
            "taskToken": {"S": event["taskToken"]},
            "incidentId": {"S": event["incidentId"]},
            "ticketId": {"S": str(event.get("ticketId", ""))},
            "ttl": {"N": str(int(time.time()) + 24 * 3600)},
        },
    )
    print({"registeredClearWatch": alarm_name})
    return {"watching": alarm_name}
