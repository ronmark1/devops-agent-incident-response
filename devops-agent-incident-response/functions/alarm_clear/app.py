"""
Triggered by EventBridge on 'CloudWatch Alarm State Change' -> OK.
Resolves the wait-for-clear task token so the state machine can close the ticket
and post the resolution to Glip. Terminal step of the workflow.
"""
import os

import boto3

ddb = boto3.client("dynamodb")
sfn = boto3.client("stepfunctions")
TABLE = os.environ["APPROVALS_TABLE"]


def handler(event, _context):
    detail = event.get("detail", {})
    alarm_name = detail.get("alarmName", "")
    new_state = detail.get("state", {}).get("value", "")
    if new_state != "OK" or not alarm_name:
        return {"ignored": True}

    key = {"pk": {"S": f"CLEAR#{alarm_name}"}}
    item = ddb.get_item(TableName=TABLE, Key=key).get("Item")
    if not item:
        print({"noClearWatch": alarm_name})
        return {"noWatch": True}

    try:
        sfn.send_task_success(taskToken=item["taskToken"]["S"], output="{\"cleared\": true}")
    except sfn.exceptions.TaskTimedOut:
        pass
    finally:
        ddb.delete_item(TableName=TABLE, Key=key)

    print({"clearedResolved": alarm_name})
    return {"cleared": alarm_name}
