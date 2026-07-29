"""Create the Freshservice ticket for a new incident. Returns ticketId to the state machine."""
import json

from helpers import config, freshservice_create_ticket


def handler(event, _context):
    cfg = config()
    alarm = event["alarm"]
    incident_id = event["incidentId"]

    subject = f"{incident_id}: CloudWatch alarm '{alarm['alarmName']}' in ALARM"
    description = (
        f"<b>Incident:</b> {incident_id}<br>"
        f"<b>Alarm:</b> {alarm['alarmName']}<br>"
        f"<b>Account/Region:</b> {alarm['accountId']} / {alarm['region']}<br>"
        f"<b>Metric:</b> {alarm['namespace']} / {alarm['metricName']}<br>"
        f"<b>State reason:</b> {alarm['reason']}<br>"
        f"<b>Detected:</b> {alarm['timestamp']}<br><br>"
        "Investigation by AWS DevOps Agent is in progress. Findings will follow."
    )

    status, body = freshservice_create_ticket(
        cfg["freshserviceDomain"], cfg["freshserviceApiKey"],
        subject=subject, description=description, priority=3, urgency=3,
    )
    ticket_id = ""
    if isinstance(body, dict):
        ticket_id = str(body.get("ticket", {}).get("id") or body.get("id", ""))
    print(json.dumps({"createTicketStatus": status, "ticketId": ticket_id}))

    if not ticket_id:
        raise RuntimeError(f"Freshservice ticket creation failed: {status} {body}")

    return {**event, "ticketId": ticket_id}
