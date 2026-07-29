"""
Update Freshservice, phase-driven:
  - "findings"    : add DevOps Agent findings as a note
  - "approved"    : note that remediation was approved + started
  - "rejected"    : note manual handling required
  - "remediated"  : note remediation outcome
  - "close"       : set status Resolved/Closed
"""
from helpers import config, freshservice_update_ticket


def handler(event, _context):
    cfg = config()
    domain = cfg["freshserviceDomain"]
    key = cfg["freshserviceApiKey"]
    tid = event["ticketId"]
    phase = event.get("phase", "findings")

    if phase == "findings":
        f = event["findings"]
        m = f["mitigation"]
        note = (f"AWS DevOps Agent findings\n\nSummary: {f['summary']}\n"
                f"Root cause: {f['rootCause']}\n"
                f"Recommended mitigation ({m.get('risk','unknown')} risk): {m['plan']}\n"
                f"Runbook: {m.get('runbookName') or 'n/a'}")
        status, _ = freshservice_update_ticket(domain, key, tid, note=note)
    elif phase == "approved":
        note = (f"Mitigation APPROVED by {event.get('approver','an approver')}. "
                f"Running SSM runbook '{event['findings']['mitigation'].get('runbookName')}'.")
        status, _ = freshservice_update_ticket(domain, key, tid, note=note)
    elif phase == "rejected":
        status, _ = freshservice_update_ticket(
            domain, key, tid,
            note=f"Mitigation REJECTED by {event.get('approver','an approver')}. Manual handling required.")
    elif phase == "remediated":
        out = event.get("remediationResult", {})
        status, _ = freshservice_update_ticket(
            domain, key, tid,
            note=f"Remediation execution {out.get('status','?')} "
                 f"(execution id {out.get('executionId','?')}).")
    elif phase == "close":
        status, _ = freshservice_update_ticket(domain, key, tid, status=4)  # 4 = Resolved
    else:
        status, _ = freshservice_update_ticket(domain, key, tid, note=event.get("message", ""))

    print({"updateTicketStatus": status, "phase": phase})
    return event
