"""
Post to RingCentral Glip. Phase-driven so one function covers every notification:
  - "findings"  : incident summary + root cause + proposed mitigation
  - "resolved"  : alarm cleared / ticket closed
  - "rejected"  : approval declined -> manual mitigation guidance
"""
from helpers import config, glip_post_text


def _findings_text(event):
    a, f, inc = event["alarm"], event["findings"], event["incidentId"]
    m = f["mitigation"]
    manual = "\n".join(f"  - {s}" for s in m.get("manualSteps", [])) or "  - none provided"
    return (
        f"**Incident {inc}** — Freshservice #{event.get('ticketId', '?')}\n"
        f"**Alarm:** {a['alarmName']}  ({a['accountId']}/{a['region']})\n"
        f"**State reason:** {a['reason']}\n\n"
        f"**AWS DevOps Agent — Summary**\n{f['summary']}\n\n"
        f"**Root cause** (confidence: {f.get('confidence','n/a')}):\n{f['rootCause']}\n\n"
        f"**Recommended mitigation** (risk: {m.get('risk','unknown')}):\n{m['plan']}\n"
        f"Runbook: `{m.get('runbookName') or 'n/a'}`\n\n"
        f"**Manual steps if not auto-remediating:**\n{manual}"
    )


def handler(event, _context):
    cfg = config()
    phase = event.get("phase", "findings")
    inc = event["incidentId"]

    if phase == "findings":
        title = f"🔎 {inc} investigated by AWS DevOps Agent"
        text = _findings_text(event)
    elif phase == "resolved":
        title = f"✅ {inc} resolved — alarm cleared"
        text = (f"Alarm **{event['alarm']['alarmName']}** returned to OK. "
                f"Freshservice #{event.get('ticketId','?')} closed.")
    elif phase == "rejected":
        m = event["findings"]["mitigation"]
        manual = "\n".join(f"  - {s}" for s in m.get("manualSteps", [])) or "  - see DevOps Agent console"
        title = f"⛔ {inc} — automated mitigation rejected"
        text = (f"An approver declined the recommended fix. Handle manually:\n{manual}\n\n"
                f"Freshservice #{event.get('ticketId','?')} remains open.")
    else:
        title, text = f"{inc} update", event.get("message", "")

    status, body = glip_post_text(cfg["glipWebhookUrl"], title, text)
    print({"glipStatus": status, "phase": phase})
    return event
