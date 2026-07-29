"""
FindingsHandler — event-driven AWS DevOps Agent -> RingCentral Glip -> Freshservice
with a single Adaptive Card (Approve/Reject) and SSM-runbook remediation.

Adapted from a proven reference implementation. This one Lambda handles four
entry points, dispatched in lambda_handler:

  1. SNS  (CloudWatch alarm)      -> create Freshservice ticket + trigger the
                                     DevOps Agent investigation (HMAC webhook).
  2. EventBridge (aws.aidevops)   -> lifecycle: Created / Investigation Completed
                                     / Investigation Linked / Failed. On
                                     'Investigation Completed' it reads the real
                                     investigation summary and posts ONE adaptive
                                     card to Glip with Approve/Reject buttons.
  3. Function URL (GET)           -> Approve/Reject click -> on approve, run the
                                     SSM runbook; update + resolve the ticket.

Config comes from a single Secrets Manager JSON secret (INTEGRATION_SECRET_ARN)
plus a handful of env vars. Only the Python stdlib + boto3 are used.
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request

import boto3

REGION = os.environ.get("AWS_REGION", "us-east-1")
AGENT_SPACE_ID = os.environ["AGENT_SPACE_ID"]
RUNBOOK_NAME = os.environ["RUNBOOK_NAME"]
AUTOMATION_ROLE_ARN = os.environ["AUTOMATION_ROLE_ARN"]
SIGNING_KEY = os.environ["APPROVAL_SIGNING_KEY"].encode("utf-8")
APPROVAL_TTL = int(os.environ.get("APPROVAL_TTL_SECONDS", "14400"))  # default 4 hours
DEDUP_PREFIX = "/findings-handler/processed/"
DEDUP_WINDOW = int(os.environ.get("TICKET_DEDUP_WINDOW_SECONDS", "3600"))

_secret_cache = None
_callback_base = None


def callback_base():
    """This function's own Function URL, discovered at runtime (avoids a
    CloudFormation circular dependency between the function and its URL)."""
    global _callback_base
    if _callback_base is None:
        env = os.environ.get("CALLBACK_BASE_URL", "").rstrip("/")
        if env:
            _callback_base = env
        else:
            lam = boto3.client("lambda", region_name=REGION)
            url = lam.get_function_url_config(
                FunctionName=os.environ["AWS_LAMBDA_FUNCTION_NAME"])["FunctionUrl"]
            _callback_base = url.rstrip("/")
    return _callback_base


# --------------------------------------------------------------------------- #
# Config / secrets
# --------------------------------------------------------------------------- #
def cfg():
    global _secret_cache
    if _secret_cache is None:
        sm = boto3.client("secretsmanager", region_name=REGION)
        raw = sm.get_secret_value(SecretId=os.environ["INTEGRATION_SECRET_ARN"])["SecretString"]
        _secret_cache = json.loads(raw)
    return _secret_cache


# --------------------------------------------------------------------------- #
# HTTP helpers
# --------------------------------------------------------------------------- #
def _http(url, method="POST", body=None, headers=None, timeout=15):
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        req.add_header(k, v)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode("utf-8")
            try:
                return r.status, json.loads(txt)
            except Exception:
                return r.status, txt
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8") if e.fp else ""
        try:
            return e.code, json.loads(txt)
        except Exception:
            return e.code, txt
    except Exception as e:
        print("HTTP error:", e)
        return 0, str(e)


def _fs_auth():
    return {"Authorization": "Basic " + base64.b64encode(
        (cfg()["freshserviceApiKey"] + ":X").encode()).decode()}


# --------------------------------------------------------------------------- #
# Freshservice
# --------------------------------------------------------------------------- #
def fs_create_ticket(subject, description, priority=3):
    body = {
        "subject": subject,
        "description": description,
        "priority": priority,
        "status": 2,
        "source": 2,
        "email": os.environ.get("FRESHSERVICE_REQUESTER_EMAIL", "devops-agent@example.com"),
        "group_id": int(os.environ["FRESHSERVICE_GROUP_ID"]),
        "workspace_id": int(os.environ["FRESHSERVICE_WORKSPACE_ID"]),
        "category": os.environ.get("FRESHSERVICE_CATEGORY", "DevOps Support"),
        "tags": ["aws", "cloudwatch", "devops-agent", "automated"],
    }
    status, resp = _http("https://" + cfg()["freshserviceDomain"] + "/api/v2/tickets",
                         body=body, headers=_fs_auth())
    tid = ""
    if isinstance(resp, dict):
        tid = str(resp.get("ticket", {}).get("id") or resp.get("id", ""))
    print(json.dumps({"fsCreate": status, "ticketId": tid, "resp": resp if status >= 400 else "ok"}))
    return tid


def fs_note(ticket_id, html, private=False):
    if not ticket_id:
        return
    _http("https://" + cfg()["freshserviceDomain"] + "/api/v2/tickets/" + str(ticket_id) + "/notes",
          body={"body": html, "private": private}, headers=_fs_auth())


def fs_resolve(ticket_id):
    if not ticket_id:
        return
    _http("https://" + cfg()["freshserviceDomain"] + "/api/v2/tickets/" + str(ticket_id),
          method="PUT", body={"status": 4}, headers=_fs_auth())  # 4 = Resolved


def fs_ticket_status(ticket_id):
    """Return the Freshservice status int (2 Open, 3 Pending, 4 Resolved, 5 Closed), or None."""
    if not ticket_id:
        return None
    _, resp = _http("https://" + cfg()["freshserviceDomain"] + "/api/v2/tickets/" + str(ticket_id),
                    method="GET", headers=_fs_auth())
    if isinstance(resp, dict):
        return resp.get("ticket", {}).get("status")
    return None


def existing_open_ticket(alarm_name):
    """If an open ticket for this alarm exists within the dedup window, return its id; else ''."""
    ssm = boto3.client("ssm", region_name=REGION)
    try:
        tid = ssm.get_parameter(Name="/findings-handler/ticket/" + alarm_name)["Parameter"]["Value"]
        ts = int(ssm.get_parameter(Name="/findings-handler/ticket-ts/" + alarm_name)["Parameter"]["Value"])
    except Exception:
        return ""
    if time.time() - ts > DEDUP_WINDOW:
        return ""
    return tid if fs_ticket_status(tid) in (2, 3) else ""


# --------------------------------------------------------------------------- #
# RingCentral Glip
# --------------------------------------------------------------------------- #
def glip_text(text):
    return _http(cfg()["glipWebhookUrl"], body={"text": text})[0]


def glip_card(card):
    """Post an Adaptive Card. Envelope proven to render buttons over an incoming webhook."""
    return _http(cfg()["glipWebhookUrl"], body={"attachments": [card]})[0]


# --------------------------------------------------------------------------- #
# DevOps Agent webhook trigger (HMAC-SHA256, verified format)
# --------------------------------------------------------------------------- #
def trigger_investigation(alarm):
    payload = {
        "eventType": "incident",
        "action": "created",
        "priority": "HIGH",
        "incidentId": alarm["incidentId"],
        "title": "[" + alarm["alarmName"] + "] entered ALARM",
        "description": alarm.get("reason", ""),
        "timestamp": alarm.get("timestamp", ""),
        "service": alarm.get("namespace", "aws.cloudwatch"),
        "data": alarm,
    }
    body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    import datetime
    ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.") \
        + f"{datetime.datetime.now(datetime.timezone.utc).microsecond // 1000:03d}Z"
    signed = (ts + ":").encode("utf-8") + body
    sig = base64.b64encode(
        hmac.new(cfg()["devopsAgentWebhookSecret"].encode("utf-8"), signed, hashlib.sha256).digest()
    ).decode("utf-8")
    req = urllib.request.Request(cfg()["devopsAgentWebhookUrl"], data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("x-amzn-event-timestamp", ts)
    req.add_header("x-amzn-event-signature", sig)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            print(json.dumps({"triggerInvestigation": r.status, "resp": "ok"}))
    except urllib.error.HTTPError as e:
        txt = e.read().decode("utf-8") if e.fp else ""
        print(json.dumps({"triggerInvestigation": e.code, "resp": txt[:300]}))
    except Exception as e:
        print(json.dumps({"triggerInvestigation": 0, "resp": str(e)}))



# --------------------------------------------------------------------------- #
# DevOps Agent journal read (verified: list_journal_records)
# --------------------------------------------------------------------------- #
def get_investigation_summary(agent_space_id, execution_id):
    try:
        c = boto3.client("devops-agent", region_name=REGION)
        r = c.list_journal_records(agentSpaceId=agent_space_id, executionId=execution_id,
                                   recordType="investigation_summary_md", limit=1, order="DESC")
        recs = r.get("records", [])
        if recs:
            content = recs[0].get("content", "")
            if isinstance(content, dict):
                return content.get("markdown", json.dumps(content))
            return str(content)
    except Exception as e:
        print("journal read failed:", e)
    return ""


def _msg_text(content):
    """Extract concatenated text from a journal 'message' record's content."""
    if isinstance(content, str):
        try:
            content = json.loads(content)
        except Exception:
            return content
    if isinstance(content, dict):
        parts = []
        for b in content.get("content", []) if isinstance(content.get("content"), list) else []:
            if isinstance(b, dict) and b.get("type") == "text":
                parts.append(b.get("text", ""))
        return "\n".join(parts)
    return ""


def get_mitigation(agent_space_id, execution_id):
    """
    The mitigation plan is emitted by a 'propose-mitigation-*' sub-agent as the
    assistant 'message' record immediately AFTER its completion marker. Anchor on
    that marker and return the following substantial assistant message. Returns ""
    when no mitigation sub-agent ran (so callers show 'no explicit mitigation'
    rather than echoing the root cause).
    """
    try:
        c = boto3.client("devops-agent", region_name=REGION)
        r = c.list_journal_records(agentSpaceId=agent_space_id, executionId=execution_id,
                                   recordType="message", limit=100, order="ASC")
        recs = r.get("records", [])
        marker_idx = -1
        for i, rec in enumerate(recs):
            t = _msg_text(rec.get("content", "")).lower()
            if "propose-mitigation" in t and ("completed" in t or "successfully" in t):
                marker_idx = i
        if marker_idx == -1:
            return ""  # no mitigation sub-agent ran
        for rec in recs[marker_idx + 1:]:
            t = _msg_text(rec.get("content", "")).strip()
            low = t.lower()
            if len(t) >= 200 and "subagent(s) running" not in low and not low.startswith("you still have"):
                return t
    except Exception as e:
        print("mitigation read failed:", e)
    return ""


def get_mitigation_plan(agent_space_id, execution_id):
    """
    Read the mitigation EXECUTION's journal (the execution_id from a
    'Mitigation Completed' event) and return the real plan text.

    Proven extraction (ported from a working reference): scan records newest-first,
    take a substantial assistant 'message' (or tool_result) that ISN'T reasoning
    chatter (skip-list) and DOES contain action words — so we surface the actual
    plan or an explicit "no mitigation", never the "generation kicked off" hand-off.
    Logs the record types found so the real shape is verifiable on first live event.
    """
    SKIP = ["let me send guidance", "let me generate", "i will generate", "i will send",
            "the plan should be available", "sent the request to generate",
            "i found the investigation", "the investigation has completed",
            "mitigation agent is now working", "let me finalize", "let me record",
            "let me check", "let me look", "let me verify", "let me confirm",
            "i need to", "i'll start by", "i'll now", "i'll check", "scratchpad",
            "let me wait for", "let me gather", "let me analyze", "generation has been kicked off",
            "being built in the background", "subagent(s) running", "you still have"]
    ACTION = ["step 1", "step 2", "immediate", "recommend", "mitigation", "remediation",
              "action plan", "no mitigation", "no action required", "no immediate",
              "restore", "install", "attach", "enable", "disable", "stop", "start",
              "reboot", "restart", "modify", "update", "change", "raise the", "lower the",
              "configure", "scale", "increase", "decrease", "rollback", "redeploy",
              "delete", "detach", "snapshot", "threshold"]

    def blocks_text(content):
        if isinstance(content, str):
            try:
                content = json.loads(content)
            except Exception:
                return content if len(content) > 0 else ""
        parts = []
        if isinstance(content, dict):
            role = content.get("role", "")
            for b in content.get("content", []) if isinstance(content.get("content"), list) else []:
                if isinstance(b, dict):
                    if b.get("type") == "text":
                        parts.append(b.get("text", ""))
                    elif b.get("type") == "tool_result":
                        for inner in b.get("content", []) if isinstance(b.get("content"), list) else []:
                            if isinstance(inner, dict) and inner.get("type") == "text":
                                parts.append(inner.get("text", ""))
            return ("assistant" if role == "assistant" else role, "\n".join(parts))
        return ("", "")

    try:
        c = boto3.client("devops-agent", region_name=REGION)
        r = c.list_journal_records(agentSpaceId=agent_space_id, executionId=execution_id,
                                   limit=100, order="ASC")
        recs = r.get("records", [])
        types = {}
        for x in recs:
            rt = x.get("recordType", "?")
            types[rt] = types.get(rt, 0) + 1
        print(json.dumps({"mitigationExec": execution_id, "recordTypes": types}))

        # 1) structured markdown record wins if present
        for x in recs:
            if x.get("recordType") in ("mitigation_summary_md", "mitigation_plan_md",
                                       "execution_plan_md", "mitigation_summary"):
                content = x.get("content", "")
                if isinstance(content, dict):
                    content = content.get("markdown") or json.dumps(content)
                if content and str(content).strip():
                    return str(content).strip()

        # 2) newest-first assistant/tool text that passes skip-list + action-words
        for x in reversed(recs):
            rt = x.get("recordType", "")
            if rt not in ("message", "tool_summary"):
                continue
            role, text = blocks_text(x.get("content", ""))
            t = (text or "").strip()
            low = t.lower()
            if len(t) < 150:
                continue
            if any(sk in low for sk in SKIP):
                continue
            if rt == "message" and role and role != "assistant":
                continue
            if any(aw in low for aw in ACTION):
                return t
    except Exception as e:
        print("mitigation-plan read failed:", e)
    return ""


def auto_generate_mitigation(agent_space_id, task_id):
    """
    Trigger mitigation-plan generation for a completed investigation (the API
    equivalent of the console's 'Generate mitigation plan' button), via the chat
    API: create_chat -> send_message. The response stream isn't consumed; the
    request kicks off generation and a 'Mitigation Completed' event follows.
    """
    try:
        c = boto3.client("devops-agent", region_name=REGION)
        chat = c.create_chat(agentSpaceId=agent_space_id)
        chat_exec = chat.get("executionId")
        if not chat_exec:
            print("auto_generate_mitigation: no chat executionId")
            return False
        c.send_message(agentSpaceId=agent_space_id, executionId=chat_exec,
                       content="Generate mitigation plan for investigation task " + str(task_id))
        print("mitigation generation triggered for task:", task_id)
        return True
    except Exception as e:
        print("auto_generate_mitigation failed:", e)
        return False


def _seen(key):
    """Idempotency marker via SSM: returns True if already processed, else records it."""
    ssm = boto3.client("ssm", region_name=REGION)
    try:
        ssm.get_parameter(Name=DEDUP_PREFIX + key)
        return True
    except Exception:
        try:
            ssm.put_parameter(Name=DEDUP_PREFIX + key, Value="1", Type="String", Overwrite=True)
        except Exception as e:
            print("dedup put failed:", e)
        return False


def _section(md, *headings):
    """Pull one markdown section body by heading keywords (## / ###)."""
    lines = md.split("\n")
    out, capturing = [], False
    for ln in lines:
        low = ln.lower()
        is_head = ln.lstrip().startswith("#")
        if is_head and any(h in low for h in headings):
            capturing = True
            continue
        if is_head and capturing:
            break
        if capturing:
            out.append(ln)
    return "\n".join(out).strip()


def _ticket_for_alarm(alarm_name):
    ssm = boto3.client("ssm", region_name=REGION)
    try:
        return ssm.get_parameter(Name="/findings-handler/ticket/" + alarm_name)["Parameter"]["Value"]
    except Exception:
        return ""


# --------------------------------------------------------------------------- #
# Signed approve/reject URLs
# --------------------------------------------------------------------------- #
def _sign(task_id, decision, exp, action="Diagnose", target=""):
    msg = task_id + ":" + decision + ":" + action + ":" + target + ":" + str(exp)
    return hmac.new(SIGNING_KEY, msg.encode(), hashlib.sha256).hexdigest()


def _url(task_id, decision, action="Diagnose", target=""):
    exp = int(time.time()) + APPROVAL_TTL
    q = urllib.parse.urlencode({"task_id": task_id, "decision": decision,
                                "action": action, "target": target,
                                "exp": exp, "sig": _sign(task_id, decision, exp, action, target)})
    return callback_base() + "/?" + q


# Allow-list of remediation actions and the mitigation-text patterns that map to them.
ALLOWED_ACTIONS = [a.strip() for a in os.environ.get(
    "ALLOWED_ACTIONS", "Diagnose,RebootInstance,RestartEcsService,RefreshAsg").split(",") if a.strip()]
REQUIRE_REMEDIATION_TAG = os.environ.get("REQUIRE_REMEDIATION_TAG", "false").lower() == "true"
REMEDIATION_TAG_KEY = os.environ.get("REMEDIATION_TAG_KEY", "devops-agent-remediation")
REMEDIATION_TAG_VALUE = os.environ.get("REMEDIATION_TAG_VALUE", "allowed")


def parse_actions(text):
    """
    Best-effort: derive candidate (action, target, label) tuples from the Agent's
    mitigation text. Conservative — only returns an action when BOTH an action verb
    and a concrete target id are present, and no negation ('do not <verb>') is near.
    Returns [] when nothing is confidently detected (card then shows Diagnose only).
    """
    if not text:
        return []
    low = text.lower()
    out = []

    def negated(verb):
        return any(neg + " " + verb in low for neg in ("do not", "don't", "dont", "never", "should not", "shouldn't"))

    # EC2 reboot/restart instance  -> RebootInstance (needs an i-xxxx id)
    if "RebootInstance" in ALLOWED_ACTIONS and any(v in low for v in ("reboot", "restart the instance", "restart instance")) \
            and not (negated("reboot") or negated("restart")):
        for iid in re.findall(r"\bi-[0-9a-f]{8,17}\b", text):
            out.append(("RebootInstance", iid, "Reboot " + iid))

    # ECS restart/redeploy service -> RestartEcsService (needs cluster + service)
    if "RestartEcsService" in ALLOWED_ACTIONS and any(v in low for v in ("restart", "redeploy", "force new deployment")) \
            and ("ecs" in low or "service" in low) and not negated("restart"):
        cl = re.search(r"cluster[:\s]+([A-Za-z0-9\-_]+)", text, re.I)
        sv = re.search(r"service[:\s]+([A-Za-z0-9\-_]+)", text, re.I)
        if cl and sv:
            tgt = cl.group(1) + "/" + sv.group(1)
            out.append(("RestartEcsService", tgt, "Restart ECS " + sv.group(1)))

    # ASG instance refresh -> RefreshAsg (needs an ASG name)
    if "RefreshAsg" in ALLOWED_ACTIONS and any(v in low for v in ("instance refresh", "refresh the asg", "refresh asg", "auto scaling group")) \
            and not negated("refresh"):
        asg = re.search(r"(?:auto scaling group|asg)[:\s]+([A-Za-z0-9\-_]+)", text, re.I)
        if asg:
            out.append(("RefreshAsg", asg.group(1), "Refresh ASG " + asg.group(1)))

    # de-dupe, cap at 3 buttons to keep the card sane
    seen, uniq = set(), []
    for a in out:
        if a[:2] not in seen:
            seen.add(a[:2]); uniq.append(a)
    return uniq[:3]


# --------------------------------------------------------------------------- #
# The single Adaptive Card
# --------------------------------------------------------------------------- #
import re as _re


def _prettify(md):
    """Make Agent markdown friendlier for a chat card: headings->bold, bullets->•,
    strip stray #/pipes, drop redundant 'Description:' labels and internal
    'Cascades to:' cross-refs."""
    if not md:
        return md
    out = []
    for ln in md.split("\n"):
        raw = ln.rstrip()
        st = raw.lstrip()
        low = st.lower()
        # drop internal cross-reference lines (e.g. "Cascades to: sym-...")
        if low.startswith(("cascades to:", "**cascades to:", "cascade to:")):
            continue
        # strip the redundant "Description:" label (the card already has a header)
        st = _re.sub(r"^\*{0,2}description:?\*{0,2}\s*", "", st, flags=_re.IGNORECASE)
        raw = st if st != raw.lstrip() else raw
        if st.startswith("#"):
            out.append("**" + st.lstrip("#").strip() + "**")
        elif st.startswith(("- ", "* ")):
            out.append("• " + st[2:])
        elif _re.match(r"^\d+\.\s", st):
            out.append("• " + _re.sub(r"^\d+\.\s", "", st))
        elif set(st) <= set("|-: ") and "|" in st:
            continue  # markdown table separator row
        else:
            out.append(raw.replace(" | ", " — ").strip("|").strip() if raw.count("|") >= 2 else raw)
    # de-duplicate consecutive identical non-empty lines, then collapse blank runs
    deduped = []
    for ln in out:
        if ln.strip() and deduped and ln.strip() == deduped[-1].strip():
            continue
        deduped.append(ln)
    text = "\n".join(deduped)
    return _re.sub(r"\n{3,}", "\n\n", text).strip()


def _console_link(agent_space_id, task_id):
    if not (agent_space_id and task_id):
        return ""
    return "https://" + agent_space_id + ".aidevops.global.app.aws/investigation/" + task_id


def _block(heading, text):
    return [
        {"type": "TextBlock", "text": heading, "weight": "Bolder", "size": "Medium", "spacing": "Medium"},
        {"type": "TextBlock", "text": text[:1800], "wrap": True},
    ]


def post_approval_card(task_id, priority, ticket_id, summary_md, execution_id="", agent_space_id="", mitigation_override=""):
    what = _section(summary_md, "symptom", "what happened", "impact", "overview", "observation")
    root = _section(summary_md, "root cause", "finding", "cause") or "(root cause not stated)"
    if mitigation_override:
        mit = mitigation_override
    else:
        mit = _section(summary_md, "mitigation", "remediat", "recommend", "next step", "forward-looking", "action")
        if not mit and execution_id:
            mit = get_mitigation(agent_space_id, execution_id)
    if not mit or mit.strip() == root.strip():
        mit = ("The Agent's full mitigation plan is in the DevOps Agent console (link below). "
               "Approving here runs the SSM runbook in Diagnose mode.")
    what, root, mit = _prettify(what), _prettify(root), _prettify(mit)
    console_url = _console_link(agent_space_id, task_id)
    fs_domain = cfg()["freshserviceDomain"]
    ticket_url = "https://" + fs_domain + "/a/tickets/" + str(ticket_id) if ticket_id else ""

    body = [
        {"type": "TextBlock", "text": "✅ AWS DevOps Agent — Investigation Complete",
         "weight": "Bolder", "size": "Large", "wrap": True},
        {"type": "FactSet", "facts": [
            {"title": "Task ID", "value": task_id},
            {"title": "Priority", "value": priority},
            {"title": "Ticket", "value": ("#" + str(ticket_id)) if ticket_id else "n/a"},
        ]},
    ]
    if what:
        body += _block("📋 What Happened", what)
    body += _block("🔎 Root Cause", root)
    body += _block("🛠️ Proposed Mitigation", mit)
    body += [
        {"type": "TextBlock", "text": "Does the team approve running the mitigation runbook?",
         "weight": "Bolder", "spacing": "Medium", "wrap": True},
        {"type": "TextBlock", "text": "⏰ This approval link is valid for "
         + str(APPROVAL_TTL // 3600) + " hours and can be used once.",
         "isSubtle": True, "spacing": "Small", "wrap": True},
    ]

    # Option A: offer specific allow-listed action buttons parsed from the mitigation.
    # Each is a human choice; nothing auto-runs. Always include Diagnose + Reject.
    candidate = parse_actions(mit if mitigation_override else summary_md)
    approve_actions = []
    for act, tgt, label in candidate:
        approve_actions.append({"type": "Action.OpenUrl", "title": "✅ Approve: " + label,
                                "style": "positive",
                                "url": _url(task_id, "approve", act, tgt)})
    approve_actions.append({"type": "Action.OpenUrl", "title": "✅ Approve: Diagnose only",
                            "style": "positive", "url": _url(task_id, "approve", "Diagnose", "")})
    reject_action = {"type": "Action.OpenUrl", "title": "❌ REJECT", "style": "destructive",
                     "url": _url(task_id, "reject", "Diagnose", "")}

    card = {
        "type": "AdaptiveCard",
        "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
        "version": "1.3",
        "body": body,
        "actions": approve_actions + [reject_action],
    }
    if console_url:
        card["actions"].append({"type": "Action.OpenUrl", "title": "🔗 Full mitigation (console)", "url": console_url})
    if ticket_url:
        card["actions"].append({"type": "Action.OpenUrl", "title": "🎫 Open Ticket", "url": ticket_url})
    status = glip_card(card)
    print(json.dumps({"cardStatus": status, "task_id": task_id}))
    if status < 200 or status >= 300:
        glip_text(
            "**AWS DevOps Agent — Investigation Complete** (Task " + task_id + ")\n\n"
            + "**Root cause:** " + root[:800] + "\n\n"
            + "✅ APPROVE: " + _url(task_id, "approve") + "\n"
            + "❌ REJECT: " + _url(task_id, "reject")
        )

# --------------------------------------------------------------------------- #
# Remediation via the existing SSM runbook
# --------------------------------------------------------------------------- #
def run_runbook(action="Diagnose", target=""):
    params = {"AutomationAssumeRole": [AUTOMATION_ROLE_ARN], "Action": [action]}
    if action == "RebootInstance" and target:
        params["InstanceId"] = [target]
    elif action == "RestartEcsService" and "/" in target:
        cluster, service = target.split("/", 1)
        params["EcsCluster"] = [cluster]
        params["EcsService"] = [service]
    elif action == "RefreshAsg" and target:
        params["AutoScalingGroupName"] = [target]
    ssm = boto3.client("ssm", region_name=REGION)
    resp = ssm.start_automation_execution(DocumentName=RUNBOOK_NAME, Parameters=params)
    return resp["AutomationExecutionId"]


def _resource_opted_in(action, target):
    """Tag guardrail: when REQUIRE_REMEDIATION_TAG is on, only allow a real action
    if the target resource carries REMEDIATION_TAG_KEY=REMEDIATION_TAG_VALUE."""
    if not REQUIRE_REMEDIATION_TAG or action == "Diagnose":
        return True
    try:
        if action == "RebootInstance":
            ec2 = boto3.client("ec2", region_name=REGION)
            r = ec2.describe_instances(InstanceIds=[target])
            for res in r.get("Reservations", []):
                for inst in res.get("Instances", []):
                    tags = {t["Key"]: t["Value"] for t in inst.get("Tags", [])}
                    if tags.get(REMEDIATION_TAG_KEY) == REMEDIATION_TAG_VALUE:
                        return True
            return False
        if action == "RestartEcsService" and "/" in target:
            cluster, service = target.split("/", 1)
            ecs = boto3.client("ecs", region_name=REGION)
            arns = ecs.describe_services(cluster=cluster, services=[service]).get("services", [])
            for svc in arns:
                tags = {t.get("key"): t.get("value") for t in svc.get("tags", [])}
                if tags.get(REMEDIATION_TAG_KEY) == REMEDIATION_TAG_VALUE:
                    return True
            return False
        if action == "RefreshAsg":
            asg = boto3.client("autoscaling", region_name=REGION)
            groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[target]).get("AutoScalingGroups", [])
            for g in groups:
                tags = {t.get("Key"): t.get("Value") for t in g.get("Tags", [])}
                if tags.get(REMEDIATION_TAG_KEY) == REMEDIATION_TAG_VALUE:
                    return True
            return False
    except Exception as e:
        print("tag guardrail check failed (denying):", e)
        return False
    return False


# --------------------------------------------------------------------------- #
# Handler
# --------------------------------------------------------------------------- #
def lambda_handler(event, _context):
    print("event:", json.dumps(event)[:600])

    # 1) SNS CloudWatch alarm -> ticket + trigger investigation
    recs = event.get("Records", [])
    if recs and recs[0].get("EventSource") == "aws:sns":
        msg = json.loads(recs[0]["Sns"]["Message"])
        if msg.get("NewStateValue") != "ALARM":
            return {"statusCode": 200}
        alarm_name = msg.get("AlarmName", "UnknownAlarm")
        trig = msg.get("Trigger", {})
        incident_id = "INC-" + hashlib.md5((alarm_name + recs[0]["Sns"]["Timestamp"]).encode()).hexdigest()[:10].upper()
        alarm = {
            "incidentId": incident_id, "alarmName": alarm_name,
            "accountId": msg.get("AWSAccountId", ""), "region": msg.get("Region", REGION),
            "reason": msg.get("NewStateReason", ""), "timestamp": msg.get("StateChangeTime", ""),
            "namespace": trig.get("Namespace", ""), "metricName": trig.get("MetricName", ""),
        }
        desc = ("<h3>CloudWatch Alarm Triggered</h3>"
                "<p><b>Alarm:</b> " + alarm_name + "</p>"
                "<p><b>Account/Region:</b> " + alarm["accountId"] + " / " + alarm["region"] + "</p>"
                "<p><b>Reason:</b> " + alarm["reason"] + "</p>"
                "<p>🔍 AWS DevOps Agent is investigating. Findings and mitigation will be "
                "added as a note and posted to RingCentral once complete.</p>")
        existing = existing_open_ticket(alarm_name)
        if existing:
            fs_note(existing, "<p>🔁 <b>Alarm re-fired</b> at " + alarm["timestamp"]
                    + " — reason: " + alarm["reason"]
                    + ". Folded into this open ticket (no new ticket/investigation).</p>")
            print(json.dumps({"dedup": "hit", "alarm": alarm_name, "ticketId": existing}))
            return {"statusCode": 200}
        ticket_id = fs_create_ticket("🚨 " + alarm_name, desc, 3)
        if ticket_id:
            ssm = boto3.client("ssm", region_name=REGION)
            ssm.put_parameter(Name="/findings-handler/ticket/" + alarm_name,
                              Value=str(ticket_id), Type="String", Overwrite=True)
            ssm.put_parameter(Name="/findings-handler/ticket-ts/" + alarm_name,
                              Value=str(int(time.time())), Type="String", Overwrite=True)
        trigger_investigation(alarm)
        return {"statusCode": 200}

    # 3) Function URL approve/reject click
    rc = event.get("requestContext", {})
    if "http" in rc or event.get("rawQueryString") is not None or "queryStringParameters" in event:
        params = event.get("queryStringParameters") or {}
        if not params and event.get("rawQueryString"):
            params = dict(urllib.parse.parse_qsl(event["rawQueryString"]))
        task_id = params.get("task_id", "")
        decision = params.get("decision", "")
        action = params.get("action", "Diagnose") or "Diagnose"
        target = params.get("target", "")
        exp = params.get("exp", "")
        sig = params.get("sig", "")
        if decision not in ("approve", "reject") or not exp.isdigit() \
                or not hmac.compare_digest(sig, _sign(task_id, decision, exp, action, target)):
            return _page(403, "Invalid link", "This approval link could not be verified.")
        if time.time() > int(exp):
            return _page(410, "Link expired",
                         "This approval link has expired. If action is still needed, "
                         "re-open the investigation in the DevOps Agent console.")
        # single-use: atomically claim the decision (Overwrite=False = compare-and-set)
        ssm = boto3.client("ssm", region_name=REGION)
        try:
            ssm.put_parameter(Name="/findings-handler/decided/" + task_id,
                              Value=decision + ":" + action, Type="String", Overwrite=False)
        except ssm.exceptions.ParameterAlreadyExists:
            try:
                prior = ssm.get_parameter(Name="/findings-handler/decided/" + task_id)["Parameter"]["Value"]
            except Exception:
                prior = "already handled"
            return _page(409, "Already actioned",
                         "This investigation was already <b>" + prior + "</b>. No further action was taken.")
        tkey = "/findings-handler/task-ticket/" + task_id
        try:
            ticket_id = ssm.get_parameter(Name=tkey)["Parameter"]["Value"]
        except Exception:
            ticket_id = ""
        if decision == "reject":
            glip_text("❌ **Mitigation REJECTED** for task " + task_id + ". No changes made.")
            fs_note(ticket_id, "<p>❌ <b>Mitigation rejected</b> by approver. Manual handling required.</p>")
            return _page(200, "Rejected", "No changes will be made. You can close this tab.")
        # approve — validate action against the allow-list
        if action not in ALLOWED_ACTIONS:
            return _page(400, "Action not allowed",
                         "The action '" + action + "' is not in the allow-list. No action taken.")
        # tag guardrail — only act on opted-in resources when enabled
        if not _resource_opted_in(action, target):
            fs_note(ticket_id, "<p>⚠️ <b>Action blocked by tag guardrail.</b> Target '" + target
                    + "' is not tagged " + REMEDIATION_TAG_KEY + "=" + REMEDIATION_TAG_VALUE
                    + ". Ran Diagnose instead.</p>")
            action, target = "Diagnose", ""
        try:
            exec_id = run_runbook(action, target)
            tgt_txt = (" on " + target) if target else ""
            glip_text("✅ **APPROVED** for task " + task_id + ". Running **" + action + "**" + tgt_txt
                      + " via `" + RUNBOOK_NAME + "` (execution " + exec_id + ").")
            fs_note(ticket_id, "<p>✅ <b>Approved.</b> Started SSM runbook " + RUNBOOK_NAME
                    + " with action <b>" + action + "</b>" + tgt_txt.replace("<", "&lt;")
                    + " (execution " + exec_id + ").</p>")
            fs_resolve(ticket_id)
            return _page(200, "Approved",
                         "Started " + action + tgt_txt + " (execution " + exec_id + "). You can close this tab.")
        except Exception as e:
            print("runbook start failed:", e)
            return _page(500, "Error starting runbook", str(e))

    # 2) EventBridge aws.aidevops lifecycle
    detail_type = event.get("detail-type", "")
    detail = event.get("detail", {})
    meta = detail.get("metadata", {})
    data = detail.get("data", {})
    agent_space_id = meta.get("agent_space_id", AGENT_SPACE_ID)
    task_id = meta.get("task_id", "")
    execution_id = meta.get("execution_id", "")
    priority = data.get("priority", "N/A")

    if "Investigation Completed" in detail_type:
        if _seen(task_id + "-completed"):
            return {"statusCode": 200}
        summary = get_investigation_summary(agent_space_id, execution_id)
        if not summary:
            # can't build a card without root cause; still trigger mitigation so the
            # Mitigation Completed branch can post something with the console link.
            auto_generate_mitigation(agent_space_id, task_id)
            return {"statusCode": 200}
        # find the linked ticket via the summary's alarm name
        ticket_id = ""
        m = re.search(r"alarm '([^']+)'", summary) or re.search(r"alarm ([A-Za-z0-9\-_]+)", summary)
        if m:
            ticket_id = _ticket_for_alarm(m.group(1))
        ssm = boto3.client("ssm", region_name=REGION)
        if ticket_id:
            ssm.put_parameter(Name="/findings-handler/task-ticket/" + task_id,
                              Value=str(ticket_id), Type="String", Overwrite=True)
            note = ("<p>🔍 <b>Investigation complete.</b> Generating mitigation plan…</p><pre>"
                    + summary[:6000].replace("<", "&lt;") + "</pre>")
            fs_note(ticket_id, note)
        # stash root-cause summary + priority for the single card built at Mitigation Completed
        try:
            ssm.put_parameter(Name="/findings-handler/inv/" + task_id,
                              Value=json.dumps({"summary": summary[:3500], "priority": priority}),
                              Type="String", Overwrite=True)
        except Exception as e:
            print("stash inv failed:", e)
        # kick off mitigation generation → a single card posts on 'Mitigation Completed'
        auto_generate_mitigation(agent_space_id, task_id)
        return {"statusCode": 200}

    if "Mitigation Completed" in detail_type:
        if _seen(task_id + "-mitigated"):
            return {"statusCode": 200}
        plan = get_mitigation_plan(agent_space_id, execution_id)
        ssm = boto3.client("ssm", region_name=REGION)
        # recover the stashed root-cause summary + priority + ticket
        summary, prio = "", priority
        try:
            blob = json.loads(ssm.get_parameter(
                Name="/findings-handler/inv/" + task_id)["Parameter"]["Value"])
            summary = blob.get("summary", "")
            prio = blob.get("priority", priority)
        except Exception:
            pass
        ticket_id = ""
        try:
            ticket_id = ssm.get_parameter(
                Name="/findings-handler/task-ticket/" + task_id)["Parameter"]["Value"]
        except Exception:
            ticket_id = ""
        # ONE consolidated card: root cause + real mitigation + Approve/Reject
        post_approval_card(task_id, prio, ticket_id, summary,
                           agent_space_id=agent_space_id, mitigation_override=plan)
        # ticket note with the plan
        if ticket_id and plan:
            console = _console_link(agent_space_id, task_id)
            note = ("<p>🛠️ <b>Mitigation plan (from DevOps Agent):</b></p><pre>"
                    + plan[:6000].replace("<", "&lt;") + "</pre>")
            if console:
                note += ('<p>🔗 <a href="' + console + '">Full plan in console</a></p>')
            fs_note(ticket_id, note)
        return {"statusCode": 200}

    if "Mitigation Failed" in detail_type or "Mitigation Timed Out" in detail_type:
        # still post exactly one card (root cause + console link) so the team isn't left silent
        if _seen(task_id + "-mitigated"):
            return {"statusCode": 200}
        ssm = boto3.client("ssm", region_name=REGION)
        summary, prio, ticket_id = "", priority, ""
        try:
            blob = json.loads(ssm.get_parameter(
                Name="/findings-handler/inv/" + task_id)["Parameter"]["Value"])
            summary, prio = blob.get("summary", ""), blob.get("priority", priority)
        except Exception:
            pass
        try:
            ticket_id = ssm.get_parameter(
                Name="/findings-handler/task-ticket/" + task_id)["Parameter"]["Value"]
        except Exception:
            ticket_id = ""
        post_approval_card(task_id, prio, ticket_id, summary, agent_space_id=agent_space_id)
        return {"statusCode": 200}

    if "Failed" in detail_type or "Timed Out" in detail_type:
        glip_text("❌ AWS DevOps Agent — " + detail_type + " (task " + task_id + ").")
        return {"statusCode": 200}

    # Created / In Progress / Linked -> no card (linked re-fires fold into parent)
    print("lifecycle noted:", detail_type)
    return {"statusCode": 200}


def _page(code, title, body):
    return {"statusCode": code, "headers": {"Content-Type": "text/html"},
            "body": "<html><body style='font-family:sans-serif;padding:40px'><h2>" + title
                    + "</h2><p>" + body + "</p></body></html>"}
