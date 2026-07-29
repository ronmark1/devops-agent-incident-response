# AWS DevOps Agent → RingCentral Glip → Freshservice — Automated Incident Response

A single self-contained AWS Lambda that turns a CloudWatch alarm into an
end-to-end, human-approved incident-response flow:

```
CloudWatch Alarm
   → SNS
   → Lambda: create Freshservice ticket + trigger DevOps Agent investigation (HMAC webhook)
        … Agent investigates autonomously …
   → EventBridge "Investigation Completed"
   → Lambda: read real root cause → post ONE Adaptive Card to RingCentral Glip
             (root cause + mitigation + Approve/Reject + console deep link)
             and add findings to the ticket
   → Approver clicks APPROVE  → Lambda runs the SSM runbook, notes + resolves the ticket
              clicks REJECT   → Lambda notes the ticket, leaves it open
```

Everything is one CloudFormation/SAM stack. The Lambda creates its own secret,
SNS topic, SSM runbook, and automation role — nothing depends on other stacks.

## Features
- **Real root cause** on the card, read live from the Agent's investigation journal.
- **Ticket dedup** — a re-firing alarm folds into the existing open ticket instead
  of spawning duplicates (window configurable, default 1 h).
- **Friendly card** — Agent markdown is prettified (headings→bold, bullets→•).
- **Console deep link** — one click to the full mitigation plan in the DevOps Agent console.
- **Single-use, expiring approvals** — each Approve/Reject link is HMAC-signed,
  works once (atomic SSM claim), and expires (default 4 h).
- **Safe remediation default** — approval runs the SSM runbook in read-only
  `Diagnose` mode. Wiring a real remediation action is a deliberate future step.

## Files
| File | Purpose |
|------|---------|
| `template.yaml` | Self-contained SAM template (all resources). |
| `functions/findings_handler/app.py` | The Lambda (stdlib + boto3 only). |
| `parameters.example.json` | Copy to `parameters.json` and fill in. |
| `deploy.sh` | Build + deploy helper. |

## Prerequisites
- AWS CLI + SAM CLI, Python 3.11+ (AWS CloudShell has all of these).
- A **DevOps Agent Space** in the target account, with an event-channel webhook
  (URL + HMAC secret). Each account needs its own.
- A **RingCentral Glip** incoming-webhook URL.
- A **Freshservice** instance: domain, API key, and the numeric `group_id` /
  `workspace_id` plus the ticket `category` you want to use.

## Deploy
```bash
cp parameters.example.json parameters.json
# edit parameters.json — fill in every REPLACE_* value
# generate a signing key:  openssl rand -hex 32   → ApprovalSigningKey

./deploy.sh devops-agent-findings          # or any stack name you like
```
The script guards against unfilled placeholders, builds `params.yaml`, deploys
non-interactively, and prints the stack outputs.

### Outputs
- `AlarmTopicArn` — point your CloudWatch alarms' actions here.
- `FindingsHandlerUrl` — the Function URL backing the Approve/Reject links.
- `MitigationRunbookName` — the SSM runbook run on approval.

## Wire up alarms
Add the topic as an alarm action:
```bash
TOPIC=$(aws cloudformation describe-stacks --stack-name devops-agent-findings \
  --query "Stacks[0].Outputs[?OutputKey=='AlarmTopicArn'].OutputValue" --output text)
aws cloudwatch put-metric-alarm --alarm-name MY_ALARM ... --alarm-actions "$TOPIC"
```

## Smoke test
```bash
TOPIC=...   # AlarmTopicArn from outputs
NAME="smoke-$(date +%H%M%S)"
aws cloudwatch put-metric-alarm --alarm-name "$NAME" --namespace AWS/Lambda \
  --metric-name Errors --statistic Sum --period 60 --evaluation-periods 1 \
  --threshold 0 --comparison-operator GreaterThanThreshold --alarm-actions "$TOPIC"
sleep 5
aws cloudwatch set-alarm-state --alarm-name "$NAME" --state-value ALARM --state-reason "smoke"
sam logs --stack-name devops-agent-findings --tail
```
Expect: `fsCreate: 201` and `triggerInvestigation: 200` immediately; a card in Glip
once the Agent completes (a few minutes). Click APPROVE → the SSM runbook runs and
the ticket resolves.

Notes:
- Use a **fresh alarm name** per test — the Agent links repeat firings of the same
  alarm within ~20 min into one investigation (no second card, by design).
- Synthetic `SetAlarmState` alarms usually produce "no mitigation needed" — that's
  correct Agent behavior. Real workload incidents produce real mitigation plans.

## Parameters
| Parameter | Notes |
|-----------|-------|
| `DevOpsAgentWebhookUrl` / `DevOpsAgentWebhookSecret` | From the account's Agent Space event channel. |
| `AgentSpaceId` | The Agent Space id (also used to filter EventBridge + build console links). |
| `GlipWebhookUrl` | RingCentral incoming webhook. |
| `FreshserviceDomain` / `FreshserviceApiKey` | Freshservice instance + key. |
| `FreshserviceGroupId` / `FreshserviceWorkspaceId` / `FreshserviceCategory` / `FreshserviceRequesterEmail` | Ticket routing/fields (verify per instance). |
| `ApprovalSigningKey` | `openssl rand -hex 32`. Signs the approval links. |
| `TicketDedupWindowSeconds` | Suppress duplicate tickets for the same alarm (default 3600). |
| `ApprovalTtlSeconds` | Approve/Reject link lifetime (default 14400 = 4 h). |

## Deploying to another account (e.g. prod)
1. Open CloudShell **in the target account** (or use a named profile); run
   `aws sts get-caller-identity` and confirm the account id.
2. Create a **separate `parameters.json`** with that account's own agent space,
   webhooks, Freshservice values, and a **fresh** `ApprovalSigningKey`. Never
   reuse another environment's secrets.
3. `./deploy.sh devops-agent-findings-prod`
4. Point that account's alarms at the new `AlarmTopicArn`.

## Production hardening (before real traffic)
- **Rotate any secrets** that were ever shared in chat/history; use fresh ones per env.
- The Function URL is `AuthType: NONE`; links are HMAC-signed, single-use, and
  expiring, so actions can't be forged — but the endpoint is public. Consider
  fronting it with API Gateway + WAF/throttling.
- Remediation runs in read-only `Diagnose` mode. Map a real action deliberately,
  behind the existing human-approval gate.
- Tighten IAM (`AutomationAssumeRole` and the handler use `Resource: '*'` in places)
  to specific ARNs.

## Security
Never commit `parameters.json` or `params.yaml` (they contain secrets) — they are
gitignored. The Lambda reads all secrets from a Secrets Manager secret the stack
creates; only the numeric/routing values are passed as plain parameters.

## Remediation actions (Stage 2)

On approval, the handler runs an **SSM Automation runbook**. It parses the Agent's
mitigation text and maps it to a **curated allow-list of AWS-managed runbooks**
(Option A — a human picks the specific action from labeled buttons; nothing runs
automatically). AWS-managed runbooks are used rather than custom logic because they
are maintained and battle-tested by AWS.

| Detected in the mitigation | Runbook that runs | Target | Notes |
|---|---|---|---|
| start a stopped EC2 (`i-...`) | `AWS-StartEC2Instance` | InstanceId | recoverable |
| reboot/restart a hung EC2 (`i-...`) | `AWS-RestartEC2Instance` | InstanceId | recoverable |
| start a stopped RDS DB | `AWS-StartRdsInstance` | DB identifier | recoverable |
| reboot an RDS DB | `AWS-RebootRdsInstance` | DB identifier | recoverable |
| restart an ECS service | stack runbook (`RestartEcsService`) | cluster/service | force new deployment |
| refresh an ASG | stack runbook (`RefreshAsg`) | ASG name | rolling refresh |
| _nothing / no mitigation_ | stack runbook (`Diagnose`) | — | read-only default |

Yes — RDS is covered: `AWS-StartRdsInstance` starts a stopped DB and
`AWS-RebootRdsInstance` reboots a DB (both AWS-managed).

**Destructive runbooks are intentionally excluded** (no `Stop`/`Terminate`/`Delete`).
Remediation is limited to recoverable actions. Adding a destructive one would be a
deliberate opt-in behind the tag guardrail.

`parse_actions` only surfaces an action button when it confidently finds BOTH an
action verb and a concrete target id, and it honors negations ("do not reboot").
When nothing is detected (synthetic test alarms, or "no mitigation warranted"), the
card shows **Diagnose only** — safe by default.

### Visibility in RingCentral and Freshservice
The action mapping is surfaced in both places, before and after approval:
- **Glip card:** a "🔧 Suggested action(s)" line plus labeled buttons, e.g.
  `✅ Approve: Start EC2 i-abc (AWS-StartEC2Instance)`.
- **Freshservice ticket:** the mitigation plan, followed by a "🔧 Suggested action(s)"
  list naming each target and the runbook that would run.
- **On approval (both):** `✅ APPROVED. Ran runbook AWS-StartEC2Instance on i-abc
  (execution ...)`. The runbook name also appears in the SSM console
  (`DocumentName`), so there is never ambiguity about which runbook executed.

### Guardrails
- `AllowedActions` — allow-list of runbook names; the callback refuses anything not on it.
- `RequireRemediationTag=true` (off by default) — a real action runs only if the
  target resource carries `RemediationTagKey=RemediationTagValue`
  (default `devops-agent-remediation=allowed`); otherwise it downgrades to Diagnose
  and notes the ticket.
- Approval links are HMAC-signed, single-use, and expiring; the signature covers the
  runbook name + target, so neither can be tampered with.

### Adding a new managed runbook
1. Add its name to `AllowedActions`.
2. Add a detection branch in `parse_actions` (verb + target pattern → runbook name).
3. If it needs specific parameters, map them in `run_runbook`.
4. Grant the matching AWS permission on `AutomationAssumeRole` in `template.yaml`.
Prefer AWS-managed runbooks; only fall back to a custom runbook branch when no
managed runbook fits (as with the ECS/ASG helpers here).

## Why SSM Automation (and when you'd reach for Kiro CLI instead)

Remediation here uses **SSM Automation runbooks**, which orchestrate **AWS API calls**
(reboot/restart/scale). This deliberately does NOT use SSM Run Command, so there is
no "managed node / SSM Agent" requirement for the API-level actions — they work on
any such resource in-account/in-Region as long as the AutomationAssumeRole has the
permission and the resource exists.

SSM Automation limitations to know:
- Only what AWS APIs can do. An in-instance fix (restart a process, clear a disk)
  would need SSM **Run Command**, which DOES require the target to be a managed node
  with a healthy SSM Agent + instance profile + network path to SSM endpoints.
- IAM per action — each action's API must be allowed on AutomationAssumeRole.
- The target must exist and be in a valid state, or the API step fails.
- Systems Manager has no resource-based policies; access is IAM-identity + tags.
- In-account/in-Region by default (cross-account/Region Automation needs extra setup).

**Kiro CLI** is a different tool for a different kind of fix — it edits *code/config
in a repo* and opens a PR (AWS's blog pattern for automated remediation). Consider it
only when the fix is a code/infra-as-code change AND your infrastructure already
lives in a Git repo with a deploy pipeline. Its limitations:
- Acts on a **repo**, not live resources — it can't reboot/restart anything; it
  proposes code changes as a reviewable PR (never writes to main directly).
- Requires a connected GitHub/GitLab repo, a **paid Kiro subscription** + API key
  (`KIRO_API_KEY`), and a CI runner (e.g. CodeBuild) for headless mode.
- **Credit-metered** — variable cost per invocation (harder to budget than SSM's
  cheap, predictable Automation steps).
- Headless CI mode is relatively new (Kiro CLI 2.0, Apr 2026) and less battle-tested.

Rule of thumb: **operational fix (reboot/restart/scale) → SSM (this pipeline).
Code/config fix in a repo → Kiro CLI + PR.** They are complementary, not
interchangeable.
