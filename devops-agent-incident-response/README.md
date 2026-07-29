# AWS DevOps Agent → RingCentral Glip → Freshservice — Automated Incident Response

Autonomous CloudWatch-alarm investigation with a **human-in-the-loop approval gate**.
When an alarm fires, AWS DevOps Agent investigates, the findings are posted to
RingCentral Glip and logged to a Freshservice ticket, an approver taps **Approve**
or **Reject** in Glip, and — only on approval — an SSM Automation runbook applies
the fix. The ticket is updated at every step and closed automatically when the
alarm clears.

## Workflow

```
CloudWatch Alarm ─▶ SNS Topic ─▶ Lambda (webhook bridge)
                                     │  HMAC-signs + calls DevOps Agent webhook
                                     ▼
                             Step Functions state machine
   ┌───────────────────────────────────────────────────────────────────────┐
   │ 1. Create Freshservice ticket                                          │
   │ 2. Fetch DevOps Agent findings (root cause + mitigation hypothesis)    │
   │ 3. Notify Glip (summary) → Update ticket                               │
   │ 4. Post Glip approval card ──⏸ waitForTaskToken                        │
   │        Approve/Reject ─▶ API Gateway ─▶ Lambda ─▶ resume state machine │
   │ 5a. APPROVED → SSM Automation runbook → update ticket + Glip           │
   │ 5b. REJECTED → Glip manual-mitigation guidance + ticket stays open     │
   │ 6. Wait for alarm → OK (EventBridge) → close ticket + Glip “resolved”  │
   └───────────────────────────────────────────────────────────────────────┘
```

### Services used
Core (as specified): **CloudWatch Alarm → SNS → Lambda → DevOps Agent → Glip →
SSM runbook → alarm cleared**, plus **Freshservice**.
Added for robustness: **Step Functions** (orchestration + the `waitForTaskToken`
human-approval pattern), **DynamoDB** (correlate an approval click back to the
paused execution), **API Gateway (HTTP API)** (Glip button callback),
**EventBridge** (detect the alarm returning to OK), **Secrets Manager** (every
webhook/key — nothing sensitive sits in plaintext template parameters),
**SQS** (SNS dead-letter safety).

## Repository layout

| Path | Purpose |
|------|---------|
| `template.yaml` | One SAM/CloudFormation template deploying every resource |
| `layer/python/helpers.py` | Shared code (secrets, signed HTTP, Freshservice, Glip) |
| `functions/webhook_bridge/` | SNS → HMAC-sign & call DevOps Agent → start state machine |
| `functions/create_ticket/` | Freshservice ticket creation |
| `functions/fetch_findings/` | Pull the DevOps Agent investigation result |
| `functions/notify_glip/` | Post findings / approval / resolution to Glip |
| `functions/update_ticket/` | Add notes / close the Freshservice ticket |
| `functions/request_approval/` | Post approval card, park the task token in DynamoDB |
| `functions/approval_callback/` | API Gateway handler for Approve/Reject links |
| `functions/wait_clear/` | Park a task token until the alarm clears |
| `functions/alarm_clear/` | EventBridge → resume execution when alarm → OK |
| `statemachine/incident_response.asl.json` | Step Functions definition |
| `runbooks/mitigation-runbook.yaml` | Standalone copy of the SSM runbook |
| `parameters.example.json` | All the values you fill in per account |
| `deploy.sh` | Build + deploy convenience wrapper |

## Prerequisites

1. **AWS DevOps Agent Space** created, with a **webhook** generated
   (*Agent Space → Capabilities → Webhooks → Add*). Save the **webhook URL** and
   **HMAC secret** — the console shows these once.
2. **RingCentral Glip incoming webhook** URL for the target team/chat.
3. **Freshservice** domain + an **API key**.
4. AWS SAM CLI + credentials for the target account.

> The webhook signature header names in `helpers.post_signed_webhook`
> (`X-Amz-Devops-Agent-Timestamp` / `X-Amz-Devops-Agent-Signature`) follow the
> HMAC-SHA256 `timestamp.body` scheme. Confirm the exact header names your Agent
> Space expects and adjust if needed — it’s the one integration point that varies.

## Deploy

```bash
cp parameters.example.json parameters.json   # then edit values
./deploy.sh
# or, without the wrapper:
sam build && sam deploy --guided --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND
```

`sam deploy` runs the CloudFormation `AWS::Serverless` transform, so this **is** a
pure CloudFormation deployment under the hood.

### Wire your alarms
Point any CloudWatch alarm’s **AlarmActions** at the `AlarmTopicArn` output:

```bash
aws cloudwatch put-metric-alarm --alarm-name my-svc-5xx ... \
  --alarm-actions <AlarmTopicArn-from-stack-output>
```

### Deploy to another AWS account
Nothing in the template is account-hardcoded. Re-run `deploy.sh` with credentials
for the other account (and a per-account `parameters.json`). To also **ingest
alarms from other accounts** into one ops pipeline, set
`AdditionalPublisherAccountIds` and point those accounts’ alarms at this topic ARN.

## Runbooks — reuse or create

* **Create (default):** `CreateDefaultRunbook=true` deploys `*-mitigation`, a
  branch-on-`Action` runbook (`Diagnose` / `RebootInstance` / `RestartEcsService`
  / `RefreshAsg`).
* **Reuse existing:** have the DevOps Agent return an existing runbook name in
  `findings.mitigation.runbookName` (with `runbookParameters` in SSM shape, e.g.
  `{"Action":["RestartEcsService"],"EcsCluster":["prod"],"EcsService":["api"]}`).
  Set `CreateDefaultRunbook=false` and provide `ExistingDefaultRunbookName` as the
  fallback. Extend `AutomationAssumeRole` with any extra permissions your runbooks need.

## Output format

Every incident produces a consistent record in three places — Glip, the Freshservice
ticket, and the Step Functions execution. The DevOps-Agent-derived section looks like:

```
Incident INC-4F9A2C7E11 — Freshservice #10432
Alarm:  prod-api-5xx-rate  (111122223333 / us-east-1)
State reason: Threshold Crossed: 3 datapoints > 5.0

AWS DevOps Agent — Summary
  Elevated 5xx on prod-api began 21:47 UTC, correlated with deployment d-8821.

Root cause (confidence: high):
  Release d-8821 shipped a config change that lowered the DB connection-pool
  ceiling below steady-state concurrency; the service exhausts connections
  under normal load and returns 5xx.

Recommended mitigation (risk: low):
  Restart the ECS service to roll back to the last healthy task definition.
  Runbook: devops-agent-incident-response-mitigation
           {"Action":["RestartEcsService"],"EcsCluster":["prod"],"EcsService":["api"]}

Manual steps if not auto-remediating:
  - Roll back ECS service 'api' to task def :47
  - Restore connection-pool max to 200 in the service config
  - Re-run the load check before closing
```

* **Root cause & mitigation plan** come straight from the Agent’s hypothesis.
* **Manual mitigation details** are always included so an approver who **rejects**
  the automated fix has an actionable fallback.

## Human-approval mechanics

The approval card’s buttons are **signed** `Action.OpenUrl` links
(`?incident=…&decision=…&sig=HMAC`). The callback verifies the HMAC before
resuming the execution, so the links can’t be forged or replayed after use. The
task token is stored in DynamoDB (TTL-expiring) and deleted once resolved. The
approval step times out after 24h and escalates via a ticket note.

## Cost & cleanup
Everything is serverless/pay-per-use (Lambda, Step Functions Standard, DynamoDB
on-demand, HTTP API). Remove with `sam delete --stack-name <name>`.

## Security notes
* All third-party credentials live in **Secrets Manager**, injected as one secret
  ARN; functions get least-privilege `GetSecretValue` on that ARN only.
* The SSM runbook runs under a dedicated assume-role scoped to the specific
  remediation APIs — tighten `Resource: '*'` to your ARNs for production.
* No fix is ever applied without an explicit human approval.
