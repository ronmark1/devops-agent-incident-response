#!/usr/bin/env bash
# Build and deploy the DevOps Agent incident-response stack to the *current*
# AWS profile/account. Re-run against a different profile/region to deploy to
# another account -- nothing in the template is account-specific.
set -euo pipefail

STACK_NAME="${STACK_NAME:-devops-agent-incident-response}"
REGION="${AWS_REGION:-us-east-1}"

# Pass parameters via a params file (see parameters.example.json).
PARAM_OVERRIDES=$(python3 - <<'PY'
import json
print(" ".join(f'{p["ParameterKey"]}={p["ParameterValue"]}'
                for p in json.load(open("parameters.json"))))
PY
)

sam build
sam deploy \
  --stack-name "$STACK_NAME" \
  --region "$REGION" \
  --capabilities CAPABILITY_IAM CAPABILITY_AUTO_EXPAND \
  --resolve-s3 \
  --no-confirm-changeset \
  --parameter-overrides $PARAM_OVERRIDES

echo
echo "Outputs:"
aws cloudformation describe-stacks --stack-name "$STACK_NAME" --region "$REGION" \
  --query "Stacks[0].Outputs" --output table
