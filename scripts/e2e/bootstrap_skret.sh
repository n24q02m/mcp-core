#!/usr/bin/env bash
# bootstrap_skret.sh -- initialize skret namespaces for all 7 credentialed MCPs.
#
# Run once per environment. Generates MCP_DCR_SERVER_SECRET (32-byte hex) per
# server. Other dynamic creds (provider API keys, OAuth client secrets, bot
# tokens, phone numbers) require user input via interactive ``skret set``.
#
# Auth: relies on ``~/.aws/credentials`` boto3 chain (``aws login``).
# Region: ap-southeast-1.
#
# Uses ``aws ssm put-parameter`` directly because skret CLI's ``--path``
# override does not concat with the key argument when no .skret.yaml exists
# in the cwd: it ends up writing to ``/<KEY>`` (root) instead of
# ``/<path>/<KEY>``. Using ``aws ssm`` is unambiguous + matches the existing
# layout of the live SSM tree (verified 2026-04-26).
#
# MSYS_NO_PATHCONV=1 stops Git-Bash on Windows from rewriting absolute SSM
# paths into Windows file paths.
set -euo pipefail
export MSYS_NO_PATHCONV=1

REGION="ap-southeast-1"
SERVERS=(
  "better-notion-mcp"
  "better-email-mcp"
  "better-telegram-mcp"
  "wet-mcp"
  "mnemo-mcp"
  "better-code-review-graph"
  "imagine-mcp"
)

for s in "${SERVERS[@]}"; do
  param="/${s}/prod/MCP_DCR_SERVER_SECRET"
  echo "[bootstrap] $param"
  if aws ssm get-parameter --name "$param" --region "$REGION" >/dev/null 2>&1; then
    echo "  -> exists, skip"
  else
    secret=$(openssl rand -hex 32)
    aws ssm put-parameter \
      --name "$param" \
      --value "$secret" \
      --type SecureString \
      --region "$REGION" >/dev/null
    echo "  -> generated"
  fi
done

echo
echo "[bootstrap] Done. Populate remaining dynamic creds (interactive):"
echo "  aws ssm put-parameter --name /<server>/prod/<KEY> --value <VAL> --type SecureString --region $REGION"
echo
echo "Required dynamic creds for T2 configs:"
echo "  /better-notion-mcp/prod/NOTION_INTEGRATION_TOKEN  (paste-token T2 #6)"
echo "  /better-email-mcp/prod/GMAIL_EMAIL + GMAIL_APP_PASSWORD  (gmail T2 #7)"
echo "  /better-email-mcp/prod/OUTLOOK_EMAIL  (outlook T2 #13, interaction)"
echo "  /better-telegram-mcp/prod/TELEGRAM_BOT_TOKEN  (bot T2 #8)"
echo "  /better-telegram-mcp/prod/TELEGRAM_PHONE  (user T2 #14, interaction)"
echo "  /<wet|mnemo|crg|imagine>/prod/{JINA,GEMINI,OPENAI,COHERE,XAI}_API_KEY  (T2 #9-10, #15-16)"
