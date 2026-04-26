#!/usr/bin/env bash
# bootstrap_skret.sh -- initialize skret namespaces for all 7 credentialed MCPs.
#
# Run once per environment. Generates MCP_DCR_SERVER_SECRET (32-byte hex) per
# server. Other dynamic creds (provider API keys, OAuth client secrets, bot
# tokens, phone numbers) require user input via interactive `skret set`.
#
# Auth: relies on `~/.aws/credentials` boto3 chain. Region: ap-southeast-1.
set -euo pipefail

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
  ns="/${s}/prod"
  echo "[bootstrap] $ns"
  if skret get -e prod --path="$ns/MCP_DCR_SERVER_SECRET" >/dev/null 2>&1; then
    echo "  -> MCP_DCR_SERVER_SECRET exists, skip"
  else
    secret=$(openssl rand -hex 32)
    skret set -e prod --path="$ns/MCP_DCR_SERVER_SECRET" --value="$secret"
    echo "  -> generated MCP_DCR_SERVER_SECRET"
  fi
done

echo "[bootstrap] Done. Set remaining dynamic creds via 'skret set' interactively:"
echo "  skret set -e prod --path=/<server>/prod/<KEY>"
