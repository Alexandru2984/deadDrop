#!/usr/bin/env bash
#
# Deploy Dead Drop from this working tree.
#
# NOTE: this directory IS the live production checkout — systemd runs
# ./deaddrop and the server serves ./web straight off disk. This script
# regenerates the integrity manifest FIRST (so the served SHA256SUMS/SRI can
# never lag the code), then rebuilds the binary and restarts the service.
#
# It does NOT commit and does NOT push — that stays the operator's call.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "▸ regenerating integrity manifest…"
node scripts/gen-integrity.mjs
if ! git diff --quiet -- web/SHA256SUMS web/index.html web/about.html web/verify.html; then
  echo "  ⚠ integrity manifest/SRI was stale and has been updated — remember to commit:"
  git --no-pager diff --stat -- web/SHA256SUMS web/index.html web/about.html web/verify.html | sed 's/^/    /'
fi

echo "▸ building (prod flags)…"
go build -trimpath -ldflags="-s -w" -o deaddrop ./cmd/server/

echo "▸ restarting deaddrop.service…"
sudo systemctl restart deaddrop
sleep 2

echo "▸ health check…"
if ! systemctl is-active --quiet deaddrop; then
  echo "  ✗ service is not active:"
  sudo journalctl -u deaddrop -n 20 --no-pager
  exit 1
fi
code="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8100/api/config)"
echo "  local upstream: HTTP $code"
[ "$code" = "200" ] || { echo "  ✗ upstream unhealthy"; exit 1; }

echo "✓ deployed and healthy. git is NOT pushed — push yourself when ready."
