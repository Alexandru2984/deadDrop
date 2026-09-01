#!/usr/bin/env bash
# Start the signaling server for a CI job and wait until it answers.
#
# ALLOW_LOCAL_ORIGINS is required by every browser job: without it the allowed
# WebSocket origin stays the production hostname, and the signaling upgrade
# rejects the loopback page — so no room can ever open.
set -euo pipefail

ALLOW_LOCAL_ORIGINS=1 PORT=8100 HOST=127.0.0.1 ./deaddrop > server.log 2>&1 &
echo $! > server.pid

for _ in $(seq 1 40); do
  if curl -sf http://127.0.0.1:8100/api/config > /dev/null; then
    echo "server up"
    exit 0
  fi
  sleep 0.25
done

echo "server did not become ready"
cat server.log
exit 1
