#!/usr/bin/env bash
#
# Fail-closed deployment from a reviewed, clean working tree. The browser
# bundle is embedded in the binary, so one atomic binary replacement deploys
# server and client together. This script never edits source or generated
# integrity files and never commits or pushes.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"
CANDIDATE=""
BACKUP=""
HAD_OLD=0

cleanup() {
  [ -z "$CANDIDATE" ] || rm -f "$CANDIDATE"
  [ -z "$BACKUP" ] || rm -f "$BACKUP"
}
trap cleanup EXIT

if [ -n "$(git status --porcelain --untracked-files=normal)" ]; then
  echo "✗ refusing to deploy a dirty or untracked working tree"
  git status --short
  exit 1
fi

if systemctl is-active --quiet deaddrop-integrity.service 2>/dev/null \
    || systemctl is-enabled --quiet deaddrop-integrity.service 2>/dev/null; then
  echo "✗ obsolete deaddrop-integrity.service is still active/enabled"
  echo "  Disable it before deployment; embedded assets make it unnecessary and"
  echo "  an auto-regenerator could legitimize an unreviewed live edit."
  exit 1
fi

echo "▸ checking committed integrity manifest…"
node scripts/gen-integrity.mjs --check

echo "▸ proving the vendored code is upstream's…"
# Before anything else: a modified third-party file must never reach a build.
# This is the only check here that looks outside the repository.
node scripts/verify-vendor.mjs

echo "▸ running pre-deploy tests…"
go vet ./...
go test -race ./...
for suite in crypto lifecycle mlkem srp fingerprint config manifest callsignal property; do
  node "test/$suite.selftest.mjs"
done

echo "▸ building (prod flags)…"
CANDIDATE="$(mktemp "$ROOT/.deaddrop-build.XXXXXX")"
go build -trimpath -ldflags="-s -w" -o "$CANDIDATE" ./cmd/server/
chmod 0755 "$CANDIDATE"

echo "▸ validating production environment…"
if [ -e /etc/deaddrop.env ]; then
  if [ -r /etc/deaddrop.env ]; then
    (
      set -a
      # /etc/deaddrop.env is root-owned deployment input, not user input.
      . /etc/deaddrop.env
      set +a
      PORT="${PORT:-8100}" HOST="${HOST:-127.0.0.1}" "$CANDIDATE" check-config
    )
  else
    sudo /bin/bash -c '
      set -euo pipefail
      set -a
      . /etc/deaddrop.env
      set +a
      PORT="${PORT:-8100}" HOST="${HOST:-127.0.0.1}" "$1" check-config
    ' _ "$CANDIDATE"
  fi
else
  PORT="${PORT:-8100}" HOST="${HOST:-127.0.0.1}" "$CANDIDATE" check-config
fi

if [ -e deaddrop ]; then
  BACKUP="$(mktemp "$ROOT/.deaddrop-rollback.XXXXXX")"
  cp -p deaddrop "$BACKUP"
  HAD_OLD=1
fi
mv -f "$CANDIDATE" deaddrop
CANDIDATE=""

echo "▸ restarting deaddrop.service…"
if ! sudo systemctl restart deaddrop; then
  healthy=0
else
  healthy=0
  for _ in $(seq 1 20); do
    if systemctl is-active --quiet deaddrop \
        && [ "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8100/api/config || true)" = "200" ]; then
      healthy=1
      break
    fi
    sleep 0.25
  done
fi

if [ "$healthy" = "1" ]; then
  # The health check says the process came back. Doctor says whether the thing
  # it came back as is the thing we meant to deploy, and whether what browsers
  # receive still matches it.
  echo "▸ post-deploy preflight…"
  # PORT and HOST live in the systemd unit, not the env file, so pass them the
  # same way check-config does. Without them doctor cannot tell which service to
  # look at, and it refuses to guess.
  if [ -r /etc/deaddrop.env ]; then
    ( set -a; . /etc/deaddrop.env; set +a
      PORT="${PORT:-8100}" HOST="${HOST:-127.0.0.1}" ./deaddrop doctor
    ) || echo "  ! doctor reported a problem"
  else
    sudo /bin/bash -c 'set -a; . /etc/deaddrop.env; set +a
      PORT="${PORT:-8100}" HOST="${HOST:-127.0.0.1}" ./deaddrop doctor' \
      || echo "  ! doctor reported a problem"
  fi
fi

if [ "$healthy" != "1" ]; then
  echo "  ✗ deployment health check failed; restoring previous binary"
  if [ "$HAD_OLD" = "1" ]; then
    mv -f "$BACKUP" deaddrop
    BACKUP=""
    sudo systemctl restart deaddrop || true
  else
    rm -f deaddrop
    sudo systemctl stop deaddrop || true
  fi
  sudo journalctl -u deaddrop -n 20 --no-pager
  exit 1
fi

echo "✓ embedded client/server binary deployed and healthy; git was not pushed."
