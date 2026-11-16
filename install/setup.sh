#!/bin/sh
# Set up a Dead Drop instance on this machine: write .env, build and start the
# containers, and print the first invite.
#
#   ./setup.sh chat.example.org
#   ./setup.sh chat.example.org --turn 203.0.113.5 [--turn-host turn.example.org]
#
# Safe to run again: an existing .env is kept exactly as it is.
set -eu
self=$(basename "$0")
cd "$(dirname "$0")"

usage() {
  sed -n '2,8p' "$self" | sed 's/^# \{0,1\}//' >&2
  exit 2
}
fail() {
  echo "setup: $*" >&2
  exit 1
}

domain=""
public_ip=""
turn_host=""
while [ $# -gt 0 ]; do
  case "$1" in
    --turn) [ $# -ge 2 ] || usage; public_ip=$2; shift 2 ;;
    --turn-host) [ $# -ge 2 ] || usage; turn_host=$2; shift 2 ;;
    -h | --help | -*) usage ;;
    *) [ -z "$domain" ] || usage; domain=$1; shift ;;
  esac
done
[ -n "$domain" ] || usage

valid_host() {
  printf '%s' "$1" | grep -Eq '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$'
}
valid_host "$domain" || fail "\"$domain\" is not a domain name (lowercase, like chat.example.org)"
if [ -n "$public_ip" ]; then
  printf '%s' "$public_ip" | grep -Eq '^([0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-f:]*:[0-9a-f:]*$' ||
    fail "--turn needs this server's public IP address, like 203.0.113.5"
  [ -n "$turn_host" ] || turn_host=$domain
  valid_host "$turn_host" || fail "\"$turn_host\" is not a domain name"
elif [ -n "$turn_host" ]; then
  fail "--turn-host goes with --turn"
fi

command -v docker > /dev/null || fail "Docker is not installed: https://docs.docker.com/engine/install/"
docker compose version > /dev/null 2>&1 || fail "the Docker Compose plugin is missing"

if [ -e .env ]; then
  echo "▸ keeping the existing .env"
  domain=$(sed -n 's/^DOMAIN=//p' .env | tail -n 1)
else
  echo "▸ writing .env"
  umask 077
  {
    sed "s/^DOMAIN=.*/DOMAIN=$domain/" env.example
    if [ -n "$public_ip" ]; then
      # 48 letters and digits: well past the 32 the app requires, and nothing
      # a shell or a URL could misread.
      secret=$(LC_ALL=C tr -dc 'A-Za-z0-9' < /dev/urandom | head -c 48)
      [ "${#secret}" -eq 48 ] || fail "could not generate a TURN secret"
      printf '\n# Written by setup.sh --turn\n'
      printf 'COMPOSE_PROFILES=turn\nPUBLIC_IP=%s\nTURN_SECRET=%s\n' "$public_ip" "$secret"
      printf 'TURN_URLS=turn:%s:3478?transport=udp,turn:%s:3478?transport=tcp\n' "$turn_host" "$turn_host"
      printf 'STUN_URLS=stun:%s:3478\n' "$turn_host"
    fi
  } > .env.tmp
  mv .env.tmp .env
fi

echo "▸ building and starting — the first build takes a few minutes"
docker compose up -d --build

echo "▸ waiting for the app to answer"
tries=0
until docker compose exec -T app deaddrop health > /dev/null 2>&1; do
  tries=$((tries + 1))
  [ "$tries" -lt 60 ] || fail "the app did not come up; see: docker compose logs app"
  sleep 1
done

invite=$(docker compose exec -T app deaddrop invite) || fail "could not mint an invite"

cat << EOF

✓ Dead Drop is running.

  Open https://$domain
  (the first visit can take a minute while the certificate is issued)

  First invite, single use: $invite
  More:                     docker compose exec app deaddrop invite

  Next: INSTALL.md — backups, updates, and checking that what you run is
  the published code.
EOF

if ! grep -q '^TURN_SECRET=.' .env; then
  cat << EOF

  ⚠ No relay. With the default "hide my IP" setting nobody can connect to
    anyone, not even to send a message. Delete .env and run this again with
    --turn <public IP>, or see "The relay" in INSTALL.md.
EOF
fi
