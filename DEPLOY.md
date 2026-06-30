# Deployment

Production runs behind nginx (TLS) → Cloudflare. The Go app binds to loopback and
self-hosts STUN/TURN via coturn. Nothing below puts secrets in the repo.

## 1. App service (systemd)

`/etc/systemd/system/deaddrop.service` runs the binary as a non-root user, reads
secrets from an env file, and is hardened (`ProtectSystem=full`, `NoNewPrivileges`,
empty `CapabilityBoundingSet`, `ReadWritePaths=<datadir>`).

Key settings:

```ini
Environment=PORT=8100
Environment=HOST=127.0.0.1            # loopback only — reachable only via nginx
EnvironmentFile=-/etc/deaddrop.env    # TURN secret etc. (mode 600, root)
Restart=always
```

Rebuild & restart:

```bash
go build -trimpath -ldflags="-s -w" -o deaddrop ./cmd/server/
sudo systemctl restart deaddrop
```

## 2. Secrets — `/etc/deaddrop.env` (mode 600, root)

```
TURN_SECRET=<openssl rand -hex 32>
TURN_URLS=turn:<PUBLIC_IP>:3478?transport=udp,turn:<PUBLIC_IP>:3478?transport=tcp
STUN_URLS=stun:<PUBLIC_IP>:3478
TURN_REALM=dead.micutu.com
```

`TURN_SECRET` must match coturn's `static-auth-secret`. The app never sends it to
the browser — it mints a short-lived `HMAC-SHA1` credential per `/api/turn` request.

## 3. nginx vhost

The app emits **all** security headers itself; the vhost must NOT include the
shared `snippets/security-headers.conf` (it would duplicate/override them). One
`add_header X-Robots-Tag ...` in the server block breaks inheritance of the
http-level defaults. Proxy passes to `127.0.0.1:8100` with WebSocket upgrade.

The enabled vhost is a real file (not a symlink); keep `sites-available` and
`sites-enabled` copies in sync and never leave `*.bak` files in `sites-enabled`
(nginx globs them).

## 4. coturn (STUN/TURN)

`/etc/turnserver.conf` highlights:

```
listening-port=3478
listening-ip=<PUBLIC_IP>
relay-ip=<PUBLIC_IP>
external-ip=<PUBLIC_IP>
fingerprint
use-auth-secret
static-auth-secret=<same as TURN_SECRET>
realm=dead.micutu.com
min-port=49160
max-port=49200
# anti-abuse: never relay to internal/private/loopback/multicast ranges
no-loopback-peers
no-multicast-peers
no-tcp-relay
denied-peer-ip=10.0.0.0-10.255.255.255   # (+ all other private/reserved ranges)
```

Enable in `/etc/default/coturn` (`TURNSERVER_ENABLED=1`), then
`sudo systemctl enable --now coturn`.

Firewall: open `3478/udp`, `3478/tcp`, and the relay range `49160:49200/udp`.

Verify a credential actually relays:

```bash
SECRET=$(grep '^static-auth-secret=' /etc/turnserver.conf | cut -d= -f2)
U=$(( $(date +%s) + 3600 )); P=$(printf '%s' "$U" | openssl dgst -sha1 -hmac "$SECRET" -binary | base64)
turnutils_uclient -y -u "$U" -w "$P" -p 3478 -n 2 <PUBLIC_IP>   # expect 0 lost packets
```

> **Privacy note:** TURN requires clients to reach the VPS directly on UDP, so the
> origin IP is disclosed to call participants (Cloudflare cannot proxy TURN). The
> win from "Max anonymity" (relay-only) mode is that the two *peers* never see each
> other's IPs and the payload stays end-to-end encrypted.

## 5. Accounts (SRP) & invites

Login uses SRP-6a: the password is turned into a verifier in the browser and never
reaches the server (or Cloudflare). Registration requires a single-use invite code.

Mint an invite from the CLI:

```bash
cd /home/micu/deaddrop && ./deaddrop invite      # prints e.g. DD-FXAV-XKH6-JC22
```

…or via the admin endpoint (set `ADMIN_TOKEN` in `/etc/deaddrop.env`):

```bash
curl -X POST -H "X-Admin-Token: $ADMIN_TOKEN" https://dead.micutu.com/api/admin/invite
```

Invites live in `data/invites.json` (single-use, consumed on registration). With an
empty list, registration is effectively closed.

Pre-SRP (bcrypt) accounts still log in via the legacy path and are transparently
upgraded to SRP on first login (the verifier is computed locally; the password is
not resent). Failed logins are throttled per-account (lockout after 5 tries).

## 6. Tor onion service (Cloudflare-free access)

`tor` serves the app as a v3 onion straight to the Go app on loopback, so visitors
never touch Cloudflare or leak the DNS lookup for dead.micutu.com.

`/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/deaddrop/
HiddenServicePort 80 127.0.0.1:8100
```

The onion address is in `/var/lib/tor/deaddrop/hostname`. Add it to
`ALLOWED_ORIGINS` in `/etc/deaddrop.env` (this env REPLACES the built-in list, so
include every origin):

```
ALLOWED_ORIGINS=https://dead.micutu.com,http://dead.micutu.com,http://<onion>.onion,http://localhost:8100,http://127.0.0.1:8100
```

Test through Tor: `curl --socks5-hostname 127.0.0.1:9050 http://<onion>.onion/`.

> **Limitation:** Tor carries TCP only, so the WebRTC P2P data channel (UDP) does
> not establish over the onion — the onion is for **private access** to load the
> app and run signalling without Cloudflare/DNS exposure. Actual peer-to-peer chat
> still needs a non-Tor transport (or TURN-over-TCP, which reveals the relay IP).
