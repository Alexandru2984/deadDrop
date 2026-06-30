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
