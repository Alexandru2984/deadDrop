# Deployment

Production runs behind nginx (TLS) → Cloudflare. The Go app binds to loopback and
self-hosts STUN/TURN via coturn. Nothing below puts secrets in the repo.

## 1. App service (systemd)

Install the reviewed unit template. It runs the binary as a non-root user, reads
secrets from an env file, makes the source tree read-only, and permits writes
only in `data/`:

```bash
sudo install -d -o micu -g micu -m 0700 /home/micu/deaddrop/data
sudo install -o root -g root -m 0644 scripts/deaddrop.service /etc/systemd/system/deaddrop.service
sudo systemctl daemon-reload
```

Key settings:

```ini
Environment=PORT=8100
Environment=HOST=127.0.0.1            # loopback only — reachable only via nginx
EnvironmentFile=-/etc/deaddrop.env    # TURN secret etc. (mode 600, root)
Restart=always
```

The browser bundle is embedded in the Go binary: loose files under `web/` are
never read at runtime. A deploy therefore cannot mix a new server with stale or
live-edited cryptographic JavaScript. Build only after the committed integrity
manifest passes its read-only check:

```bash
node scripts/gen-integrity.mjs --check
go build -trimpath -ldflags="-s -w" -o deaddrop ./cmd/server/
sudo systemctl restart deaddrop
```

`scripts/deploy.sh` additionally requires a clean working tree, runs all Go and
browser tests, validates `/etc/deaddrop.env` with `deaddrop check-config`, swaps
the binary atomically, checks health, and restores the old binary on failure.

### Remove the obsolete integrity watcher

The former watcher rewrote hashes after any live edit. That could turn a
compromised JavaScript file into the new locally “valid” bundle. Embedded assets
make it unnecessary; disable and remove it before using the deploy script:

```bash
sudo systemctl disable --now deaddrop-integrity.service
sudo rm -f /etc/systemd/system/deaddrop-integrity.service
sudo systemctl daemon-reload
```

## 2. Secrets — `/etc/deaddrop.env` (mode 600, root)

```
TURN_SECRET=<openssl rand -hex 32>
TURN_URLS=turn:<PUBLIC_IP>:3478?transport=udp,turn:<PUBLIC_IP>:3478?transport=tcp
STUN_URLS=stun:<PUBLIC_IP>:3478
TURN_REALM=dead.micutu.com
ALLOWED_ORIGINS=https://dead.micutu.com,http://<onion>.onion
OPEN_REGISTRATION=0
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

### Cloudflare-only HTTPS origin

Do not expose the HTTPS application origin directly. At `http` scope, maintain
a `geo` map named `$from_cloudflare_origin` over `$realip_remote_addr`, allowing
only loopback and Cloudflare's current published IPv4/IPv6 prefixes. Use
`$realip_remote_addr`, not the visitor-rewritten `$remote_addr`, so a forged
`CF-Connecting-IP` or `X-Forwarded-For` header cannot pass the check. Then put
this fail-closed guard in the TLS server block:

```nginx
if ($from_cloudflare_origin = 0) {
    return 444;
}
```

Keep the port-80 Certbot/nginx challenge path outside that TLS-only guard, and
validate before reloading with `sudo nginx -t`. After reload, the Cloudflare URL
and an explicit loopback TLS resolve must return 200, while an explicit resolve
to the public origin IP must fail before HTTP. The app emits
`Cache-Control: no-store, no-transform`; compare public, loopback, and onion
SHA-256 hashes after every deploy to detect CDN HTML rewriting.

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
> relay-only mode hides endpoint addresses from the other *peer* when TURN
> succeeds. The VPS/TURN operator still sees both client IPs, timing, and volume;
> this is not anonymity.

## 5. Accounts (SRP) & invites

New and upgraded accounts use SRP-6a: normal login sends proofs instead of the
password. A legacy bcrypt account still sends its password once to the Go origin
(through Cloudflare on clearnet), then upgrades. Registration requires a
single-use invite code by default.

Mint invites from the CLI (codes go to stdout, status to stderr, so they pipe cleanly):

```bash
cd /home/micu/deaddrop
./deaddrop invite                 # mint one   → DD-FXAV-XKH6-JC22
./deaddrop invite 10              # mint ten at once
./deaddrop invites list           # show all unused codes (+ count on stderr)
./deaddrop invites export backup.json   # creates a new 0600 JSON file; refuses overwrite
./deaddrop invites import backup.json   # merge a backup (dedup; `-` reads stdin)
```

`import` accepts at most 4 MiB, from either the JSON array that `export` writes or plain
newline-separated codes; malformed tokens and duplicates are skipped and reported.
This lets you pre-generate a batch offline and restore or migrate the invite pool.

The network admin endpoint is disabled by default. Prefer the local CLI. If it is
strictly required, set both `ENABLE_ADMIN_API=1` and a random `ADMIN_TOKEN` of at
least 32 characters in `/etc/deaddrop.env`, then use:

```bash
curl -X POST -H "X-Admin-Token: $ADMIN_TOKEN" https://dead.micutu.com/api/admin/invite
```

Invites live in `data/invites.json` (single-use, consumed on registration). With an
empty list, registration is effectively closed. The running server re-reads the file
on each registration, so codes minted/imported by the CLI are usable immediately —
no restart needed.

Pre-SRP (bcrypt) accounts still log in via the legacy path and are transparently
upgraded to SRP on first login (the verifier is computed locally; the password is
not resent). Failed logins are throttled per-account (lockout after 5 tries).

## 6. Tor onion service (Cloudflare-free access)

`tor` serves the app as a v3 onion straight to the Go app on loopback, removing
Cloudflare and public DNS from page/API/WebSocket signaling delivery. WebRTC and
TURN use separate network paths and are not automatically anonymized by this.

`/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/deaddrop/
HiddenServicePort 80 127.0.0.1:8100
```

The onion address is in `/var/lib/tor/deaddrop/hostname`. Add it to
`ALLOWED_ORIGINS` in `/etc/deaddrop.env` (this env replaces the built-in list):

```
ALLOWED_ORIGINS=https://dead.micutu.com,http://<onion>.onion
```

Plain HTTP is accepted only for loopback development and `.onion`; never list
the public clearnet domain with `http://`. Loopback development origins cannot
be mixed with deployed origins. For a local-only server, omit
`ALLOWED_ORIGINS` and set `ALLOW_LOCAL_ORIGINS=1`.

Test through Tor: `curl --socks5-hostname 127.0.0.1:9050 http://<onion>.onion/`.

> **Limitation:** Tor carries TCP only, so the WebRTC P2P data channel (UDP) does
> not establish over the onion — the onion is for **private access** to load the
> app and run signalling without Cloudflare/DNS exposure. Actual peer-to-peer chat
> still needs a non-Tor transport (or TURN-over-TCP, which reveals the relay IP).
