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

Accounts use SRP-6a: login sends proofs, never the password. No endpoint accepts
a password, so neither the origin nor Cloudflare ever sees one. Registration
requires a single-use invite code by default.

Codes expire 14 days after they are minted. `INVITE_TTL_DAYS` overrides the
window; `0` disables expiry. Codes issued before expiry existed are stored in the
older bare-string form and are read as never-expiring, so nothing already handed
out stops working. Expired codes are pruned the next time the store is written.

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

A users.json carrying a pre-SRP bcrypt credential is refused at startup: delete
the account and re-register it. Failed logins are throttled per account and
source IP (lockout after 5 tries).

## 6. Tor onion service (Cloudflare-free access)

`tor` serves the app as a v3 onion straight to the Go app on loopback, removing
Cloudflare and public DNS from page/API/WebSocket signaling delivery. WebRTC and
TURN use separate network paths and are not automatically anonymized by this.

Tor must target the dedicated `ONION_PORT` listener (`8101` in the shipped
unit), **never** the nginx-facing `PORT`. Both proxies connect from loopback,
but nginx normalizes `X-Real-IP` while tor relays whatever the client wrote —
on the main port an onion visitor could spoof arbitrary source IPs and rotate
past rate limits and login lockout. The `ONION_PORT` listener ignores forwarded
headers entirely and rate-limits all onion traffic as one shared source.

`/etc/tor/torrc`:

```
HiddenServiceDir /var/lib/tor/deaddrop/
HiddenServicePort 80 127.0.0.1:8101
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

## 7. Backups

Account state is three files in `data/`: `users.json` (SRP verifiers and salts),
`invites.json`, and `srp_dummy.key`. Nothing else on the box is irreplaceable —
the binary is rebuilt from the repo, and message content never touches the disk.

```bash
sudo install -m 0700 scripts/deaddrop-backup /usr/local/sbin/deaddrop-backup
sudo install -d -m 0700 /srv/backups/deaddrop
sudo cp scripts/deaddrop-backup.{service,timer} /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now deaddrop-backup.timer
```

Daily at 04:10 UTC. The server writes every state file atomically (temp, fsync,
rename), so a snapshot taken while it runs sees the old file or the new one and
never a torn one — the service does not need to stop.

Each run unpacks what it just wrote and parses it before publishing the archive,
so a backup that cannot be restored fails loudly on the day it is taken rather
than on the day it is needed. Fourteen days are kept.

**Restore:**

```bash
sudo systemctl stop deaddrop
cd /srv/backups/deaddrop && sha256sum -c deaddrop-<stamp>.tar.gz.sha256
sudo tar -xzf deaddrop-<stamp>.tar.gz -C /home/micu/deaddrop/data --no-same-owner
sudo chown micu:micu /home/micu/deaddrop/data/*
sudo chmod 600 /home/micu/deaddrop/data/*
sudo systemctl start deaddrop
```

`--no-same-owner` then an explicit `chown`: the archive records root's ownership
because the backup runs as root, and the service reads these as `micu`.

The archive holds SRP verifiers and the anti-enumeration dummy key. Verifiers are
not password-equivalent — that is the point of SRP, and the client applies 600k
PBKDF2 rounds before the server sees anything — but the dummy key would let a
holder tell a real account from a fabricated reply. Keep the backup directory as
restricted as `data/` itself: root-only, mode 0700.

## 8. Preflight and monitoring

```bash
sudo -E ./deaddrop doctor
```

`check-config` reads the environment and says whether the settings are legal.
That stays true while the service is down, the backup silently stops running, or
the binary serves a bundle nobody recognises. `doctor` asks what is true of the
machine right now:

| Check | What it would catch |
| --- | --- |
| configuration | an env file that will not start |
| served bundle | a binary built from a tampered tree, or an embed that dropped a file |
| service | a process that is up while the hub goroutine is wedged |
| delivered bundle | a CDN or proxy rewriting the page browsers actually receive |
| backups | a daily timer that has been failing every day |

The delivered-bundle check is the one that is not about this machine. It fetches
the page and the entry module from the loopback origin and from the public URL
and compares them: everything between the two — Cloudflare, nginx, anything that
terminates TLS — can replace the client, and the client is the whole security
product. The page matters most, because its script tags carry the subresource
integrity hashes that make every other module tamper-evident in the browser.

Section 3 asked for this comparison by hand after every deploy. Do it on a timer
instead:

```
# /etc/cron.d/deaddrop-doctor
17 * * * * root . /etc/deaddrop.env; ./deaddrop doctor \
  || logger -t deaddrop-doctor "preflight failed"
```

It exits non-zero on failure, so it works as a cron entry or as a gate before
handing out invites. Run it as root, or the backup check reports that it could
not look rather than that anything is wrong.

`GET /api/health` answers only after a round trip through the goroutine that
routes signaling, so a wedged hub fails it while the page still loads. Point the
uptime monitor there rather than at `/`. It reports liveness and nothing else:
room and peer counts would tell anyone who asks how many people are using the
service and when, so they are not exposed.

## 9. When it breaks

**The site is down.** `systemctl status deaddrop` and `journalctl -u deaddrop -n
50`. The unit restarts on failure, so a process that is *repeatedly* dead is
usually a bad `/etc/deaddrop.env` — `./deaddrop check-config` names the field.

**The page loads but nothing works.** `./deaddrop doctor`. A 404 on `/api/health`
means the running binary predates that endpoint; anything else there means the
hub is not answering and the service needs a restart.

**Calls connect but carry no audio.** Almost always TURN. Re-run the
`turnutils_uclient` check in section 4 — a relay that stops working is invisible
to everyone whose network happens not to need it.

**A bad deploy.** `scripts/deploy.sh` keeps the previous binary and restores it
on a failed health check. To go back by hand: put the old binary in place and
`systemctl restart deaddrop`. The bundle is embedded, so the binary is the whole
client — there is no second thing to roll back.

**Losing account state.** Restore from section 7. Everything else is rebuilt from
the repo, and no message content is ever on the disk to lose.
