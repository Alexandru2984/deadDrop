# Running your own Dead Drop

This is the short way: Docker, one script, HTTPS certificates that renew
themselves. It runs the same code as the public instance — the same client,
byte for byte, which anyone can check (see [Is it the real thing?](#is-it-the-real-thing)).
[`DEPLOY.md`](DEPLOY.md) describes the longer, hand-built setup the public
instance itself uses.

## What you need

- A Linux server with [Docker Engine and the Compose plugin](https://docs.docker.com/engine/install/).
  One CPU and 1 GB of memory are plenty: conversations, files and calls go
  between browsers, not through the server.
- A domain name, with its DNS pointing at the server.
- Ports 80 and 443 open (443 over UDP too, for HTTP/3), and nothing else
  listening on them — or see [a web server you already run](#behind-a-web-server-you-already-run).
- For the relay (you want one, see below): 3478 over UDP and TCP, and
  49160–49999 over UDP.

## Install

```bash
git clone https://github.com/Alexandru2984/deadDrop.git
cd deadDrop/install
./setup.sh chat.example.org --turn 203.0.113.5
```

Use your domain, and the server's public IP address after `--turn`. Leaving
`--turn …` out skips [the relay](#the-relay), which you almost certainly need.

The script writes the settings to `install/.env`, builds the image, starts
everything, and prints the first invite. Open `https://your-domain`, register
with it, and that is your account. Running the script again keeps `.env` as it
is.

Three containers run, four with the relay:

| | |
|---|---|
| `app` | Dead Drop. No shell, no package manager, an unprivileged user, a read-only file system, its port on no network. |
| `web` | [Caddy](https://caddyserver.com/), for HTTPS. It keeps no access log. |
| `net` | Holds the network `app` and `web` share, so `web` reaches `app` on `127.0.0.1` — the only address `app` accepts a visitor's address from. |
| `turn` | [coturn](https://github.com/coturn/coturn), the relay. Optional. |

## Invites

Accounts need an invite, used once, valid 14 days:

```bash
docker compose exec app deaddrop invite        # one
docker compose exec app deaddrop invite 5      # five
docker compose exec app deaddrop invites list
```

(Every `docker compose` command here is run from the `install` directory.)

## Settings

Everything is in `install/.env`, explained line by line in
[`install/env.example`](install/env.example). After changing it:

```bash
docker compose up -d
```

Set `SECURITY_CONTACT` (a `mailto:` or `https:` address) to publish where
people should report a vulnerability, at `/.well-known/security.txt`.

## The relay

Messages, files and calls go straight between the two browsers — and by
default, through a relay, so that neither learns the other's IP address.
Without a relay, nobody using that default can connect to anyone, not even to
send a message; and those who turn it off connect only when their networks
allow it, which most mobile networks and many offices do not. So run one.

`setup.sh --turn <public IP>` sets it up. To add one later, uncomment the relay
lines in `.env` (with a secret of 32+ random characters), then
`docker compose up -d`.

The relay must be reached directly. If your domain goes through a proxy such as
Cloudflare, give the relay a separate DNS-only name: `--turn-host
turn.example.org`, or `TURN_URLS` and `STUN_URLS` in `.env`.

The relay sees both ends' IP addresses, and when and how much — but not the
content, which is encrypted between the browsers.

## Behind Cloudflare

Every visitor then seems to come from one of Cloudflare's addresses, and the
app's per-visitor limits would be shared by everyone behind the same one. Tell
the web server to take the visitor's address from Cloudflare — and only from
Cloudflare — by listing [Cloudflare's address ranges](https://www.cloudflare.com/ips/)
in `.env`, separated by spaces:

```bash
TRUSTED_PROXIES=173.245.48.0/20 103.21.244.0/22 … 2400:cb00::/32 …
```

The ranges change now and then; check them once in a while.

## Behind a web server you already run

If nginx or another web server already has ports 80 and 443, keep it, and
skip `web` and `net`. Add to `.env`:

```bash
COMPOSE_FILE=compose.yaml:compose.behind-proxy.yaml
APP_PORT=8100
```

The app then listens on `127.0.0.1:8100` of the host itself. For nginx:

```nginx
map $http_upgrade $connection_upgrade {   # at http level, once
    default upgrade;
    ''      close;
}

server {
    listen 443 ssl;
    http2 on;
    server_name chat.example.org;
    # ssl_certificate …; ssl_certificate_key …;

    location / {
        proxy_pass http://127.0.0.1:8100;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        proxy_read_timeout 120s;
    }
}
```

Add no security headers there: the app sets them all, and a second set would
fight the first. And `access_log off;` in that block keeps your server from
recording what the app does not.

## Updating

```bash
cd deadDrop
git pull
cd install
docker compose up -d --build
```

Accounts and invites are kept; anyone signed in signs in again. Read
[`CHANGELOG.md`](CHANGELOG.md) first: it says when something needs doing.

## Is it the real thing?

```bash
docker compose exec app deaddrop version
```

prints the version and the digest of the client this server sends to
browsers. It should equal `sha256sum web/SHA256SUMS` in the repository at that
version's tag, and release notes state it from 0.8.0 on. Visitors can check
from their side too, at `/verify.html` on your site, which compares what the
server sent them with the public repository.

The pages name the public instance as their canonical address, because a
server that rewrote them would no longer match the digest — the one property
that lets a visitor check the code. Search engines are therefore pointed at
the public instance rather than yours.

## Backups

Three files hold every account and invite. Copy them out:

```bash
mkdir -p ~/deaddrop-backup && cd ~/deaddrop-backup && umask 077
for f in users.json invites.json srp_dummy.key; do
  docker compose -f ~/deadDrop/install/compose.yaml cp app:/var/lib/deaddrop/data/$f ./
done
```

Keep them as private as the server: they cannot reveal passwords, but they can
tell a real account from an invented one. Messages left for someone offline
are left out on purpose — one restored from a backup could already have been
collected, or kept past the time its sender gave it.

To restore, from the backup directory:

```bash
docker compose -f ~/deadDrop/install/compose.yaml stop app
docker run --rm -v deaddrop_app-data:/data -v "$PWD":/backup:ro busybox:1.37 sh -c '
  cp /backup/users.json /backup/invites.json /backup/srp_dummy.key /data/ &&
  chown 65532:65532 /data/*.json /data/srp_dummy.key &&
  chmod 600 /data/*.json /data/srp_dummy.key'
docker compose -f ~/deadDrop/install/compose.yaml start app
```

## What your server learns

Not what anyone says: messages, files and calls are end-to-end encrypted, and
messages left for someone offline are sealed with keys the server never has.
It does learn who has an account, when they are online, who is in a room with
whom, and IP addresses. [`/about.html`](web/about.html) on your own site lists
all of it — read it, because your users are trusting you with it now.

## Removing it

```bash
docker compose down        # stop, keep the data
docker compose down -v     # stop and delete every account and invite
```
