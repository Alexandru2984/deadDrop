# Propria ta instanță Dead Drop

English: [INSTALL.md](INSTALL.md)

Aceasta e calea scurtă: Docker, un singur script și certificate HTTPS care se
reînnoiesc singure. Rulează același cod ca instanța publică — același client,
byte cu byte, lucru pe care oricine îl poate verifica (vezi [E chiar codul publicat?](#e-chiar-codul-publicat)).
[`DEPLOY.md`](DEPLOY.md) descrie instalarea mai lungă, făcută de mână, pe care o
folosește chiar instanța publică.

## De ce ai nevoie

- Un server Linux cu [Docker Engine și pluginul Compose](https://docs.docker.com/engine/install/).
  Un procesor și 1 GB de memorie sunt de ajuns: conversațiile, fișierele și
  apelurile circulă între browsere, nu prin server.
- Un nume de domeniu, cu DNS-ul îndreptat spre server.
- Porturile 80 și 443 deschise (443 și pe UDP, pentru HTTP/3) și nimic altceva
  care să asculte pe ele — altfel, vezi [un server web pe care îl ai deja](#în-spatele-unui-server-web-pe-care-îl-ai-deja).
- Pentru releu (îți trebuie unul, vezi mai jos): 3478 pe UDP și TCP, și
  49160–49999 pe UDP.

## Instalare

```bash
git clone https://github.com/Alexandru2984/deadDrop.git
cd deadDrop/install
./setup.sh chat.example.org --turn 203.0.113.5
```

Folosește domeniul tău, iar după `--turn` adresa IP publică a serverului. Fără
`--turn …` nu se instalează [releul](#releul), de care aproape sigur ai nevoie.

Scriptul scrie setările în `install/.env`, construiește imaginea, pornește
totul și afișează prima invitație. Deschide `https://domeniul-tău`, înregistrează-te
cu ea, și acela e contul tău. Dacă rulezi scriptul din nou, `.env` rămâne cum
este.

Rulează trei containere, patru cu releul:

| | |
|---|---|
| `app` | Dead Drop. Fără shell, fără manager de pachete, un utilizator fără privilegii, un sistem de fișiere doar pentru citire, portul său în nicio rețea. |
| `web` | [Caddy](https://caddyserver.com/), pentru HTTPS. Nu ține jurnal de accesări. |
| `net` | Ține rețeaua pe care o împart `app` și `web`, astfel încât `web` ajunge la `app` pe `127.0.0.1` — singura adresă de la care `app` acceptă adresa unui vizitator. |
| `turn` | [coturn](https://github.com/coturn/coturn), releul. Opțional. |

## Invitații

Conturile au nevoie de o invitație, folosită o singură dată, valabilă 14 zile:

```bash
docker compose exec app deaddrop invite        # una
docker compose exec app deaddrop invite 5      # cinci
docker compose exec app deaddrop invites list
```

(Fiecare comandă `docker compose` de aici se rulează din directorul `install`.)

## Setări

Totul e în `install/.env`, explicat rând cu rând în
[`install/env.example`](install/env.example). După ce îl schimbi:

```bash
docker compose up -d
```

Setează `SECURITY_CONTACT` (o adresă `mailto:` sau `https:`) ca să publici unde
pot fi raportate vulnerabilitățile, la `/.well-known/security.txt`.

## Releul

Mesajele, fișierele și apelurile merg direct între cele două browsere — și,
implicit, printr-un releu (TURN), ca niciunul să nu afle adresa IP a celuilalt.
Fără releu, nimeni care păstrează această setare implicită nu se poate conecta
la nimeni, nici măcar ca să trimită un mesaj; iar cei care o dezactivează se
conectează doar când rețelele lor permit, ceea ce majoritatea rețelelor mobile
și multe birouri nu permit. Așa că rulează unul.

`setup.sh --turn <IP public>` îl configurează. Ca să adaugi unul mai târziu,
decomentează liniile releului din `.env` (cu un secret de cel puțin 32 de
caractere aleatorii), apoi `docker compose up -d`.

Releul trebuie să poată fi accesat direct. Dacă domeniul tău trece printr-un
proxy precum Cloudflare, dă-i releului un nume separat, doar DNS: `--turn-host
turn.example.org`, sau `TURN_URLS` și `STUN_URLS` în `.env`.

Releul vede adresele IP ale ambelor capete, plus când și cât comunică — dar nu
și conținutul, care e criptat între browsere.

## În spatele Cloudflare

Atunci fiecare vizitator pare să vină de la una dintre adresele Cloudflare, iar
limitele aplicației pentru fiecare vizitator ar fi împărțite de toți cei din
spatele aceleiași adrese. Spune-i serverului web să ia adresa vizitatorului de
la Cloudflare — și numai de la Cloudflare — trecând
[intervalele de adrese ale Cloudflare](https://www.cloudflare.com/ips/) în `.env`,
separate prin spații:

```bash
TRUSTED_PROXIES=173.245.48.0/20 103.21.244.0/22 … 2400:cb00::/32 …
```

Intervalele se mai schimbă; verifică-le din când în când.

## În spatele unui server web pe care îl ai deja

Dacă nginx sau alt server web ocupă deja porturile 80 și 443, păstrează-l și
renunță la `web` și `net`. Adaugă în `.env`:

```bash
COMPOSE_FILE=compose.yaml:compose.behind-proxy.yaml
APP_PORT=8100
```

Aplicația ascultă atunci pe `127.0.0.1:8100` chiar pe server. Pentru nginx:

```nginx
map $http_upgrade $connection_upgrade {   # la nivel http, o singură dată
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

Nu adăuga acolo antete de securitate: aplicația le setează pe toate, iar un al
doilea set s-ar bate cu primul. Iar `access_log off;` în acel bloc îți
împiedică serverul să înregistreze ce aplicația nu înregistrează.

## Actualizare

```bash
cd deadDrop
git pull
cd install
docker compose up -d --build
```

Conturile și invitațiile se păstrează; cine era autentificat se autentifică din
nou. Citește întâi [`CHANGELOG.md`](CHANGELOG.md): acolo scrie când trebuie
făcut ceva.

## E chiar codul publicat?

```bash
docker compose exec app deaddrop version
```

afișează versiunea și amprenta clientului pe care acest server îl trimite
browserelor. Trebuie să fie egală cu `sha256sum web/SHA256SUMS` din depozit, la
tag-ul acelei versiuni, iar notele de release o menționează începând cu 0.8.0.
Și vizitatorii pot verifica din partea lor, la `/verify.html` pe site-ul tău,
care compară ce le-a trimis serverul cu depozitul public.

Paginile numesc instanța publică drept adresa lor canonică, pentru că un server
care le-ar rescrie n-ar mai corespunde amprentei — singura proprietate care îi
permite unui vizitator să verifice codul. De aceea motoarele de căutare sunt
îndreptate spre instanța publică, nu spre a ta.

## Copii de siguranță

Trei fișiere conțin toate conturile și invitațiile. Copiază-le afară:

```bash
mkdir -p ~/deaddrop-backup && cd ~/deaddrop-backup && umask 077
for f in users.json invites.json srp_dummy.key; do
  docker compose -f ~/deadDrop/install/compose.yaml cp app:/var/lib/deaddrop/data/$f ./
done
```

Păstrează-le la fel de private ca serverul: nu pot dezvălui parole, dar pot
deosebi un cont real de unul inventat. Mesajele lăsate pentru cineva offline
sunt lăsate deoparte intenționat — unul restaurat dintr-o copie putea fi deja
ridicat sau păstrat mai mult decât timpul dat de cel care l-a trimis.

Pentru restaurare, din directorul cu copia:

```bash
docker compose -f ~/deadDrop/install/compose.yaml stop app
docker run --rm -v deaddrop_app-data:/data -v "$PWD":/backup:ro busybox:1.37 sh -c '
  cp /backup/users.json /backup/invites.json /backup/srp_dummy.key /data/ &&
  chown 65532:65532 /data/*.json /data/srp_dummy.key &&
  chmod 600 /data/*.json /data/srp_dummy.key'
docker compose -f ~/deadDrop/install/compose.yaml start app
```

## Ce află serverul tău

Nu ce spune cineva: mesajele, fișierele și apelurile sunt criptate cap la cap,
iar mesajele lăsate pentru cineva offline sunt sigilate cu chei pe care serverul
nu le are niciodată. Află în schimb cine are cont, când e cineva online, cine e
într-o cameră cu cine și adresele IP. [`/about.ro.html`](web/about.ro.html) pe
propriul tău site le enumeră pe toate — citește-o, pentru că acum utilizatorii
tăi îți încredințează ție aceste informații.

## Dezinstalare

```bash
docker compose down        # oprește, păstrează datele
docker compose down -v     # oprește și șterge toate conturile și invitațiile
```
