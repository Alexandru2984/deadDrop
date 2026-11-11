# Analiză privacy și CI — 11 noiembrie 2026

Revizie analizată: `652b2c1ff24a3d164ccdf25a10971eb5ebc543c0` (0.7.0).
Analiza acoperă implementarea serverului, autentificarea, protocolul clientului,
transportul, fișierele, retenția și configurația de deployment din repository.
Reproducerile au rulat pe servere locale separate, cu date temporare. Configurația
efectivă din producție și infrastructura Cloudflare/nginx/coturn nu au fost auditate.

**Stare după remediere:** cele patru probleme reproduse mai jos au fost corectate
în repository, cu teste de regresie. La revizia inițială, testele existente treceau fără
să le detecteze. Proiectul oferă confidențialitate
a conținutului între endpoints verificate, cu limite documentate; nu oferă
anonimitate față de toate componentele infrastructurii.

## CI: cauza și modificarea aplicată

[Vulnerability watch, run 43039286504](https://github.com/Alexandru2984/deadDrop/actions/runs/43039286504)
a eșuat pe 11 noiembrie în `govulncheck`. Logul raportează
`GO-2026-6859`, „HTTP/1 server crash due to MaxBytesReader header race in net/http”,
pentru Go 1.26.10, cu remediere în 1.26.11. Este o problemă de disponibilitate;
logul nu dovedește decriptarea mesajelor sau exploatarea instanței.

Ultimul CI complet pentru același commit, [run 41458199450](https://github.com/Alexandru2984/deadDrop/actions/runs/41458199450),
trecuse pe 2 noiembrie. Scanarea zilnică a detectat ulterior advisory-ul, fără
schimbări de cod între aceste rulări.

Am actualizat `go.mod` și cerința din README la Go 1.26.11. Ambele workflow-uri
folosesc `go-version-file: go.mod`, deci preiau aceeași versiune. Cu noul toolchain,
scanerul fixat de proiect raportează `No vulnerabilities found.`
[Istoricul oficial Go](https://go.dev/doc/devel/release#go1.26.11)
confirmă patch-ul din 10 noiembrie și remedierile de securitate din `net/http`.

Remedierile au fost publicate la `d2c3898582a784e89e24e367b5aa004335e61363`.
[CI complet, run 43091071686](https://github.com/Alexandru2984/deadDrop/actions/runs/43091071686)
a trecut toate cele 14 job-uri, iar
[Vulnerability watch, run 43091104517](https://github.com/Alexandru2984/deadDrop/actions/runs/43091104517)
a trecut separat pe aceeași revizie. Un executabil deja construit trebuie
reconstruit și redeployat pentru a beneficia de patch; `deaddrop version` și
`deaddrop doctor` verifică separat starea instalării.

## Constatări inițiale și remedieri

Referințele numerice și reproducerile de mai jos descriu revizia analizată
inițial, înaintea remedierilor.

### 1. P1 — Proof-urile SRP pregătite înaintea schimbării parolei rămân autorizate

**Remediat:** fiecare cont are revizii de autorizare în memorie, separate pentru
credențialul principal și duress. Verificarea reviziei, emiterea sesiunii,
modificările de cont și revocările sunt sincronizate. Sesiunea este reverificată
după citirea corpului cererii. `internal/auth/revocation_test.go` acoperă proof-uri
vechi, duress, ștergere/reînregistrare, un challenge deja consumat și cereri
suspendate înainte de revocarea cookie-ului.

Locuri: `internal/auth/srp_auth.go:1147`, `:1157`, `:1464`; schimbările de
credențiale la `:1219` și ștergerea contului la `:1315`.

Un challenge păstrează verifier-ul și indicatorii `real`/`realDuress` de la
emitere. Autentificarea și reautentificarea verifică proof-ul împotriva acestei
copii, fără să verifice că acel cont și acea versiune de credențial mai există.
Schimbarea parolei și ștergerea contului revocă sesiuni, dar nu invalidează
aceste autorizări în așteptare.

Reproducere HTTP cu implementarea reală JS de SRP și serverul real Go:

1. Se înregistrează un cont de test și se pregătesc două proof-uri pentru parola veche.
2. Proprietarul schimbă parola cu un al treilea proof, valid la acel moment.
3. Primul proof păstrat trimis la `/api/srp/authenticate` primește **200 și cookie nou**.
4. Al doilea proof păstrat, împreună cu acest cookie, permite încă o schimbare de
   parolă la `/api/account/verifier`: **200**, iar parola aleasă de atacator autentifică.
5. Separat, un proof pregătit înainte de ștergerea contului autentifică după
   ștergere: **200**, apoi `/api/me` răspunde tot **200**.

Atacatorul trebuie să cunoască vechea parolă și să pregătească proof-urile în
fereastra de valabilitate a challenge-ului, de un minut. Nu este autentificare
fără parolă și nu recuperează cheile sau mesajele E2EE vechi. Totuși, fereastra
scurtă poate produce o preluare persistentă a credențialului, nu doar un minut
de acces, și încalcă așteptarea că schimbarea parolei elimină vechiul acces.

Remediere: legați challenge-urile de generația contului și a credențialului.
Verificarea generației, emiterea sesiunii și mutațiile de cont trebuie
serializate; simpla golire a tabelului lasă o cursă cu proof-uri deja extrase
din el. O ștergere și reînregistrare cu același username trebuie să creeze altă
generație. Adăugați cazuri pentru parola principală, duress, ștergere,
reînregistrare și cereri concurente.

### 2. P1 — „Ascunde IP-ul” permite automat transport direct fără TURN

**Remediat:** crearea/intrarea într-o cameră este oprită dacă opțiunea este activă
și lipsește un relay valid; aceeași verificare apără crearea fiecărui peer.
Politica WebRTC nu mai depinde de disponibilitatea relay-ului. Suita nouă
`test/browser.privacy.mjs` acoperă lipsa configurației, 401/429/500, JSON invalid,
credențiale expirate și eșecul refresh-ului după expirare.

Locuri: `web/js/app.js:1437`, `:1555`, `:1566`; `web/js/peer.js:304`.

Politica este calculată ca `this._relayOnly && this._hasRelay()`. Când configurația
nu conține TURN, cererea utilizatorului de a ascunde IP-ul devine `false`, iar
`RTCPeerConnection` folosește `iceTransportPolicy: 'all'`. Un răspuns `/api/turn`
eșuat, invalid sau fără relay poate ajunge la același rezultat dacă nu mai există
o configurație încă valabilă.

Reproducere cu doi peers Chromium izolați, clientul original și server local
fără TURN: checkbox-ul a rămas **bifat**, constructorul WebRTC a primit politica
**`all`**, iar peers au stabilit sesiunea, comparat același SAS, verificat reciproc
și transferat un fișier. Aplicația afișează un avertisment; acesta nu cere un
acord explicit înainte să înceapă negocierea directă.

Impact: adrese/candidați de rețea pot fi expuși partenerului, conform comportamentului
ICE al browserului, înaintea verificării SAS. Nu este o ocolire demonstrată a
unei conexiuni configurate efectiv cu politica `relay`; problema este schimbarea
automată a politicii atunci când configurația relay lipsește.

Remediere: păstrați politica `relay` cât timp opțiunea este activă. Lipsa TURN
trebuie să oprească negocierea și să explice problema. Transportul direct trebuie
să rezulte dintr-o alegere explicită a utilizatorului. Testați și răspunsuri
401/429/500, JSON invalid și credențiale expirate.

### 3. P2 — Pregătirea asincronă a unui fișier poate reintroduce date după Panic

**Remediat:** trimiterea este legată de generația sesiunii, camera și
destinatarii inițiali; operațiile vechi sunt abandonate după fiecare așteptare
relevantă. Decriptarea fișierelor și mesajele în curs nu mai pot reintroduce
conținut după cleanup. Panic golește interfața imediat, șterge local preferințele
și limba și limitează așteptarea logout-ului la trei secunde. Identitatea și
contactele se șterg într-o singură tranzacție IndexedDB, așteptată până la commit.
Testul Chromium cu modulul de scrub și logout-ul întârziate trece acum fără
reapariția fișierului. Harness-ul de schimbare a camerei abandonează trimiterea.

Locuri: `web/js/app.js:1965`, `:1988`, `:1996`, `:2049`, `:2058`, `:3620`, `:3840`.

`sendFile()` verifică starea sesiunii la intrare, apoi așteaptă importul
scrubber-ului și curățarea fișierului. Calea obișnuită nu reverifică sesiunea
înainte să creeze Blob-ul și cardul de fișier. `_cleanup()` invalidează lucrul
asincron de signaling, dar nu și pregătirea fișierelor.

Reproducere în Chromium, cu doi peers și clientul original, schimbând doar
momentul în care se livrează două cereri de rețea:

1. Se întârzie încărcarea `/js/scrub.js`, iar utilizatorul selectează un fișier.
2. Se apasă butonul Panic; se întârzie cererea de logout, ca la o rețea blocată.
3. Imediat după cleanup sunt **zero carduri de fișier**.
4. Se livrează modulul original de scrub: **fișierul reapare, cu URL Blob de descărcare**.

Acest test nu a modificat codul aplicației, manifestul sau verificările de
integritate. A confirmat reținerea/reafișarea fișierului după cleanup, nu
transmiterea lui către peer după Panic.

Un harness separat, executând metodele originale `_sendFiles`/`sendFile` cu
pregătirea suspendată, a schimbat starea din camera A în camera B înainte de
reluare: destinatarul selectat a fost peer-ul B. Acesta dovedește lipsa legării
operației de sesiunea inițială; traseul de schimbare A → B nu a fost reprodus
prin navigarea obișnuită a interfeței și nu este tratat ca un leak confirmat
prin acel traseu.

Remediere: fiecare operație trebuie legată de o generație a sesiunii/camerei și
de destinatarii inițiali, invalidată la cleanup și reverificată după fiecare
`await` relevant, înainte de randare și trimitere. Finalizarea wipe-ului local
trebuie să aibă o limită de timp independentă de răspunsul logout-ului. Adăugați
teste de browser cu import/curățare întârziate și Panic în timpul lor.

### 4. P2 — JPEG/PNG/video cu MIME gol sau generic sar peste curățarea metadatelor

**Remediat:** fallback-ul include formatele foto/video suportate; curățarea
verifică semnătura binară și păstrează MIME-ul normalizat în rezultatul trimis.
`test/scrub.selftest.mjs` verifică eliminarea efectivă a metadatelor cu MIME
corect/gol/generic și respingerea conținutului incompatibil cu tipul declarat.

Locuri: `web/js/scrub.js:45`, `:52`, `:94`; `web/js/app.js:1993`.

Fallback-ul după extensie acoperă HEIC/AVIF/TIFF, documente și PDF, dar nu
`jpg`, `jpeg`, `png`, `webp`, `gif`, `mp4`, `mov` sau `m4a`. Dacă browserul furnizează
`File.type === ''` ori `application/octet-stream`, aceste fișiere sunt tratate
ca nesuportate și se trimit fără scrub, deși opțiunea este activă.

Reproducere pe modulul original în Node: pentru un `File` numit
`IMG_20261111_121212.jpg`, `isScrubbable()` întoarce **false** pentru ambele
tipuri MIME menționate. Decizia precedă citirea conținutului, deci nu depinde de
ce metadate conține imaginea. Un JPEG pe care browserul îl etichetează corect
`image/jpeg` urmează calea de curățare.

Remediere: completați extensiile pentru toate formatele suportate și verificați
semnătura binară înainte de curățare. O nepotrivire de tip trebuie explicată,
fără a prezenta fișierul drept curățat. Matricea de teste trebuie să includă
MIME corect, gol și generic pentru fiecare format.

## Verificare suplimentară — operații reluate după cleanup

Revizie verificată: `f4c9115a255271419384500999a49366d1b0a4f8` (0.7.1).
Cu răspunsurile de rețea și logout-ul întârziate controlat în Chromium, Panic
golea ecranul, dar un challenge SRP primit ulterior putea continua autentificarea
și redeschide ecranul contului. Un răspuns întârziat de creare a camerei putea
deschide un WebSocket nou și afișa din nou invitația. Patru aserțiuni din testul
extins `browser.privacy.mjs` au eșuat pe clientul 0.7.1.

**Remediat:** operațiile de autentificare, reautentificare, modificare de cont,
creare/intrare în cameră și încărcare TURN folosesc un semnal de anulare legat de
sesiunea locală. Cleanup îl invalidează înainte să elimine starea. Cererile în
curs sunt întrerupte, iar rezultatele operațiilor care nu pot fi întrerupte, precum
derivarea parolei, sunt verificate înaintea următoarei cereri sau modificări UI.
Așteptarea mesajului WebSocket de bun venit se încheie și la anulare; operațiile
vechi nu pot elibera blocajul unei acțiuni noi sau relua reconectarea. Mesajele de
signaling care așteaptă configurația TURN verifică din nou generația conexiunii.

Regresiile suplimentare verifică și o derivare de parolă întârziată și un răspuns
de cameră livrat după logout obișnuit, fără a se baza pe flag-ul Panic. Anularea
locală nu retrage o modificare pe care serverul a procesat-o deja și nu înlocuiește
revocarea server-side a sesiunii.

## Ce este bine construit

- Backend mic, cu o singură dependență Go directă; conținutul conversațiilor
  circulă între browsere, iar serverul persistă credențiale și invitații.
- Chei de trafic separate pe direcții și contexte, AEAD cu versiune/epocă,
  replay tracking, commit/reveal și blocarea traficului până la confirmare reciprocă.
  Certificatul DTLS al apelului este legat de sesiunea criptată.
- Identitatea persistentă este opt-in, cu dovadă de posesie înainte de folosirea
  contactelor salvate; cheia privată WebCrypto nu este extractabilă prin API.
- CSP strict, construcție DOM fără HTML din mesaje, fișiere active excluse din
  preview, nume de fișiere normalizate și bugete pentru memorie/cozi.
- Bundle încorporat în executabil, manifest, SRI/import-map integrity și cod
  vendorizat verificat față de upstream. Acestea ajută integritatea și supply
  chain-ul; documentația recunoaște corect limita în fața HTML/JS malițios servit
  de origine.
- Limite explicite de resurse, JSON strict, protecții de origine, cookie-uri
  HttpOnly/SameSite și trust boundary separat pentru onion. Rate limiting-ul
  folosește etichete HMAC efemere în locul unor liste de IP-uri persistate.
- CI cu race detector, fuzzing, vectori NIST, clienți ostili și mai multe motoare
  de browser. Scanarea zilnică de vulnerabilități tocmai și-a demonstrat utilitatea.

## Limite de privacy și priorități de arhitectură

| Componentă | Ce poate observa sau păstra |
| --- | --- |
| Serverul de aplicație | Conturi și verifiere persistente; în funcționare, legături între sesiuni, surse, camere și signaling SDP/ICE. |
| Cloudflare / terminatorul TLS | Traficul HTTP/WebSocket de pe calea clearnet și codul livrat; poate modifica clientul livrat dacă este compromis sau ostil. |
| TURN / VPS | Endpoint-uri, timing și volum; relay-only ascunde IP-ul față de peer, nu față de relay. |
| Browserul / interlocutorul | Plaintext și fișiere primite; pot păstra copii indiferent de TTL, burn sau ștergere cooperativă. |
| Stocarea locală și backup-urile | Preferințe/limbă și identitate/contacte opționale în browser; backup-uri de conturi cu retenție de aproximativ 14 zile în scriptul livrat. |

Onion separă livrarea paginii/API/signaling de Cloudflare; nu transformă automat
WebRTC în transport prin Tor. Cover traffic-ul ocazional și padding-ul nu ascund
graful conversațiilor, volumul sau timing-ul. Rekey-ul la zece minute păstrează
epoca curentă și două anterioare; nu echivalează cu o garanție formală Double Ratchet.
Aceste limite sunt în mare parte descrise corect în README.

Îmbunătățirile secundare au fost incluse: preferințele și limba se șterg direct,
fără a depinde de `Clear-Site-Data`; retenția conturilor șterse în backup-uri este
explicată în ambele versiuni ale paginii de securitate și în DEPLOY.md;
`scripts/deploy.sh` rulează acum și `scrub.selftest.mjs`.

După rezolvarea constatărilor, prioritatea este un audit extern al protocolului
și o strategie de distribuție verificabilă a clientului, dacă adversarul vizat
include operatorul/CDN-ul. `app.js` (~4.100 linii) și handlerul SRP (~1.500 linii)
concentrează multe stări și efecte asincrone; separarea lor în module cu reguli
explicite de anulare ar reduce tocmai clasele de erori găsite aici.

## Validarea reviziei inițiale

- `go vet ./...`, `go build ./...`, `go test -race ./...`: trecute pe Go 1.26.11.
- `govulncheck@v1.6.0 ./...`: nicio vulnerabilitate raportată după actualizare.
- `gosec@v2.27.1`: zero probleme raportate.
- `gitleaks@v8.30.1`, cu redactare, pe 294 commit-uri: nicio scurgere raportată.
- Toate cele 12 self-test-uri Node enumerate în README: trecute.
- Verificarea manifestului și comparația codului vendorizat cu upstream: trecute.
- Flux Chromium cu doi peers reali, SAS identic, verificare reciprocă și transfer
  de fișier: trecut; fallback-ul direct a fost observat în aceeași rulare.
- Reproduceri suplimentare: SRP prin HTTP, Panic cu rețea întârziată în Chromium,
  metodele originale de trimitere cu stare controlată și selecția scrub după MIME.

Safari/Firefox, campaniile de fuzzing de 30 secunde per target și întreaga
matrice browser din GitHub nu au fost rerulate în analiza inițială. Acesta este
un review de cod cu teste țintite, nu o certificare criptografică.

## Validarea remedierilor

- Build, `go vet ./...`, `go test -race ./...`: trecute, inclusiv testele noi de revocare și concurență.
- `govulncheck@v1.6.0`: nicio vulnerabilitate raportată; `gosec@v2.27.1`: zero probleme.
- Toate cele 12 self-test-uri Node, manifestul și verificarea codului vendorizat: trecute.
- Noul test Chromium de privacy și fluxul SRP HTTP: trecute.
- Toate cele nouă suite Chromium trec: privacy, smoke, accesibilitate, suport,
  doi peers, grupuri, apeluri, client ostil și integritatea modulelor.
- Testul de conversie folosește acum un AVIF real, generat ca fixture; un PNG
  etichetat HEIC este refuzat, iar un container HEIC nedecodabil cere în continuare
  acordul utilizatorului înainte de trimiterea originalului.
- Verificarea metodelor originale de trimitere confirmă că o schimbare de cameră
  abandonează fișierul și că deconectarea destinatarului eliberează contorul de transfer.
- Firefox și Safari nu sunt disponibile în mediul local. Suitele găzduite pentru
  Gecko, boot Safari și Safari–Chrome au trecut în CI; aleg explicit transportul
  direct, deoarece runner-ele nu au TURN.
