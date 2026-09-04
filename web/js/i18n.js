/**
 * Dead Drop — minimal i18n (English / Romanian).
 *
 * Static markup is translated via data-i18n / data-i18n-ph / data-i18n-title
 * attributes; dynamic strings use t(key). The only thing persisted is the chosen
 * language (localStorage), which carries no private data.
 */

const STRINGS = {
  en: {
    'tagline': 'Pseudonymous · Verified E2EE · Ephemeral',
    'boot.checking': 'Checking this browser…',
    'err.serverAuth': 'Server authentication failed — do not trust this connection.',
    'err.connection': 'Connection failed',
    'err.shortPassword': 'Password must be at least 8 characters',
    'err.roomCreate': 'Failed to create room',
    'err.signaling': 'Failed to connect to signaling server',
    'err.roomCode': 'Invalid room code',
    'err.fileTooLarge': 'File too large',
    'err.fileFailed': 'File transfer failed for at least one peer',
    'err.micDenied': 'Microphone access denied',
    'err.messageTooLarge': 'Message too large',
    'err.fileTransfer': 'File transfer failed',
    'err.fileDecrypt': 'Failed to decrypt file',
    'err.media': 'Failed to access camera/microphone',
    'call.calling': 'Calling…',
    'call.connecting': 'Connecting…',
    'call.connectingMedia': 'Connecting media…',
    'call.declined': 'Call declined',
    'call.ended': 'Call ended',
    'aria.settings': 'Account settings',
    'aria.copyCode': 'Copy the room code',
    'aria.copyLink': 'Copy the invite link',
    'aria.call': 'Start a call',
    'aria.panic': 'Panic — clear this tab and log out',
    'aria.attach': 'Attach a file',
    'aria.record': 'Record a voice message',
    'aria.mic': 'Mute or unmute the microphone',
    'aria.cam': 'Turn the camera on or off',
    'aria.backToChat': 'Back to the conversation',
    'aria.endCall': 'End the call',
    'aria.language': 'Change language',
    'aria.transcript': 'Conversation',
    'aria.qrVerify': 'Verify by QR code',
    'aria.incomingCall': 'Incoming call',
    'aria.callOverlay': 'Call in progress',
    'aria.account': 'Account settings',
    'intro.title': 'What this is',
    'intro.lead': 'Dead Drop is a browser-based chat that carries messages directly '
      + 'between two people. The server introduces you and then has nothing to relay: '
      + 'no message, file, or call ever passes through it, and none is stored anywhere.',
    'intro.verifiedTitle': 'Verified, not assumed.',
    'intro.verified': 'Both sides compare a six-emoji safety code before anything can be '
      + 'sent. Until they match, the app refuses to send — which is what separates '
      + 'encryption you can check from encryption you are promised.',
    'intro.pqTitle': 'Post-quantum handshake.',
    'intro.pq': 'Keys are agreed with classical P-256 and ML-KEM-768 together, so a '
      + 'recording made today is not opened by a quantum computer later.',
    'intro.nothingTitle': 'Nothing kept.',
    'intro.nothing': 'No email, no phone number, no message history, no password on the '
      + 'server — logging in proves the password without sending it. Registration needs an invite.',
    'intro.limits': 'It does not make you anonymous. The service can still see who '
      + 'connects, when, and to whom — and it says so plainly rather than leaving you to find out.',
    'msg.peerRemoved': 'The other side removed a message',
    'boot.unsupported': 'This browser cannot run Dead Drop safely.',
    'boot.explain': 'Everything protecting a conversation runs in your browser, '
      + 'and this one is missing something it needs. Rather than take your password '
      + 'and encrypt nothing, Dead Drop stops here.',
    'boot.suggest': 'A current Firefox, Safari, Chrome or Edge will work.',
    'boot.degraded': 'Not available in this browser',
    'boot.stillSafe': 'Messages are protected either way.',
    'auth.user': 'Username',
    'auth.pass': 'Password',
    'auth.invite': 'Invite code (only to register)',
    'auth.login': 'Login',
    'auth.register': 'Register',
    'auth.hint': 'The password never leaves your browser — login proves it with SRP. No email. No recovery. Registration needs an invite code.',
    'auth.hintOpen': 'The password never leaves your browser — login proves it with SRP. No email or recovery. Registration is open.',
    'about.link': '🔐 How your privacy is protected',
    'about.link.short': '🔐 Security & privacy',
    'verify.code.link': "🔎 Verify the code you're running",
    'landing.create': 'Create Room',
    'landing.or': 'or',
    'landing.code': 'Room code',
    'landing.join': 'Join',
    'relay.label': '🛡️ Hide IP from peer',
    'relay.sub': '— TURN relay; VPS still sees it',
    'cover.label': '🕶️ Cover traffic',
    'cover.sub': '— occasional decoys; does not hide traffic volume',
    'logout': 'Logout',
    'chat.burn': '🔥 Burn',
    'chat.ttl.none': 'No TTL',
    'chat.msg': 'Type a message…',
    'chat.send': 'Send',
    'verify.label': '🔐 Safety code',
    'verify.btn': 'Codes match — trust',
    'verify.waitingPeer': '✓ Waiting for peer',
    'verify.confirm': 'Did you compare this code with your peer over a separate trusted channel and confirm an exact match?',
    'verify.hint': "Compare this over a separate trusted channel. Chat, files, and calls stay locked until you confirm an exact match. If they differ, stop.",
    'privacy.hidden': 'Hidden while this tab is in the background',
    'privacy.reveal': 'Tap to reveal',
    'typing': 'peer is typing…',
    'call.incoming': 'Incoming call…',
    'call.accept': 'Accept',
    'call.reject': 'Reject',
    'st.waiting': '⏳ Waiting for peer…',
    'st.encrypted': '🔒 E2E Encrypted',
    'st.encryptedN': '🔒 E2E — {n} peers',
    'st.unverified': '⚠️ Encrypted, peer identity not verified',
    'st.verified': '🔒 E2EE · peer verified',
    'st.verifiedN': '🔒 E2EE · {n} verified peers',
    'st.peerLeft': '👋 Peer disconnected',
    'sys.joined': 'joined with encryption — verify the safety code before trust',
    'sys.awaitVerify': 'connected with encryption, but is not authenticated yet — compare the safety code',
    'sys.verified': 'identity verified — messaging is now unlocked',
    'sys.waitPeerVerify': 'code confirmed locally — waiting for the peer to confirm theirs',
    'sys.left': 'left the room',
    'sys.insecure': 'Secure handshake with {peer} failed — that connection was closed. Do not trust it.',
    'share.intro': 'Send your peer this link (or the code above):',
    'share.copy': 'Copy link',
    'share.copied': '✓ Copied',
    'verify.verified': '✓ Verified',
    'lang.toggle': 'RO',
    'duress.ph': 'Duress password (decoy)',
    'duress.set': 'Set duress password',
    'duress.saved': '✓ Saved',
    'account.delete': 'Delete account',
    'account.confirmDelete': 'Delete your account permanently?',
    'contacts.label': '🔖 Saved contacts',
    'contacts.sub': '— verify a person once instead of every session; they can tell your sessions apart',
    'contacts.on': 'Saved contacts are on. Peers you save can recognise you across rooms.',
    'contacts.off': 'Saved contacts are off. Every session stays unlinkable and needs its own safety-code check.',
    'contacts.none': 'No saved contacts yet.',
    'contacts.confirmOff': 'Turn off saved contacts? This deletes your identity key and every saved contact. People who saved you will no longer recognise you.',
    'contacts.forget': 'Forget',
    'contact.recognised': 'is a saved contact — unlocked without a new check',
    'contact.savePrompt': 'Save this contact under what name?',
    'contact.saved': 'saved. Future sessions unlock without a new safety-code check.',
    'contact.saveFailed': 'Could not save this contact.',
    'account.currentPh': 'Current password',
    'account.reauthHint': 'Both actions re-check your current password, so an open session alone cannot change or destroy the account.',
    'account.needCurrent': 'Enter your current password first',
    'account.wrongCurrent': 'Wrong current password',
    'duress.hint': 'Optional decoy login. The server knows the session type, and active coercion or forensics can defeat it.',
    'verify.qr': '📷 QR',
    'qr.title': '📷 QR verification',
    'qr.hint': "Scan your peer's screen over a trusted in-person path. An exact match authenticates this encrypted session.",
    'qr.close': 'Close',
    'qr.scanning': 'Scanning…',
    'qr.match': '✓ Codes match — waiting for the peer to confirm too',
    'qr.mismatch': '⛔ CODES DIFFER — the line may be intercepted. Stop.',
    'qr.cameraFail': 'Camera unavailable — compare the emoji code instead',
  },
  ro: {
    'tagline': 'Pseudonim · E2EE verificat · Efemer',
    'boot.checking': 'Se verifică browserul…',
    'err.serverAuth': 'Autentificarea serverului a eșuat — nu avea încredere în această conexiune.',
    'err.connection': 'Conexiune eșuată',
    'err.shortPassword': 'Parola trebuie să aibă cel puțin 8 caractere',
    'err.roomCreate': 'Camera nu a putut fi creată',
    'err.signaling': 'Conectarea la serverul de semnalizare a eșuat',
    'err.roomCode': 'Cod de cameră invalid',
    'err.fileTooLarge': 'Fișier prea mare',
    'err.fileFailed': 'Transferul fișierului a eșuat pentru cel puțin un participant',
    'err.micDenied': 'Accesul la microfon a fost refuzat',
    'err.messageTooLarge': 'Mesaj prea mare',
    'err.fileTransfer': 'Transferul fișierului a eșuat',
    'err.fileDecrypt': 'Fișierul nu a putut fi decriptat',
    'err.media': 'Camera sau microfonul nu au putut fi accesate',
    'call.calling': 'Se apelează…',
    'call.connecting': 'Se conectează…',
    'call.connectingMedia': 'Se conectează media…',
    'call.declined': 'Apel refuzat',
    'call.ended': 'Apel încheiat',
    'aria.settings': 'Setările contului',
    'aria.copyCode': 'Copiază codul camerei',
    'aria.copyLink': 'Copiază linkul de invitație',
    'aria.call': 'Începe un apel',
    'aria.panic': 'Panică — șterge acest tab și deconectează-te',
    'aria.attach': 'Atașează un fișier',
    'aria.record': 'Înregistrează un mesaj vocal',
    'aria.mic': 'Pornește sau oprește microfonul',
    'aria.cam': 'Pornește sau oprește camera',
    'aria.backToChat': 'Înapoi la conversație',
    'aria.endCall': 'Încheie apelul',
    'aria.language': 'Schimbă limba',
    'aria.transcript': 'Conversație',
    'aria.qrVerify': 'Verificare prin cod QR',
    'aria.incomingCall': 'Apel primit',
    'aria.callOverlay': 'Apel în desfășurare',
    'aria.account': 'Setările contului',
    'intro.title': 'Ce este',
    'intro.lead': 'Dead Drop e un chat din browser care duce mesajele direct între doi '
      + 'oameni. Serverul vă face cunoștință și apoi nu mai are ce transporta: niciun '
      + 'mesaj, fișier sau apel nu trece prin el și nimic nu se stochează nicăieri.',
    'intro.verifiedTitle': 'Verificat, nu presupus.',
    'intro.verified': 'Ambele părți compară un cod de siguranță din șase emoji înainte '
      + 'să se poată trimite ceva. Până când se potrivesc, aplicația refuză să trimită — '
      + 'asta desparte criptarea pe care o poți verifica de cea care ți-e doar promisă.',
    'intro.pqTitle': 'Handshake post-cuantic.',
    'intro.pq': 'Cheile se stabilesc cu P-256 clasic și ML-KEM-768 împreună, deci o '
      + 'înregistrare făcută azi nu se deschide mai târziu cu un calculator cuantic.',
    'intro.nothingTitle': 'Nimic păstrat.',
    'intro.nothing': 'Fără email, fără număr de telefon, fără istoric, fără parolă pe '
      + 'server — autentificarea dovedește parola fără s-o trimită. Înregistrarea cere o invitație.',
    'intro.limits': 'Nu te face anonim. Serviciul tot poate vedea cine se conectează, '
      + 'când și cu cine — și o spune direct, în loc să te lase să afli singur.',
    'msg.peerRemoved': 'Interlocutorul a șters un mesaj',
    'boot.unsupported': 'Acest browser nu poate rula Dead Drop în siguranță.',
    'boot.explain': 'Tot ce protejează o conversație rulează în browserul tău, '
      + 'iar acestuia îi lipsește ceva de care are nevoie. În loc să îți ia parola '
      + 'și să nu cripteze nimic, Dead Drop se oprește aici.',
    'boot.suggest': 'Un Firefox, Safari, Chrome sau Edge recent va funcționa.',
    'boot.degraded': 'Indisponibil în acest browser',
    'boot.stillSafe': 'Mesajele sunt protejate oricum.',
    'auth.user': 'Utilizator',
    'auth.pass': 'Parolă',
    'auth.invite': 'Cod de invitație (doar pentru înregistrare)',
    'auth.login': 'Autentificare',
    'auth.register': 'Înregistrare',
    'auth.hint': 'Parola nu îți părăsește browserul — autentificarea o dovedește prin SRP. Fără email sau recuperare. Înregistrarea cere invitație.',
    'auth.hintOpen': 'Parola nu îți părăsește browserul — autentificarea o dovedește prin SRP. Fără email sau recuperare. Înregistrarea este deschisă.',
    'about.link': '🔐 Cum îți este protejată confidențialitatea',
    'about.link.short': '🔐 Securitate & confidențialitate',
    'verify.code.link': '🔎 Verifică codul care rulează',
    'landing.create': 'Creează cameră',
    'landing.or': 'sau',
    'landing.code': 'Cod cameră',
    'landing.join': 'Intră',
    'relay.label': '🛡️ Ascunde IP-ul de partener',
    'relay.sub': '— relay TURN; VPS-ul încă îl vede',
    'cover.label': '🕶️ Trafic de acoperire',
    'cover.sub': '— momeli ocazionale; nu ascund volumul traficului',
    'logout': 'Deconectare',
    'chat.burn': '🔥 Ardere',
    'chat.ttl.none': 'Fără TTL',
    'chat.msg': 'Scrie un mesaj…',
    'chat.send': 'Trimite',
    'verify.label': '🔐 Cod de siguranță',
    'verify.btn': 'Codurile coincid — am încredere',
    'verify.waitingPeer': '✓ Aștept confirmarea',
    'verify.confirm': 'Ai comparat acest cod cu partenerul printr-un canal separat de încredere și ai confirmat că este identic?',
    'verify.hint': 'Compară-l printr-un canal separat de încredere. Chatul, fișierele și apelurile rămân blocate până confirmi potrivirea exactă. Dacă diferă, oprește-te.',
    'privacy.hidden': 'Ascuns cât timp fila e în fundal',
    'privacy.reveal': 'Atinge pentru a dezvălui',
    'typing': 'partenerul scrie…',
    'call.incoming': 'Apel în curs…',
    'call.accept': 'Acceptă',
    'call.reject': 'Respinge',
    'st.waiting': '⏳ Se așteaptă partenerul…',
    'st.encrypted': '🔒 Criptat E2E',
    'st.encryptedN': '🔒 E2E — {n} parteneri',
    'st.unverified': '⚠️ Criptat, identitatea partenerului neverificată',
    'st.verified': '🔒 E2EE · partener verificat',
    'st.verifiedN': '🔒 E2EE · {n} parteneri verificați',
    'st.peerLeft': '👋 Partener deconectat',
    'sys.joined': 's-a conectat criptat — verifică codul înainte să ai încredere',
    'sys.awaitVerify': 's-a conectat criptat, dar nu este încă autentificat — compară codul de siguranță',
    'sys.verified': 'identitate verificată — mesageria este acum deblocată',
    'sys.waitPeerVerify': 'cod confirmat local — se așteaptă confirmarea partenerului',
    'sys.left': 'a părăsit camera',
    'sys.insecure': 'Handshake-ul securizat cu {peer} a eșuat — conexiunea a fost închisă. Nu avea încredere în ea.',
    'share.intro': 'Trimite-i partenerului acest link (sau codul de mai sus):',
    'share.copy': 'Copiază linkul',
    'share.copied': '✓ Copiat',
    'verify.verified': '✓ Verificat',
    'lang.toggle': 'EN',
    'duress.ph': 'Parolă duress (decoy)',
    'duress.set': 'Setează parola duress',
    'duress.saved': '✓ Salvat',
    'account.delete': 'Șterge contul',
    'account.confirmDelete': 'Ștergi contul definitiv?',
    'contacts.label': '🔖 Contacte salvate',
    'contacts.sub': '— verifici o persoană o singură dată, nu la fiecare sesiune; te poate corela între sesiuni',
    'contacts.on': 'Contactele salvate sunt active. Cine te salvează te poate recunoaște între camere.',
    'contacts.off': 'Contactele salvate sunt oprite. Fiecare sesiune rămâne necorelabilă și cere propria verificare.',
    'contacts.none': 'Niciun contact salvat încă.',
    'contacts.confirmOff': 'Oprești contactele salvate? Se șterge cheia ta de identitate și toate contactele. Cine te-a salvat nu te va mai recunoaște.',
    'contacts.forget': 'Uită',
    'contact.recognised': 'este un contact salvat — deblocat fără verificare nouă',
    'contact.savePrompt': 'Sub ce nume salvezi acest contact?',
    'contact.saved': 'salvat. Sesiunile viitoare se deblochează fără verificare nouă.',
    'contact.saveFailed': 'Nu am putut salva contactul.',
    'account.currentPh': 'Parola curentă',
    'account.reauthHint': 'Ambele acțiuni recer parola curentă, deci o sesiune deschisă singură nu poate schimba sau distruge contul.',
    'account.needCurrent': 'Introdu întâi parola curentă',
    'account.wrongCurrent': 'Parola curentă este greșită',
    'duress.hint': 'Login decoy opțional. Serverul știe tipul sesiunii, iar constrângerea activă sau analiza dispozitivului îl pot demasca.',
    'verify.qr': '📷 QR',
    'qr.title': '📷 Verificare prin QR',
    'qr.hint': 'Scanează ecranul partenerului pe un canal fizic de încredere. Potrivirea exactă autentifică această sesiune criptată.',
    'qr.close': 'Închide',
    'qr.scanning': 'Se scanează…',
    'qr.match': '✓ Codurile se potrivesc — se așteaptă și confirmarea partenerului',
    'qr.mismatch': '⛔ CODURILE DIFERĂ — linia poate fi interceptată. Oprește-te.',
    'qr.cameraFail': 'Camera nu e disponibilă — compară codul emoji în schimb',
  },
};

let lang = detect();

export function t(key, fallback) {
  return (STRINGS[lang] && STRINGS[lang][key]) || STRINGS.en[key] || fallback || key;
}

export function getLang() { return lang; }

export function setLang(l) {
  if (!STRINGS[l]) return;
  lang = l;
  try { localStorage.setItem('dd_lang', l); } catch { /* storage may be blocked */ }
  applyI18n();
}

export function applyI18n() {
  document.documentElement.lang = lang;
  document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.dataset.i18n); });
  document.querySelectorAll('[data-i18n-ph]').forEach((el) => { el.placeholder = t(el.dataset.i18nPh); });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => { el.title = t(el.dataset.i18nTitle); });
  // Accessible names for controls whose only visible content is an icon. Without
  // these a screen reader announces the emoji — "skull" for the panic button —
  // which is worse than silence because it sounds like information.
  document.querySelectorAll('[data-i18n-aria]').forEach((el) => {
    el.setAttribute('aria-label', t(el.dataset.i18nAria));
  });
}

function detect() {
  try {
    const saved = localStorage.getItem('dd_lang');
    if (saved && STRINGS[saved]) return saved;
  } catch { /* ignore */ }
  return (navigator.language || 'en').toLowerCase().startsWith('ro') ? 'ro' : 'en';
}
