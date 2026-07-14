/**
 * Dead Drop — minimal i18n (English / Romanian).
 *
 * Static markup is translated via data-i18n / data-i18n-ph / data-i18n-title
 * attributes; dynamic strings use t(key). The only thing persisted is the chosen
 * language (localStorage), which carries no private data.
 */

const STRINGS = {
  en: {
    'tagline': 'Anonymous · Encrypted · Ephemeral',
    'auth.user': 'Username',
    'auth.pass': 'Password',
    'auth.invite': 'Invite code (only to register)',
    'auth.login': 'Login',
    'auth.register': 'Register',
    'auth.hint': 'Zero-knowledge login (SRP) — your password never leaves this device. No email. No recovery. Registration needs an invite code.',
    'auth.hintOpen': 'Zero-knowledge login (SRP) — your password never leaves this device. No email, no recovery. Registration is open — just pick a handle and a password.',
    'about.link': '🔐 How your privacy is protected',
    'about.link.short': '🔐 Security & privacy',
    'verify.code.link': "🔎 Verify the code you're running",
    'landing.create': 'Create Room',
    'landing.or': 'or',
    'landing.code': 'Room code',
    'landing.join': 'Join',
    'relay.label': '🛡️ Max anonymity',
    'relay.sub': '— relay via server, hide IP from peer',
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
    'sys.joined': 'joined — end-to-end encrypted',
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
    'duress.hint': 'Optional: a second password that also logs in (to a decoy). Hand it over under coercion without revealing your real one.',
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
    'tagline': 'Anonim · Criptat · Efemer',
    'auth.user': 'Utilizator',
    'auth.pass': 'Parolă',
    'auth.invite': 'Cod de invitație (doar pentru înregistrare)',
    'auth.login': 'Autentificare',
    'auth.register': 'Înregistrare',
    'auth.hint': 'Login zero-knowledge (SRP) — parola nu părăsește niciodată acest dispozitiv. Fără email. Fără recuperare. Înregistrarea cere un cod de invitație.',
    'auth.hintOpen': 'Login zero-knowledge (SRP) — parola nu părăsește niciodată acest dispozitiv. Fără email, fără recuperare. Înregistrarea e deschisă — alege-ți un nume și o parolă.',
    'about.link': '🔐 Cum îți este protejată confidențialitatea',
    'about.link.short': '🔐 Securitate & confidențialitate',
    'verify.code.link': '🔎 Verifică codul care rulează',
    'landing.create': 'Creează cameră',
    'landing.or': 'sau',
    'landing.code': 'Cod cameră',
    'landing.join': 'Intră',
    'relay.label': '🛡️ Anonimat maxim',
    'relay.sub': '— prin server, ascunde IP-ul de peer',
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
    'sys.joined': 's-a conectat — criptat end-to-end',
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
    'duress.hint': 'Opțional: o a doua parolă care tot te loghează (într-un decoy). O dai sub constrângere fără să dezvălui parola reală.',
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
}

function detect() {
  try {
    const saved = localStorage.getItem('dd_lang');
    if (saved && STRINGS[saved]) return saved;
  } catch { /* ignore */ }
  return (navigator.language || 'en').toLowerCase().startsWith('ro') ? 'ro' : 'en';
}
