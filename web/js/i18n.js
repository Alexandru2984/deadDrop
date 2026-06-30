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
    'about.link': '🔐 How your privacy is protected',
    'about.link.short': '🔐 Security & privacy',
    'landing.create': 'Create Room',
    'landing.or': 'or',
    'landing.code': 'Room code',
    'landing.join': 'Join',
    'relay.label': '🛡️ Max anonymity',
    'relay.sub': '— relay via server, hide IP from peer',
    'logout': 'Logout',
    'chat.burn': '🔥 Burn',
    'chat.ttl.none': 'No TTL',
    'chat.msg': 'Type a message…',
    'chat.send': 'Send',
    'verify.label': '🔐 Safety code',
    'verify.btn': 'Mark verified',
    'verify.hint': "Read this aloud to your peer. If your codes match, no one is intercepting. If they differ, stop — the line is compromised.",
    'privacy.hidden': 'Hidden while this tab is in the background',
    'privacy.reveal': 'Tap to reveal',
    'typing': 'peer is typing…',
    'call.incoming': 'Incoming call…',
    'call.accept': 'Accept',
    'call.reject': 'Reject',
    'st.waiting': '⏳ Waiting for peer…',
    'st.encrypted': '🔒 E2E Encrypted',
    'st.peerLeft': '👋 Peer disconnected',
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
  },
  ro: {
    'tagline': 'Anonim · Criptat · Efemer',
    'auth.user': 'Utilizator',
    'auth.pass': 'Parolă',
    'auth.invite': 'Cod de invitație (doar pentru înregistrare)',
    'auth.login': 'Autentificare',
    'auth.register': 'Înregistrare',
    'auth.hint': 'Login zero-knowledge (SRP) — parola nu părăsește niciodată acest dispozitiv. Fără email. Fără recuperare. Înregistrarea cere un cod de invitație.',
    'about.link': '🔐 Cum îți este protejată confidențialitatea',
    'about.link.short': '🔐 Securitate & confidențialitate',
    'landing.create': 'Creează cameră',
    'landing.or': 'sau',
    'landing.code': 'Cod cameră',
    'landing.join': 'Intră',
    'relay.label': '🛡️ Anonimat maxim',
    'relay.sub': '— prin server, ascunde IP-ul de peer',
    'logout': 'Deconectare',
    'chat.burn': '🔥 Ardere',
    'chat.ttl.none': 'Fără TTL',
    'chat.msg': 'Scrie un mesaj…',
    'chat.send': 'Trimite',
    'verify.label': '🔐 Cod de siguranță',
    'verify.btn': 'Marchează verificat',
    'verify.hint': 'Citește-l cu voce tare partenerului. Dacă se potrivesc, nimeni nu interceptează. Dacă diferă, oprește-te — linia e compromisă.',
    'privacy.hidden': 'Ascuns cât timp fila e în fundal',
    'privacy.reveal': 'Atinge pentru a dezvălui',
    'typing': 'partenerul scrie…',
    'call.incoming': 'Apel în curs…',
    'call.accept': 'Acceptă',
    'call.reject': 'Respinge',
    'st.waiting': '⏳ Se așteaptă partenerul…',
    'st.encrypted': '🔒 Criptat E2E',
    'st.peerLeft': '👋 Partener deconectat',
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
