/** Shared helpers for base64 ↔ ArrayBuffer conversion. */

export function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

export function b64ToBuf(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes.buffer;
}

const ICE_URL_RE = /^(stun|stuns|turn|turns):(\[[0-9a-f:.]+\]|[a-z0-9.-]+)(?::(\d{1,5}))?(?:\?transport=(udp|tcp))?$/i;

/** Validate the bounded STUN/TURN response before handing it to WebRTC. */
export function sanitizeIceConfig(data, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (!data || typeof data !== 'object' || !Array.isArray(data.iceServers)
      || data.iceServers.length > 2 || !Number.isInteger(data.ttl)
      || data.ttl < 300 || data.ttl > 7200) {
    throw new Error('Invalid ICE configuration');
  }
  const iceServers = data.iceServers.map((entry) => {
    if (!entry || typeof entry !== 'object' || !Array.isArray(entry.urls)
        || entry.urls.length < 1 || entry.urls.length > 8) {
      throw new Error('Invalid ICE server entry');
    }
    let kind = null;
    const urls = entry.urls.map((raw) => {
      if (typeof raw !== 'string' || raw.length > 512) throw new Error('Invalid ICE URL');
      const match = ICE_URL_RE.exec(raw);
      if (!match) throw new Error('Invalid ICE URL');
      const scheme = match[1].toLowerCase();
      const currentKind = scheme.startsWith('turn') ? 'turn' : 'stun';
      if (kind && kind !== currentKind) throw new Error('Mixed ICE URL types');
      kind = currentKind;
      if (match[3] && (Number(match[3]) < 1 || Number(match[3]) > 65535)) {
        throw new Error('Invalid ICE port');
      }
      if (currentKind === 'stun' && match[4]) throw new Error('STUN transport query is invalid');
      if (!validIceHost(match[2])) throw new Error('Invalid ICE host');
      return raw;
    });
    if (kind === 'turn') {
      const usernameMatch = typeof entry.username === 'string'
        ? /^(\d{10,12}):[0-9a-f]{16}$/.exec(entry.username)
        : null;
      if (!usernameMatch || typeof entry.credential !== 'string'
          || !/^[A-Za-z0-9+/]{27}=$/.test(entry.credential)) {
        throw new Error('Invalid TURN credential');
      }
      const expiry = Number(usernameMatch[1]);
      if (Math.abs(expiry - nowSeconds - data.ttl) > 60) throw new Error('Invalid TURN expiry');
      return { urls, username: entry.username, credential: entry.credential };
    }
    if (entry.username || entry.credential) throw new Error('Unexpected STUN credential');
    return { urls };
  });
  return { iceServers, ttl: data.ttl };
}

function validIceHost(host) {
  if (host.startsWith('[')) return host.endsWith(']') && host.includes(':');
  if (host.length < 1 || host.length > 253) return false;
  if (/^[0-9.]+$/.test(host)) {
    const octets = host.split('.');
    return octets.length === 4 && octets.every((part) => /^\d{1,3}$/.test(part) && Number(part) <= 255);
  }
  return host.split('.').every((label) => label.length >= 1 && label.length <= 63
    && /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label));
}

/**
 * Concatenate byte sequences.
 *
 * Lived in three copies — crypto.js, handshake.js and identity.js — and they had
 * already drifted: the identity one wrote its inputs straight into the output,
 * which silently truncates anything handed an ArrayBuffer rather than a typed
 * array. One copy, and it wraps.
 */
export function concatBytes(...parts) {
  const chunks = parts.map((part) => (part instanceof Uint8Array ? part : new Uint8Array(part)));
  const out = new Uint8Array(chunks.reduce((n, c) => n + c.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

// The handful of bases every guessing list tries first. Not a dictionary — a
// verifier stolen from the server is attacked offline with real ones — just the
// shapes that would fall in the first second of that attack.
const OBVIOUS_BASES = [
  'password', 'parola', 'qwerty', 'azerty', 'letmein', 'iloveyou', 'admin',
  'welcome', 'deaddrop', 'abcdef', '123456', '654321', '111111', '000000',
];

/**
 * Why a new password is not good enough, as an i18n key, or null.
 *
 * Applied when a credential is created or changed, never at login: an existing
 * account must still be able to sign in to change it. The bar is length, because
 * the server-side verifier allows offline guessing if it is ever taken, and
 * PBKDF2 only multiplies the cost of each guess.
 */
export function passwordProblem(password, username = '') {
  const pw = String(password || '');
  if ([...pw].length < 12) return 'err.shortPassword';
  const lower = pw.toLowerCase();
  const name = String(username || '').toLowerCase();
  if (name.length >= 3 && lower.includes(name)) return 'err.passwordHasName';
  if (new Set(pw).size < 5) return 'err.passwordSimple';
  const stripped = lower.replace(/[^a-z0-9]/g, '');
  if (OBVIOUS_BASES.some((base) => stripped.includes(base)) && [...pw].length < 20) {
    return 'err.passwordSimple';
  }
  return null;
}

/**
 * A uniformly random integer in [0, n) from the platform CSPRNG. Rejection
 * sampling: taking a random value modulo n would favour the low end whenever n
 * does not divide the range, and a passphrase is only as strong as its least
 * likely word is unlikely.
 */
export function randomBelow(n) {
  if (!Number.isSafeInteger(n) || n < 1 || n > 0x10000) throw new Error('range out of bounds');
  const limit = Math.floor(0x10000 / n) * n;
  const buf = new Uint16Array(1);
  for (;;) {
    crypto.getRandomValues(buf);
    if (buf[0] < limit) return buf[0] % n;
  }
}

/** `count` words drawn independently and uniformly from `words`, hyphenated. */
export function passphrase(words, count = 6) {
  const out = [];
  for (let i = 0; i < count; i++) out.push(words[randomBelow(words.length)]);
  return out.join('-');
}
