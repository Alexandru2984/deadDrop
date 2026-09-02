/**
 * Dead Drop — what this browser must be able to do.
 *
 * Everything protecting a conversation runs in the browser, so a missing
 * primitive is not a cosmetic problem: it is the difference between an
 * encrypted session and a broken one. Until now the app assumed every
 * capability it uses and simply failed wherever the assumption did not hold —
 * on a browser without WebCrypto that means a page that looks alive, takes a
 * password, and cannot protect anything.
 *
 * So the requirements are checked before the app starts, and a browser that
 * cannot meet them is told plainly rather than handed a form.
 *
 * The probes actually run the algorithms. Feature detection by `typeof` finds
 * the names, and the names have been present on engines where the operation
 * throws — the useful question is whether a key can be generated, not whether
 * the method exists. Iteration counts here are deliberately trivial: this asks
 * whether an algorithm is implemented, not how fast it is.
 */

/** Required: without any of these there is no secure session to offer. */
const REQUIRED = [
  {
    id: 'secure-context',
    label: 'a secure origin (HTTPS, .onion or localhost)',
    probe: () => (globalThis.isSecureContext === true ? true : 'this page was not loaded over HTTPS'),
  },
  {
    id: 'webcrypto',
    label: 'the Web Crypto API',
    probe: () => (globalThis.crypto?.subtle ? true : 'crypto.subtle is unavailable'),
  },
  {
    id: 'ecdh',
    label: 'ECDH on P-256 (handshake key agreement)',
    probe: async () => {
      const pair = await crypto.subtle.generateKey(
        { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveBits']);
      await crypto.subtle.deriveBits(
        { name: 'ECDH', public: pair.publicKey }, pair.privateKey, 256);
      return true;
    },
  },
  {
    id: 'ecdsa',
    label: 'ECDSA on P-256 (identity signatures)',
    probe: async () => {
      const pair = await crypto.subtle.generateKey(
        { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, new Uint8Array(8));
      return true;
    },
  },
  {
    id: 'aes-gcm',
    label: 'AES-256-GCM (message encryption)',
    probe: async () => {
      const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, false, ['encrypt']);
      await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv: new Uint8Array(12) }, key, new Uint8Array(4));
      return true;
    },
  },
  {
    id: 'hkdf',
    label: 'HKDF (key derivation)',
    probe: async () => {
      const key = await crypto.subtle.importKey('raw', new Uint8Array(32), 'HKDF', false, ['deriveBits']);
      await crypto.subtle.deriveBits(
        { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new Uint8Array(0) }, key, 256);
      return true;
    },
  },
  {
    id: 'pbkdf2',
    label: 'PBKDF2 (password stretching)',
    probe: async () => {
      const key = await crypto.subtle.importKey('raw', new Uint8Array(8), 'PBKDF2', false, ['deriveBits']);
      await crypto.subtle.deriveBits(
        { name: 'PBKDF2', hash: 'SHA-256', salt: new Uint8Array(8), iterations: 1 }, key, 256);
      return true;
    },
  },
  {
    id: 'webrtc',
    label: 'WebRTC data channels (the peer-to-peer transport)',
    probe: () => {
      if (typeof RTCPeerConnection !== 'function') return 'RTCPeerConnection is unavailable';
      const pc = new RTCPeerConnection();
      try {
        if (typeof pc.createDataChannel !== 'function') return 'data channels are unsupported';
        pc.createDataChannel('probe');
        return true;
      } finally {
        pc.close();
      }
    },
  },
  {
    id: 'websocket',
    label: 'WebSocket (signaling)',
    probe: () => (typeof WebSocket === 'function' ? true : 'WebSocket is unavailable'),
  },
];

/**
 * Optional: the session is still fully protected without these, so refusing to
 * run would cost the user security rather than buy it. Reported, not enforced.
 */
const OPTIONAL = [
  {
    id: 'indexeddb',
    label: 'saved contacts',
    why: 'this browser has no usable IndexedDB, so contacts cannot be remembered between sessions',
    probe: () => typeof indexedDB === 'object' && indexedDB !== null,
  },
  {
    id: 'media',
    label: 'audio and video calls',
    why: 'this browser exposes no camera or microphone API',
    probe: () => typeof navigator.mediaDevices?.getUserMedia === 'function',
  },
  {
    id: 'trusted-types',
    label: 'Trusted Types hardening',
    why: 'this browser does not enforce Trusted Types, so one class of scripting bug is caught by review alone',
    probe: () => typeof globalThis.trustedTypes === 'object',
  },
];

async function run(check) {
  try {
    const result = await check.probe();
    return result === true ? null : (typeof result === 'string' ? result : 'unsupported');
  } catch (err) {
    return err?.message ? String(err.message) : 'threw';
  }
}

/**
 * @returns {Promise<{ok: boolean, missing: Array, degraded: Array}>}
 *   `missing` is fatal; `degraded` is worth telling the user about and no more.
 */
export async function checkSupport() {
  const missing = [];
  for (const check of REQUIRED) {
    const reason = await run(check);
    if (reason) missing.push({ id: check.id, label: check.label, reason });
  }

  const degraded = [];
  for (const check of OPTIONAL) {
    if (await run(check)) degraded.push({ id: check.id, label: check.label, why: check.why });
  }

  return { ok: missing.length === 0, missing, degraded };
}
