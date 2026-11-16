/**
 * What the parts of the app share: limits, small DOM and text helpers, and
 * the lazily loaded file cleaner. app.js and every app-*.js file import
 * from here.
 */

import { DEFAULT_KDF } from './srp.js';
import { t } from './i18n.js';

// The code that cleans a file is a sixth of what the app loads and is needed
// only to send one, so it is fetched when a conversation opens rather than
// before the first page shows — held to its import-map hash like the rest. A
// failed load is forgotten, so the next file tries again.
let scrubbing = null;
export const scrubber = () => (scrubbing ??= import('./scrub.js').catch((err) => {
  scrubbing = null;
  throw err;
}));

export const ROOM_CODE_RE = /^[0-9a-f]{24}$/;
export const MESSAGE_ID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
export const PEER_ID_RE = /^[0-9a-f]{32}$/;
export const MAX_TEXT_LEN = 16 * 1024;
export const MAX_FILES_AT_ONCE = 10;

/** Media arrived for a call that had already ended; nothing left to do. */
export class CallGone extends Error {}
export const MAX_RENDERED_NODES = 600;
export const MAX_REMOTE_PEERS = 5;
export const SIGNAL_WINDOW_MS = 10 * 1000;
// How long a call rings before the caller gives up. The callee gives up a
// little later, so the caller's hang-up normally arrives first.
export const CALL_RING_MS = 45 * 1000;
export const CALL_MISSED_MS = CALL_RING_MS + 5 * 1000;
export const MAX_SIGNAL_MESSAGES_PER_WINDOW = 240;
export const MAX_SIGNAL_BYTES_PER_WINDOW = 1024 * 1024;
export const ALLOWED_TTLS = new Set([0, 10, 30, 60, 300]);
// How long a message left for someone stays on their screen once opened.
export const DROP_READ_TTLS = new Set([0, 30, 300]);
export const DROP_POLL_MS = 60_000;
export const CURRENT_KDF_ITERATIONS = Number(DEFAULT_KDF.split(':')[1]);

/**
 * Build an element without ever handing a string to an HTML parser.
 *
 * `node.append()` inserts strings as text nodes, so nothing here can be talked
 * into creating markup. Every render path below uses this instead of innerHTML,
 * which is what lets the CSP refuse the innerHTML sink outright — see
 * require-trusted-types-for in internal/middleware/headers.go.
 */
/**
 * Element.append with h()'s rule for children: null, undefined and false mean
 * "nothing here". The DOM's own append stringifies them, which is how every
 * message in a two-person room came to read "null" above its text.
 */
export function appendPresent(parent, ...children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    parent.append(child);
  }
  return parent;
}

export function h(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else node.setAttribute(key, value);
  }
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child);
  }
  return node;
}

// The server answers in plain English. The ones a person can actually meet
// are translated here; anything else is shown as sent rather than hidden.
export const SERVER_ERRORS = {
  'invalid credentials': 'srv.badLogin',
  'invalid or used invite code': 'srv.badInvite',
  'too many attempts — try again later': 'srv.tooMany',
  'too many requests': 'srv.tooMany',
  'username: 3–20 chars, letters/numbers/underscores': 'srv.username',
  'registration temporarily unavailable': 'srv.unavailable',
  'authentication temporarily unavailable': 'srv.unavailable',
  're-authentication required': 'srv.reauth',
  'session expired': 'srv.expired',
  'not authenticated': 'srv.expired',
  'room unavailable': 'srv.roomFull',
  'invalid room code': 'err.roomCode',
  'invalid or used guest link': 'guest.failed',
  'guest links are temporarily unavailable': 'srv.unavailable',
};

export function serverMessage(text, fallbackKey) {
  if (!text) return t(fallbackKey);
  const key = SERVER_ERRORS[text];
  return key ? t(key) : text;
}

/** What to ask before a document goes with comments, changes or hidden parts left in it. */
export function keptQuestion(kept) {
  const listed = (items) => items.slice(0, 5).join(', ') + (items.length > 5 ? ` +${items.length - 5}` : '');
  const parts = [
    kept.comments && t('scrub.keptComments'),
    kept.changes && t('scrub.keptChanges'),
    kept.hiddenText && t('scrub.keptHiddenText'),
    kept.hiddenSlides && t('scrub.keptHiddenSlides'),
    kept.sheets?.length && t('scrub.keptHiddenSheets').replace('{sheets}', () => listed(kept.sheets)),
    kept.redactions && t('scrub.keptRedactions'),
  ].filter(Boolean);
  const what = parts.length > 1 ? `${parts.slice(0, -1).join(', ')} ${t('scrub.and')} ${parts.at(-1)}` : parts[0];
  const people = kept.people ?? [];
  return t(people.length ? 'scrub.keptNamed' : 'scrub.kept').replace('{what}', () => what).replace('{names}', () => listed(people));
}

// Web addresses in a message become links — built as elements, never markup,
// and only for http(s). The visible text is the address itself, so a link
// cannot say one place and go to another. No preview is ever fetched: that
// would tell the linked site this device's address before anyone clicked.
export const URL_IN_TEXT = /\bhttps?:\/\/[^\s<>"'`]+/gi;

// "see https://example.com." — the full stop belongs to the sentence. A
// closing bracket belongs to the address only when it closes one inside it,
// as in https://en.wikipedia.org/wiki/Foo_(bar).
export function trimUrl(raw) {
  const pairs = { ')': '(', ']': '[', '}': '{' };
  let end = raw.length;
  while (end > 0) {
    const ch = raw[end - 1];
    if ('.,;:!?\'"'.includes(ch)) { end--; continue; }
    const open = pairs[ch];
    if (open) {
      const body = raw.slice(0, end);
      if (body.split(ch).length > body.split(open).length) { end--; continue; }
    }
    break;
  }
  return raw.slice(0, end);
}

export function linkify(text) {
  const parts = [];
  let last = 0;
  for (const match of text.matchAll(URL_IN_TEXT)) {
    const raw = trimUrl(match[0]);
    let href;
    let shown = raw;
    try {
      const url = new URL(raw);
      if (url.protocol !== 'https:' && url.protocol !== 'http:') continue;
      // "https://bank.example@elsewhere.example" goes to elsewhere.example;
      // everything before the @ is a user name, there to be read as the host.
      // Nobody sends a real link with credentials in it: left as text.
      if (url.username || url.password) continue;
      href = url.href;
      // A host in another script can be drawn to look like a familiar one —
      // "аpple.com" with a Cyrillic а. Browsers show such hosts in their
      // punycode form so the difference is visible; so does the link.
      if (url.hostname.split('.').some((label) => label.startsWith('xn--'))) shown = href;
    } catch { continue; }
    if (match.index > last) parts.push(text.slice(last, match.index));
    parts.push(h('a', {
      href, text: shown, target: '_blank', rel: 'noopener noreferrer nofollow', class: 'msg-link',
    }));
    last = match.index + raw.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

/**
 * The room code in what someone typed or pasted: the code itself, or the whole
 * invitation link — which is what people are actually sent, and used to be cut
 * to its first 24 characters by the field's maxlength and refused.
 */
export function roomCodeFrom(input) {
  const text = String(input || '').trim().toLowerCase();
  const match = text.match(/#join=([0-9a-f]{24})(?![0-9a-f])/) || text.match(/^([0-9a-f]{24})$/);
  return match ? match[1] : null;
}

export function needsKdfUpgrade(kdf) {
  const match = /^pbkdf2:(\d+)$/.exec(kdf || '');
  return !match || Number(match[1]) < CURRENT_KDF_ITERATIONS;
}

// A sign-out the server has not confirmed. The cookie is HttpOnly, so only the
// server can end a session: if it could not be reached, the session lives on
// there and the cookie stays here, and the next reload would walk straight back
// in. Only the fact is kept — no name, no token — so the next page finishes the
// job before it believes that cookie. 'wipe' repeats a panic wipe's request.
export const SIGNOUT_OWED = 'dd_signout_owed';

export function signOutOwed() {
  try {
    const owed = localStorage.getItem(SIGNOUT_OWED);
    return owed === 'wipe' || owed === '1' ? owed : null;
  } catch {
    return null;
  }
}

export function setSignOutOwed(owed) {
  try {
    if (owed) localStorage.setItem(SIGNOUT_OWED, owed);
    else localStorage.removeItem(SIGNOUT_OWED);
  } catch { /* storage may be blocked */ }
}
