/**
 * Dead Drop — messages left for a saved contact who is not online.
 *
 * Two people who saved each other as contacts can leave each other messages
 * that wait on the server until collected. The server only ever holds sealed
 * boxes under names it cannot connect to anyone; the keys are agreed in a
 * live, end-to-end encrypted session whose safety code both compared.
 *
 * Each side owns its inbox. On every verified meeting with a saved contact it
 * mints a fresh one and hands the contact the key to it, over the encrypted
 * channel — the server never sees it. The key is the start of a chain:
 *
 *   box n's name = HMAC(C_n, "id")     box n's key = HMAC(C_n, "key")
 *   C_{n+1}      = HMAC(C_n, "next")   and C_n is then forgotten
 *
 * so every message has a name and a key of its own, two messages for the same
 * person share nothing an observer could match, and a device seized later
 * holds only the chain from the next message on: nothing it can derive opens
 * one that was already sent or collected. A message the recipient skipped
 * keeps its own key, not the chain, until it is collected or could no longer
 * be waiting.
 *
 * This module is the cryptography and the bookkeeping. Records are stored by
 * identity.js; the app moves boxes to and from the server.
 */

import { bufToB64, b64ToBuf } from './util.js';

export const DROP_TTLS = Object.freeze([3600, 86400, 604800]);
export const MAX_DROP_TEXT = 4000;
// Boxes past the last one collected that are looked for. A sender whose
// upload failed moves on to the next name; this is how many it may skip.
export const DROP_WINDOW = 6;
// Inboxes kept per contact: the newest, and older ones while anything left
// in them could still be waiting.
const MAX_INBOXES = 3;
const LONGEST_WAIT_MS = 7 * 24 * 3600 * 1000;
const MAX_SKIPPED = 32;
// Every box is one of these sizes, so its size says little about its text.
const PAD_BUCKETS = [1024, 4096, 16384];

const enc = new TextEncoder();
const dec = new TextDecoder();

const label = (what) => enc.encode(`deaddrop/drop/v1/${what}`);

async function hmac(keyBytes, what) {
  const key = await crypto.subtle.importKey('raw', keyBytes, { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', key, label(what)));
}

function hex(bytes) {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

/** Box n of a chain: its name and key, and the chain for box n+1. */
async function step(chain) {
  const [idBytes, key, next] = await Promise.all([hmac(chain, 'id'), hmac(chain, 'key'), hmac(chain, 'next')]);
  return { id: hex(idBytes.subarray(0, 16)), key, next };
}

async function aesKey(raw, usage) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, false, [usage]);
}

function emptyRecord() {
  return { v: 1, inbox: [], outbox: null };
}

function copyBytes(value) {
  return value instanceof Uint8Array ? new Uint8Array(value) : new Uint8Array(value || []);
}

/** A record as stored, made safe to work on: old inboxes and skipped keys
 *  that could no longer have anything waiting are dropped. */
export function tidyRecord(record, now = Date.now()) {
  const out = emptyRecord();
  if (!record || record.v !== 1) return out;
  out.inbox = (Array.isArray(record.inbox) ? record.inbox : [])
    .filter((box) => !box.retired || now - box.retired < LONGEST_WAIT_MS)
    .slice(0, MAX_INBOXES)
    .map((box) => ({
      id: String(box.id),
      chain: copyBytes(box.chain),
      next: box.next,
      retired: box.retired || 0,
      skipped: (box.skipped || []).filter((s) => s.until > now).slice(-MAX_SKIPPED)
        .map((s) => ({ n: s.n, id: s.id, key: copyBytes(s.key), until: s.until })),
    }));
  if (record.outbox?.chain) {
    out.outbox = { chain: copyBytes(record.outbox.chain), n: record.outbox.n, received: record.outbox.received };
  }
  return out;
}

/**
 * Open a fresh inbox for a contact. Returns the record to store and the
 * capability to hand them — only over the encrypted channel of a verified
 * session, and only once the record holding it is stored.
 */
export function mintInbox(record, now = Date.now()) {
  const next = tidyRecord(record, now);
  for (const box of next.inbox) if (!box.retired) box.retired = now;
  const chain = crypto.getRandomValues(new Uint8Array(32));
  const id = hex(crypto.getRandomValues(new Uint8Array(8)));
  next.inbox.unshift({ id, chain, next: 0, retired: 0, skipped: [] });
  next.inbox = next.inbox.slice(0, MAX_INBOXES);
  return { record: next, capability: { chain: bufToB64(chain), n: 0 } };
}

/** Take the inbox a contact handed us, replacing the one we had for them. */
export function acceptCapability(record, capability, now = Date.now()) {
  if (!capability || typeof capability.chain !== 'string' || capability.n !== 0) return null;
  let chain;
  try { chain = new Uint8Array(b64ToBuf(capability.chain)); } catch { return null; }
  if (chain.length !== 32) return null;
  const next = tidyRecord(record, now);
  next.outbox = { chain, n: 0, received: now };
  return next;
}

/**
 * Seal a message for the contact's inbox. Nothing changes until the server
 * has taken it: `advance()` is the record to store then. A failed upload can
 * be retried under the same name; one the server already has is moved past.
 */
export async function sealDrop(record, { text, readTtl = 0, burn = false }) {
  const current = tidyRecord(record);
  if (!current.outbox) throw new Error('No inbox to leave a message in');
  if (typeof text !== 'string' || !text.trim() || text.length > MAX_DROP_TEXT) throw new Error('Invalid message');
  const { id, key, next } = await step(current.outbox.chain);
  const body = JSON.stringify({ v: 1, text, readTtl, burn: burn === true });
  const plain = enc.encode(pad(body));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const box = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: label(`box/${id}`) }, await aesKey(key, 'encrypt'), plain,
  ));
  plain.fill(0);
  key.fill(0);
  return {
    id,
    box: bufToB64(box),
    iv: bufToB64(iv),
    advance() {
      const after = tidyRecord(current);
      after.outbox = { ...after.outbox, chain: new Uint8Array(next), n: current.outbox.n + 1 };
      return after;
    },
  };
}

function pad(body) {
  const length = enc.encode(body).length;
  const target = PAD_BUCKETS.find((size) => size >= length + 2);
  if (!target) throw new Error('Message too long');
  // The padding is spaces after the JSON, which a parser skips.
  return body + ' '.repeat(target - length);
}

/** Every name this browser should look for: the next few boxes of each
 *  inbox, and boxes skipped on the way to a later one. */
export async function namesToCheck(record) {
  const current = tidyRecord(record);
  const names = [];
  for (const box of current.inbox) {
    for (const skipped of box.skipped) names.push({ inbox: box.id, n: skipped.n, id: skipped.id });
    let chain = box.chain;
    for (let n = box.next; n < box.next + DROP_WINDOW; n++) {
      const s = await step(chain);
      names.push({ inbox: box.id, n, id: s.id });
      s.key.fill(0);
      chain = s.next;
    }
  }
  return names;
}

/**
 * Open a collected box. Returns the message and the record to store, with
 * the chain moved past it and the keys of any boxes skipped on the way kept
 * for when they turn up. A box that does not open changes nothing.
 */
export async function openDrop(record, name, boxB64, ivB64, now = Date.now()) {
  const current = tidyRecord(record, now);
  const box = current.inbox.find((b) => b.id === name.inbox);
  if (!box || !Number.isSafeInteger(name.n) || name.n < 0) throw new Error('Unknown inbox');
  let key;
  let skipped = [];
  let chainAfter = null;
  const known = box.skipped.find((s) => s.n === name.n && s.id === name.id);
  if (known) {
    key = known.key;
  } else {
    if (name.n < box.next || name.n >= box.next + DROP_WINDOW) throw new Error('Not a box this inbox is waiting for');
    let chain = box.chain;
    for (let n = box.next; ; n++) {
      const s = await step(chain);
      if (n === name.n) {
        if (s.id !== name.id) throw new Error('Box name does not match');
        key = s.key;
        chainAfter = s.next;
        break;
      }
      skipped.push({ n, id: s.id, key: s.key, until: now + LONGEST_WAIT_MS });
      chain = s.next;
    }
  }
  let plain;
  try {
    plain = new Uint8Array(await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: new Uint8Array(b64ToBuf(ivB64)), additionalData: label(`box/${name.id}`) },
      await aesKey(key, 'decrypt'),
      new Uint8Array(b64ToBuf(boxB64)),
    ));
  } catch {
    for (const s of skipped) s.key.fill(0);
    throw new Error('The box did not open');
  }
  const message = parseMessage(dec.decode(plain));
  plain.fill(0);
  key.fill(0);
  if (known) {
    box.skipped = box.skipped.filter((s) => s !== known);
  } else {
    box.chain.fill(0);
    box.chain = chainAfter;
    box.next = name.n + 1;
    box.skipped = [...box.skipped, ...skipped].slice(-MAX_SKIPPED);
  }
  return { message, record: current };
}

function parseMessage(json) {
  let data;
  try { data = JSON.parse(json); } catch { throw new Error('Malformed message'); }
  if (!data || data.v !== 1 || typeof data.text !== 'string' || data.text.length > MAX_DROP_TEXT) {
    throw new Error('Malformed message');
  }
  return {
    text: data.text,
    readTtl: Number.isSafeInteger(data.readTtl) && data.readTtl >= 0 ? data.readTtl : 0,
    burn: data.burn === true,
  };
}
