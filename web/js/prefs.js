/**
 * Dead Drop — remembered settings.
 *
 * Only switches live here: which protections are on, how soon an idle tab locks.
 * Nothing about people, rooms or messages. It sits in this origin's
 * localStorage, which the panic wipe clears (Clear-Site-Data: "storage").
 *
 * Every value is validated on the way out as well as on the way in, so a stale
 * or hand-edited entry cannot switch a protection off: anything unrecognised
 * reads as the default.
 */

const KEY = 'dd_prefs';

const DEFAULTS = Object.freeze({
  relayOnly: true,
  coverTraffic: false,
  scrubMetadata: true,
  typingIndicator: true,
  idleLockMinutes: 0,
  messageTtl: 30,
});

const VALID = {
  relayOnly: (v) => typeof v === 'boolean',
  coverTraffic: (v) => typeof v === 'boolean',
  scrubMetadata: (v) => typeof v === 'boolean',
  typingIndicator: (v) => typeof v === 'boolean',
  idleLockMinutes: (v) => [0, 5, 15, 30, 60].includes(v),
  messageTtl: (v) => [0, 10, 30, 60, 300].includes(v),
};

function readAll() {
  try {
    const raw = JSON.parse(localStorage.getItem(KEY) || '{}');
    return raw && typeof raw === 'object' && !Array.isArray(raw) ? raw : {};
  } catch {
    return {};
  }
}

export function getPref(name) {
  if (!(name in DEFAULTS)) throw new Error(`unknown preference ${name}`);
  const value = readAll()[name];
  return VALID[name](value) ? value : DEFAULTS[name];
}

export function setPref(name, value) {
  if (!(name in DEFAULTS) || !VALID[name](value)) return;
  const all = readAll();
  all[name] = value;
  try { localStorage.setItem(KEY, JSON.stringify(all)); } catch { /* storage may be blocked */ }
}

export const PREF_DEFAULTS = DEFAULTS;
