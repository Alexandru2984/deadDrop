/**
 * Dead Drop — remembered settings.
 *
 * Only switches live here: which protections are on, how soon an idle tab locks.
 * Nothing about people, rooms or messages. It sits in this origin's
 * localStorage, which the panic wipe clears locally, even without a response.
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
  callRing: true,
  idleLockMinutes: 0,
  messageTtl: 30,
  theme: 'dark',
});

const VALID = {
  relayOnly: (v) => typeof v === 'boolean',
  coverTraffic: (v) => typeof v === 'boolean',
  scrubMetadata: (v) => typeof v === 'boolean',
  typingIndicator: (v) => typeof v === 'boolean',
  callRing: (v) => typeof v === 'boolean',
  idleLockMinutes: (v) => [0, 5, 15, 30, 60].includes(v),
  messageTtl: (v) => [0, 10, 30, 60, 300].includes(v),
  theme: (v) => ['dark', 'light', 'system'].includes(v),
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

let followingSystem = false;

/**
 * Show the page in the chosen theme. boot.js calls it first thing, while the
 * rest of the app is still loading, so a light page is light from about its
 * first frame rather than after everything arrives; the browser's own bar and
 * form controls follow it too.
 */
export function applyTheme(theme = getPref('theme')) {
  const root = document.documentElement;
  root.dataset.theme = theme;
  const query = typeof matchMedia === 'function' ? matchMedia('(prefers-color-scheme: light)') : null;
  const light = theme === 'light' || (theme === 'system' && !!query?.matches);
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', light ? '#f4f5f7' : '#0a0a0f');
  document.querySelector('meta[name="color-scheme"]')?.setAttribute('content', light ? 'light' : 'dark');
  if (query && !followingSystem) {
    followingSystem = true;
    query.addEventListener('change', () => {
      if (root.dataset.theme === 'system') applyTheme('system');
    });
  }
}

export function clearPrefs() {
  try { localStorage.removeItem(KEY); } catch { /* storage may be blocked */ }
}
