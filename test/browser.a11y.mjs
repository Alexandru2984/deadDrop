/**
 * Can this be used without a mouse, and without seeing it?
 *
 *   DD_URL=… DD_INVITE=… node test/browser.a11y.mjs
 *
 * Checked in a browser rather than by reading the markup, because the answer
 * depends on what the accessibility tree ends up containing — which is the
 * product of the HTML, the translations applied at runtime, and whatever the app
 * does to the DOM afterwards. A label that exists in the source and never gets
 * applied is not a label.
 *
 * The failure this guards against is quiet: every control on the chat screen is
 * an emoji, and an emoji with no accessible name is announced by its Unicode
 * name. The panic button — which wipes the tab and logs you out — was announced
 * as "skull".
 */

import { Peer, launchBrowser, waitFor } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITE = process.env.DD_INVITE || '';
const PASS = 'a11y-test-passphrase-2208';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITE) {
  console.error('a11y: set DD_INVITE');
  process.exit(1);
}

const suffix = Math.floor(Math.random() * 1e6);
console.log(`Accessibility check against ${BASE}`);
const { cdp, cleanup } = await launchBrowser('a11y');
const peer = await Peer.open(cdp, 'a11y');
await peer.goto(BASE + '/');

/**
 * Every visible interactive element and the name a screen reader would use.
 * aria-label wins; then the text content; then title, which several readers do
 * not announce at all and which no touch user can reach.
 */
const controls = () => peer.eval(`
  (() => {
    const visible = (el) => {
      const r = el.getBoundingClientRect();
      return r.width > 0 && r.height > 0 && getComputedStyle(el).visibility !== 'hidden';
    };
    return [...document.querySelectorAll('button, a[href], input, select, textarea')]
      .filter(visible)
      .map((el) => {
        // The name a reader would use, in the order the accessible-name
        // algorithm resolves it. A control wrapped in a label takes the
        // label's text, which is why reading the element alone is not enough.
        const labelled = el.getAttribute('aria-labelledby');
        const byId = labelled && document.getElementById(labelled);
        const wrapping = el.closest('label');
        const forAttr = el.id && document.querySelector(\`label[for="\${el.id}"]\`);
        return {
          id: el.id || el.className || el.tagName.toLowerCase(),
          tag: el.tagName.toLowerCase(),
          aria: el.getAttribute('aria-label') || '',
          labelled: (byId?.textContent || wrapping?.textContent || forAttr?.textContent || '').trim(),
          text: (el.textContent || '').trim(),
          placeholder: el.getAttribute('placeholder') || '',
          title: el.getAttribute('title') || '',
        };
      });
  })()
`);

/** A name that is not the element's own icon. */
const named = (c) => {
  const name = c.aria || c.labelled
    || (c.tag === 'input' ? c.placeholder : c.text);
  if (!name) return false;
  // An emoji-only name is the failure this exists to catch.
  return /[a-z0-9]/i.test(name.replace(/[\p{Extended_Pictographic}️]/gu, ''));
};

console.log('\nsign-in page');
let list = await controls();
let unnamed = list.filter((c) => !named(c));
ok(unnamed.length === 0,
  `every control has a name that is not just an icon${unnamed.length ? ': ' + unnamed.map((c) => c.id).join(', ') : ` (${list.length} checked)`}`);

// The whole page has to be reachable from the keyboard, in order.
const tabOrder = await peer.eval(`
  (() => {
    const focusable = [...document.querySelectorAll(
      'button, a[href], input, select, textarea, [tabindex]:not([tabindex="-1"])')]
      .filter((el) => el.offsetParent !== null && !el.disabled);
    return focusable.filter((el) => el.tabIndex < 0).map((el) => el.id || el.className);
  })()
`);
ok(tabOrder.length === 0,
  `nothing visible is removed from the tab order${tabOrder.length ? ': ' + tabOrder.join(', ') : ''}`);

ok(await peer.eval(`
  (() => {
    const el = document.querySelector('#auth-user');
    el.focus();
    const s = getComputedStyle(el, ':focus-visible');
    return document.activeElement === el;
  })()
`), 'focus can be placed on the first field');

console.log('\nchat screen');
ok(await peer.register(`zz_ax_${suffix}`, INVITE, PASS), 'an account is registered');
await peer.eval(`document.querySelector('#create-room').click(); true`);
ok(await waitFor(() => peer.inChat()), 'a room opens');

list = await controls();
unnamed = list.filter((c) => !named(c));
ok(unnamed.length === 0,
  `every chat control has a real name${unnamed.length ? ': ' + unnamed.map((c) => `${c.id} (${c.text})`).join(', ') : ` (${list.length} checked)`}`);

// The panic button is the specific one worth naming here: it wipes the tab, and
// it used to announce as its own emoji.
const panic = list.find((c) => c.id === 'panic-btn');
ok(panic && /panic/i.test(panic.aria), `the panic button says what it does ("${panic?.aria}")`);

console.log('\nannouncements');
ok(await peer.eval(`document.querySelector('#messages')?.getAttribute('role') === 'log'`),
  'the transcript is a log region, so arriving messages are announced');
ok(await peer.eval(`document.querySelector('#messages')?.getAttribute('aria-live') === 'polite'`),
  'and announced without interrupting');
ok(await peer.eval(`document.querySelector('#status')?.getAttribute('role') === 'status'`),
  'connection state changes are announced');

console.log('\noverlays');
for (const [id, role] of [['qr-verify', 'dialog'], ['incoming-call', 'alertdialog'],
  ['call-overlay', 'dialog'], ['account-panel', 'dialog']]) {
  const got = await peer.eval(`document.querySelector('#${id}')?.getAttribute('role')`);
  const label = await peer.eval(`document.querySelector('#${id}')?.getAttribute('aria-label') || ''`);
  ok(got === role && label.length > 2, `#${id} is a ${role} with a name ("${label}")`);
}

console.log('\ncontrast');

// Computed from what the browser actually paints, not from the palette: text
// inherits colours through places nobody thinks to check, and a token that
// passes in isolation can still land on a surface where it does not.
const lowContrast = await peer.eval(`
  (() => {
    const lin = (c) => { c /= 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
    const lum = ([r, g, b]) => 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
    const rgb = (s) => (s.match(/\\d+/g) || []).slice(0, 3).map(Number);
    const alpha = (s) => { const m = s.match(/rgba?\\([^)]*?([\\d.]+)\\s*\\)/); return m ? Number(m[1]) : 1; };

    // The first ancestor that actually paints something behind this text.
    const backdrop = (el) => {
      for (let n = el; n && n !== document.documentElement; n = n.parentElement) {
        const bg = getComputedStyle(n).backgroundColor;
        if (bg && alpha(bg) > 0.5) return rgb(bg);
      }
      return rgb(getComputedStyle(document.body).backgroundColor) || [0, 0, 0];
    };

    const ratio = (a, b) => {
      const [x, y] = [lum(a), lum(b)];
      return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
    };

    const bad = [];
    for (const el of document.querySelectorAll('body *')) {
      // Only elements holding their own visible text.
      const own = [...el.childNodes].filter((n) => n.nodeType === 3 && n.textContent.trim()).length;
      if (!own) continue;
      const r = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      if (r.width < 1 || r.height < 1 || style.visibility === 'hidden' || Number(style.opacity) < 0.5) continue;

      const size = parseFloat(style.fontSize);
      const bold = Number(style.fontWeight) >= 700;
      // WCAG's own definition of large text: 24px, or 18.66px when bold.
      const large = size >= 24 || (bold && size >= 18.66);
      const need = large ? 3 : 4.5;
      const got = ratio(rgb(style.color), backdrop(el));
      if (got < need) {
        bad.push(\`\${el.id || el.className || el.tagName}: \${got.toFixed(2)} (needs \${need})\`);
      }
    }
    return [...new Set(bad)];
  })()
`);
ok(lowContrast.length === 0,
  `every piece of visible text meets WCAG AA${lowContrast.length ? ': ' + lowContrast.slice(0, 6).join('; ') : ''}`);

console.log('\ndecoration is not announced');
ok(await peer.eval(`[...document.querySelectorAll('.logo')].every((el) => el.getAttribute('aria-hidden') === 'true')`),
  'the logo is hidden from assistive technology');

ok(peer.errors.length === 0, `no uncaught exceptions${peer.errors.length ? ': ' + peer.errors[0] : ''}`);

cdp.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
