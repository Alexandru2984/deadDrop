/**
 * Two-peer end-to-end test: two isolated browser contexts, one real WebRTC
 * session between them.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… node test/browser.pair.mjs
 *
 * Everything else in the suite exercises one side at a time. The Go tests never
 * run the client, the crypto self-test drives both handshake halves in one
 * process with no transport, and the single-page smoke test never has a peer to
 * talk to. So nothing covered the path that actually matters: two browsers, the
 * signaling server between them, a data channel, a safety code both humans
 * compare, and — since protocol v5 — a saved contact recognised on a later
 * session without comparing anything again.
 */

import { Peer, launchBrowser, waitFor, sleep } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [process.env.DD_INVITE || '', process.env.DD_INVITE2 || ''];
const PASS = 'pair-test-passphrase-9182';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITES[0] || !INVITES[1]) {
  console.error('pair test: set DD_INVITE and DD_INVITE2 (one account each)');
  process.exit(1);
}

const suffix = Math.floor(Math.random() * 1e6);
const USERS = [`zz_pa_${suffix}`, `zz_pb_${suffix}`];
console.log(`Two-peer run against ${BASE} as ${USERS[0]} + ${USERS[1]}`);

const { cdp, cleanup } = await launchBrowser('pair');

// ── First session: strangers must compare a safety code ──
const alice = await Peer.open(cdp, 'alice');
const bob = await Peer.open(cdp, 'bob');

// A handle on A's sockets, so a dropped connection can be simulated.
await cdp.send('Page.addScriptToEvaluateOnNewDocument', { source: `
  window.__sockets = [];
  const Native = WebSocket;
  window.WebSocket = class extends Native {
    constructor(...args) { super(...args); window.__sockets.push(this); }
  };
` }, alice.sessionId);
await alice.goto(BASE + '/');
await bob.goto(BASE + '/');
ok(await alice.register(USERS[0], INVITES[0], PASS), 'peer A registers');
ok(await bob.register(USERS[1], INVITES[1], PASS), 'peer B registers');

// Both opt into saved contacts before connecting, so the identity is present in
// the very first handshake and can be pinned when they verify.
await alice.enableSavedContacts();
await bob.enableSavedContacts();

await alice.eval(`document.querySelector('#create-room').click(); true`);
const room = await waitFor(async () => {
  const code = await alice.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
ok(room, 'peer A creates a room');

// Someone arriving through the invitation, not logged in, is told why they
// are looking at a sign-in page and that the room will be waiting.
const visitor = await Peer.open(cdp, 'visitor');
await visitor.goto(`${BASE}/#join=${room}`);
const invitedNote = await waitFor(() => visitor.eval(`(() => {
  const note = document.querySelector('#auth-invited');
  return !document.querySelector('#auth').classList.contains('hidden') && !note.classList.contains('hidden')
    ? note.textContent : false;
})()`), { timeout: 10000 });
ok(invitedNote && /invited/i.test(invitedNote), `an invited visitor is told the room will be ready after signing in (${invitedNote || 'nothing'})`);
ok(await visitor.eval(`location.hash === ''`), 'and the room code is taken out of the address bar');
await cdp.send('Target.closeTarget', { targetId: visitor.targetId });

await bob.eval(`
  document.querySelector('#room-code-input').value = ${JSON.stringify(room)};
  document.querySelector('#join-room').click(); true
`);
ok(await waitFor(() => bob.inChat()), 'peer B joins the room');

const sasA = await waitFor(() => alice.sas(), { timeout: 30000 });
const sasB = await waitFor(() => bob.sas(), { timeout: 30000 });
ok(sasA && sasB, 'both peers complete the hybrid handshake and show a safety code');
ok(sasA === sasB, `both peers derive the same safety code (${sasA} / ${sasB})`);

ok(await alice.verified() === false && await bob.verified() === false,
  'traffic stays locked before anyone confirms');

ok(await alice.clickVerify(), 'peer A confirms the safety code');
// B is told A is waiting — and told to compare anyway, not just to click.
const told = await waitFor(() => bob.eval(
  `document.querySelector('.verify-peer-confirmed')?.textContent || ''`), { timeout: 10000 });
ok(/compare/i.test(told || ''), `the other side learns its peer has confirmed (${told || 'nothing shown'})`);
ok(await bob.clickVerify(), 'peer B confirms the safety code');
ok(await waitFor(() => alice.verified()) && await waitFor(() => bob.verified()),
  'mutual confirmation unlocks both sides');

// The QR dialog is modal in fact, not just in its ARIA: the conversation and
// the panic button behind it cannot take focus, and Escape gives them back.
await bob.eval(`document.querySelector('#verify-rows .verify-actions .btn').click(); true`);
const qrModal = await waitFor(() => bob.eval(`(() => {
  if (document.querySelector('#qr-verify').classList.contains('hidden')) return false;
  return ['#msg-input', '#panic-btn'].every((s) => document.querySelector(s).closest('[inert]'))
    && !document.querySelector('#qr-verify').closest('[inert]');
})()`), { timeout: 10000 });
ok(qrModal, 'with the QR dialog open, the page behind it is inert');
await bob.eval(`window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })); true`);
ok(await waitFor(() => bob.eval(`document.querySelector('#qr-verify').classList.contains('hidden')
  && !document.querySelector('[inert]')`)), 'Escape closes it and nothing stays inert');

// The camera permission prompt can outlast the dialog. A camera granted after
// the dialog was closed used to start scanning, unseen, until the tab closed.
await bob.eval(`(() => {
  const real = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  window.__lateCam = null;
  navigator.mediaDevices.getUserMedia = (c) => new Promise((resolve) => setTimeout(async () => {
    window.__lateCam = await real(c);
    resolve(window.__lateCam);
  }, 1200));
  window.__restoreGum = () => { navigator.mediaDevices.getUserMedia = real; };
  document.querySelector('#verify-rows .verify-actions .btn').click();
  return true;
})()`);
await waitFor(() => bob.eval(`!document.querySelector('#qr-verify').classList.contains('hidden')`), { timeout: 10000 });
await bob.eval(`document.querySelector('#qr-verify-close').click(); true`);
const lateCam = await waitFor(() => bob.eval(`window.__lateCam
  && { live: window.__lateCam.getTracks().some((tr) => tr.readyState === 'live') }`), { timeout: 10000 });
await bob.eval(`window.__restoreGum(); true`);
ok(lateCam && !lateCam.live, `a camera granted after the QR dialog closed is stopped at once (${JSON.stringify(lateCam)})`);
// Six emoji are 36 bits; the row has to say so, and point at the QR.
// Verified, the bar folds to a single line so the conversation keeps the
// screen; the sentences are still there for screen readers and one tap away.
const folded = await waitFor(() => alice.eval(`(() => {
  const bar = document.querySelector('#verify-bar');
  const row = bar.querySelector('.verify-row');
  return bar.classList.contains('verified') && !bar.classList.contains('expanded')
    && row.getBoundingClientRect().height < 60
    && getComputedStyle(row.querySelector('.verify-actions')).display === 'none';
})()`), { timeout: 10000 });
ok(folded, 'once verified the safety-code bar folds to one line');
const unfolded = await alice.eval(`(() => {
  document.querySelector('.verify-more').click();
  const bar = document.querySelector('#verify-bar');
  return bar.classList.contains('expanded')
    && getComputedStyle(bar.querySelector('.verify-actions')).display !== 'none'
    && document.querySelector('.verify-more').getAttribute('aria-expanded') === 'true';
})()`);
ok(unfolded, 'one tap unfolds it, QR upgrade included');
await alice.eval(`document.querySelector('.verify-more').click(); true`);
const method = await alice.eval(`document.querySelector('.verify-method')?.className || ''`);
ok(/verify-method-emoji/.test(method),
  'an emoji-only confirmation is labelled as the weaker check');

// No relay is configured for this run, so the connection is direct, and the
// row has to admit that the other side can see this one's address.
const route = await waitFor(async () => (await alice.eval(
  `document.querySelector('.verify-route')?.className || ''`)) || false, { timeout: 20000 });
ok(/verify-route-direct/.test(route || ''),
  `the route line reports what ICE actually chose (${route || 'nothing shown'})`);

const secret = 'ciphertext round trip ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(secret)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(secret)),
  'a message sent by A is decrypted by B');

// The whole bubble, not just its text node. A null child handed to the DOM's
// append() is printed as "null"; for six weeks every message in a two-person
// room carried that word above it, and checking .msg-text alone never saw it.
const bubbles = async (p) => p.eval(`[...document.querySelectorAll('.msg:not(.system)')]
  .flatMap((n) => [...n.childNodes])
  .filter((c) => c.nodeType === Node.TEXT_NODE && /^(null|undefined|false)$/.test(c.data.trim()))
  .map((c) => c.data)`);
const stray = [...await bubbles(alice), ...await bubbles(bob)];
ok(stray.length === 0, `no bubble renders a stray null or undefined (${stray[0] || 'none'})`);

// ── Burn after reading ──
// The one message class that is meant to vanish from both sides. It works by the
// reader telling the sender it was read, so if that stops working the message
// quietly stops burning — and nothing would have noticed.
const burning = 'burn this ' + suffix;
await alice.sendBurning(burning);
// The badge is the only sign the sender gets that it will vanish; it is
// translated like every other word on screen, not left in English.
ok(await waitFor(() => alice.eval(`[...document.querySelectorAll('.burn-badge')]
  .some((b) => b.dataset.i18n === 'msg.burnBadge' && b.textContent.includes('🔥'))`), { timeout: 3000 }),
  'the burn badge is labelled through the translation table');
ok(await waitFor(async () => (await bob.transcript()).includes(burning)),
  'a burn-after-reading message reaches B');
ok(await waitFor(async () => !(await bob.transcript()).includes(burning), { timeout: 15000 }),
  'and burns on the reader side');
ok(await waitFor(async () => !(await alice.transcript()).includes(burning), { timeout: 15000 }),
  "and the reader's receipt burns the sender's copy too");

// An ordinary message must survive all of that: only what was sent to burn burns.
const keeper = 'keep this ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(keeper)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(keeper)),
  'an ordinary message still arrives');
await sleep(4000);
ok((await alice.transcript()).includes(keeper),
  'and is still on the sender side after the burn window');

// ── Files ──
// filetransfer.js chunks, reassembles and re-checks the declared size against
// both the ciphertext and the plaintext. None of that had ever run against a
// real peer.
const fileBody = 'dead drop file payload ' + suffix + '\n' + 'x'.repeat(120 * 1024);
// Record every progress label the receiver shows while the file comes in.
await bob.eval(`(() => {
  window.__progress = [];
  new MutationObserver(() => {
    for (const n of document.querySelectorAll('.progress-text')) window.__progress.push(n.textContent);
  }).observe(document.querySelector('#messages'), { subtree: true, childList: true, characterData: true });
  return true;
})()`);
await alice.eval(`(() => {
  window.__sending = [];
  new MutationObserver(() => {
    for (const n of document.querySelectorAll('.file-sending')) window.__sending.push(n.textContent);
  }).observe(document.querySelector('#messages'), { subtree: true, childList: true, characterData: true });
  return true;
})()`);
ok(await alice.sendFile('notes.txt', fileBody), 'peer A attaches a file');

const received = await waitFor(async () => {
  const files = await bob.receivedFiles();
  const match = files.find((f) => f.name === 'notes.txt');
  return match || false;
}, { timeout: 40000 });
ok(received, 'peer B receives the file and renders it');
const sentProgress = await alice.eval(`window.__sending`);
ok(sentProgress.some((p) => /\d+%/.test(p)),
  `the sender sees how far the file has gone (${[...new Set(sentProgress)].slice(-2).join(', ') || 'none seen'})`);
ok(await waitFor(() => alice.eval(`!document.querySelector('.file-sending')`), { timeout: 10000 }),
  'and the note goes once it has left');
const progress = await bob.eval(`window.__progress`);
ok(progress.length > 0 && progress.every((p) => /^\d{1,3}%$/.test(p)),
  `the receiver's progress reads as a percentage (${[...new Set(progress)].slice(0, 4).join(', ') || 'none seen'})`);

// Both ends format the size from the same declared length, so a mismatch means
// the metadata and the payload disagreed somewhere in between.
const sentFile = (await alice.receivedFiles()).find((f) => f.name === 'notes.txt');
ok(received && sentFile && received.size === sentFile.size,
  `the received size matches what the sender showed (${received?.size} / ${sentFile?.size})`);
ok(received && received.href && received.href.startsWith('blob:'),
  'the download link points at a locally created blob, not the network');

// An image that decodes to its original dimensions could not have survived a
// corrupted chunk, a short read, or a mis-sliced reassembly.
const pngBytes = await alice.sendGeneratedImage(64, 48);
ok(pngBytes > 0, 'peer A sends a generated PNG');
ok(await waitFor(async () => (await bob.decodedImageSize()) === '64x48', { timeout: 40000 }),
  'the received image decodes at its original dimensions');

// A phone photo carries its GPS position in an EXIF block. Build a JPEG with
// one, run it through the same scrubber the composer uses, and look for it.
const scrubbed = await alice.eval(`
  (async () => {
    const { scrubImage } = await import('/js/scrub.js');
    const canvas = document.createElement('canvas');
    canvas.width = 40; canvas.height = 30;
    canvas.getContext('2d').fillRect(0, 0, 20, 15);
    const plain = new Uint8Array(await (await new Promise((r) => canvas.toBlob(r, 'image/jpeg'))).arrayBuffer());
    const marker = new TextEncoder().encode('Exif\\0\\0GPS-DEADDROP-MARKER');
    const app1 = new Uint8Array(4 + marker.length);
    app1.set([0xff, 0xe1, (marker.length + 2) >> 8, (marker.length + 2) & 255]);
    app1.set(marker, 4);
    const tagged = new Uint8Array(plain.length + app1.length);
    tagged.set(plain.subarray(0, 2)); tagged.set(app1, 2); tagged.set(plain.subarray(2), 2 + app1.length);
    const text = (bytes) => new TextDecoder('latin1').decode(bytes);
    const out = await scrubImage(new File([tagged], 'cat.jpg', { type: 'image/jpeg' }));
    const bytes = new Uint8Array(await out.arrayBuffer());
    return { before: text(tagged).includes('GPS-DEADDROP-MARKER'),
             after: text(bytes).includes('GPS-DEADDROP-MARKER') || text(bytes).includes('Exif'),
             type: out.type, name: out.name };
  })()
`);
ok(scrubbed?.before && scrubbed.after === false && scrubbed.type === 'image/jpeg' && scrubbed.name === 'cat.jpg',
  'a photo leaves without its EXIF block, still a JPEG under its own name');

// The name is peer-controlled text and reaches the DOM. Under Trusted Types a
// markup-shaped name must arrive as literal characters, not as elements.
const nastyName = '<img src=x onerror=alert(1)>.txt';
ok(await alice.sendFile(nastyName, 'small'), 'peer A sends a file with a markup-shaped name');
const nasty = await waitFor(async () => {
  const files = await bob.receivedFiles();
  return files.find((f) => f.name === nastyName) || false;
}, { timeout: 30000 });
ok(nasty, 'the hostile filename arrives as text, not markup');
ok(await bob.eval(`!document.querySelector('#messages img[src="x"]')`),
  'no element was created from the filename');

// A socket error mid-conversation, with the login still valid, must leave
// the conversation on screen. It used to rerun the boot-time check, which on
// a good session showed the landing page — the room vanished mid-sentence.
await alice.eval(`window.__sockets.at(-1).onerror(new Event('error')); true`);
await sleep(1500);
ok(await alice.eval(`!document.querySelector('#chat-wrap').classList.contains('hidden')
  && document.querySelector('#landing').classList.contains('hidden')`),
  'a socket error with a valid login leaves the conversation on screen');

// Losing the server mid-conversation loses nothing already running: the
// session is direct. A is told newcomers cannot arrive, and is not torn down
// to reconnect — a rejoin would be a new peer and a new code to compare.
await alice.eval(`window.__sockets.at(-1).close(); true`);
const lostNote = await waitFor(async () => (await alice.notices()).find((n) => /server connection dropped/i.test(n)) || false,
  { timeout: 5000 });
ok(lostNote, 'losing the server mid-conversation is explained, not shown as a failure');
const afterLoss = 'after the server went ' + suffix;
await bob.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(afterLoss)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await alice.transcript()).includes(afterLoss)),
  'the conversation carries on directly without the server');
ok(await alice.verified(), 'and the session stays verified — nothing was renegotiated');

// The composer takes more than one line: Shift+Enter breaks the line and the
// field grows with it, Enter sends, and the far side shows the break.
const key = (type, k, extra = {}) => cdp.send('Input.dispatchKeyEvent', {
  type, key: k, code: k === 'Enter' ? 'Enter' : `Key${k.toUpperCase()}`,
  windowsVirtualKeyCode: k === 'Enter' ? 13 : k.toUpperCase().charCodeAt(0),
  ...(type === 'keyDown' && k !== 'Enter' ? { text: k } : {}),
  ...(type === 'keyDown' && k === 'Enter' ? { text: '\r' } : {}),
  ...extra,
}, alice.sessionId);
const press = async (k, extra) => { await key('keyDown', k, extra); await key('keyUp', k, extra); };
await alice.eval(`document.querySelector('#msg-input').focus(); true`);
const oneLine = await alice.eval(`document.querySelector('#msg-input').offsetHeight`);
await press('a');
await press('Enter', { modifiers: 8 }); // Shift
await press('b');
const composed = await alice.eval(`({ value: document.querySelector('#msg-input').value,
  height: document.querySelector('#msg-input').offsetHeight })`);
ok(composed.value === 'a\nb', `Shift+Enter starts a new line instead of sending (${JSON.stringify(composed.value)})`);
ok(composed.height > oneLine, `the field grows with the second line (${oneLine}px → ${composed.height}px)`);
await press('Enter');
const twoLines = await waitFor(() => bob.eval(`(() => {
  const el = [...document.querySelectorAll('.msg-text')].find((n) => n.textContent === 'a\\nb');
  return el ? el.getClientRects().length && el.getBoundingClientRect().height > parseFloat(getComputedStyle(el).lineHeight) * 1.5 : false;
})()`), { timeout: 10000 });
ok(twoLines, 'Enter sends it, and it arrives on two lines');
ok(await alice.eval(`document.querySelector('#msg-input').value === ''
  && document.querySelector('#msg-input').offsetHeight === ${oneLine}`), 'the field empties back to one line');

// Addresses become links, safely: elements rather than markup, http(s) only,
// the visible text is the address, and the sentence's full stop stays out.
const linkText = 'see https://example.com/a?b=1. not javascript:alert(1) nor <a href=x>y</a>';
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(linkText)};
  document.querySelector('#send-btn').click(); true
`);
const links = await waitFor(() => bob.eval(`(() => {
  const bubble = [...document.querySelectorAll('.msg-text')].find((n) => n.textContent === ${JSON.stringify(linkText)});
  return bubble && [...bubble.querySelectorAll('a')].map((a) => ({ href: a.getAttribute('href'), text: a.textContent, rel: a.rel, target: a.target }));
})()`), { timeout: 10000 });
ok(links && links.length === 1 && links[0].href === 'https://example.com/a?b=1' && links[0].text === 'https://example.com/a?b=1',
  `exactly the web address becomes a link (${JSON.stringify(links)})`);
ok(links && /noopener/.test(links[0].rel) && /noreferrer/.test(links[0].rel) && links[0].target === '_blank',
  'and it opens apart from this page, sending no referrer');

// A pasted screenshot goes out as an attachment, not as nothing.
await alice.eval(`(async () => {
  const canvas = new OffscreenCanvas(20, 10);
  canvas.getContext('2d').fillRect(0, 0, 20, 10);
  const blob = await canvas.convertToBlob({ type: 'image/png' });
  const data = new DataTransfer();
  data.items.add(new File([blob], 'Screenshot 2026-10-15 at 10.11.12.png', { type: 'image/png' }));
  document.querySelector('#msg-input').dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true }));
  return true;
})()`);
const pasted = await waitFor(() => bob.eval(`(() => {
  const link = [...document.querySelectorAll('.file-download')].find((a) => a.getAttribute('download') === 'photo.png');
  return !!link && !!link.closest('.file-msg').querySelector('.file-preview-img');
})()`), { timeout: 20000 });
ok(pasted, 'a pasted screenshot arrives as an image, under a neutral name');

// Copying from a word processor puts a picture of the selection beside the
// text. That is a text paste, and must not send the picture.
const before = await bob.eval(`document.querySelectorAll('.file-msg').length`);
await alice.eval(`(async () => {
  const canvas = new OffscreenCanvas(20, 10);
  canvas.getContext('2d').fillRect(0, 0, 20, 10);
  const blob = await canvas.convertToBlob({ type: 'image/png' });
  const data = new DataTransfer();
  data.setData('text/plain', 'quarterly numbers');
  data.items.add(new File([blob], 'image.png', { type: 'image/png' }));
  document.querySelector('#msg-input').dispatchEvent(new ClipboardEvent('paste', { clipboardData: data, bubbles: true, cancelable: true }));
  return true;
})()`);
await sleep(2500);
ok(await bob.eval(`document.querySelectorAll('.file-msg').length`) === before,
  'pasting text that comes with a picture of itself sends no picture');

// A bracket that closes one inside the address belongs to it.
const wiki = 'read https://en.wikipedia.org/wiki/Foo_(bar) (and https://example.org/x).';
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(wiki)};
  document.querySelector('#send-btn').click(); true
`);
const wikiLinks = await waitFor(() => bob.eval(`(() => {
  const bubble = [...document.querySelectorAll('.msg-text')].find((n) => n.textContent === ${JSON.stringify(wiki)});
  return bubble && [...bubble.querySelectorAll('a')].map((a) => a.textContent);
})()`), { timeout: 10000 });
ok(JSON.stringify(wikiLinks) === JSON.stringify(['https://en.wikipedia.org/wiki/Foo_(bar)', 'https://example.org/x']),
  `brackets: kept inside an address, dropped around one (${JSON.stringify(wikiLinks)})`);

// A lookalike host is shown as what it is. "аpple.com" below begins with a
// Cyrillic а; the link must not read as apple.com.
const homograph = 'login at https://\u0430pple.com/account now';
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(homograph)};
  document.querySelector('#send-btn').click(); true
`);
const spoof = await waitFor(() => bob.eval(`(() => {
  const a = [...document.querySelectorAll('.msg-link')].find((l) => l.getAttribute('href').includes('xn--'));
  return a && { text: a.textContent, href: a.getAttribute('href') };
})()`), { timeout: 10000 });
ok(spoof && spoof.text === spoof.href && spoof.text.includes('xn--pple'),
  `a lookalike host is shown in punycode, not as the name it imitates (${spoof?.text})`);

// A voice note is named for what it is, not for when it was made: a
// timestamped name handed the other side the sender's clock to the
// millisecond.
await alice.eval(`document.querySelector('#record-btn').click(); true`);
const recHint = await waitFor(() => alice.eval(
  `document.querySelector('.chat-footer.recording') && document.querySelector('#msg-input').placeholder`), { timeout: 10000 });
ok(/🔴/.test(recHint || ''), `recording is visible while the microphone is live (${recHint || 'no sign'})`);
await sleep(1200);
await alice.eval(`document.querySelector('#record-btn').click(); true`);
const voice = await waitFor(() => bob.eval(`(() => {
  const link = [...document.querySelectorAll('.file-download')]
    .find((a) => /^voice/.test(a.getAttribute('download')));
  return link && { name: link.getAttribute('download'),
    label: link.closest('.file-msg').querySelector('.file-name').textContent };
})()`), { timeout: 30000 });
ok(voice && /^voice\.(webm|ogg|m4a)$/.test(voice.name), `a voice note carries no timestamp (${voice?.name})`);
ok(voice && voice.label === '🎙️ Voice message', `and is shown as a voice message (${voice?.label})`);
ok(await alice.eval(`!document.querySelector('.chat-footer.recording')
  && document.querySelector('#msg-input').placeholder !== ''
  && !/🔴/.test(document.querySelector('#msg-input').placeholder)`),
  'the recording sign clears once the note is sent');

// Stopping sends, so a recording needs a way to be thrown away: the discard
// button ends the microphone at once and nothing reaches the other side.
const voicesAtBob = () => bob.eval(`[...document.querySelectorAll('.file-download')]
  .filter((a) => /^voice/.test(a.getAttribute('download'))).length`);
const voicesBefore = await voicesAtBob();
await alice.eval(`(() => {
  const real = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  navigator.mediaDevices.getUserMedia = async (c) => (window.__mic = await real(c));
  document.querySelector('#record-btn').click();
  return true;
})()`);
ok(await waitFor(() => alice.eval(`!!document.querySelector('.chat-footer.recording')
  && !document.querySelector('#rec-cancel-btn').classList.contains('hidden')`), { timeout: 10000 }),
  'while recording, a discard button is offered');
await sleep(800);
await alice.eval(`document.querySelector('#rec-cancel-btn').click(); true`);
const discarded = await alice.eval(`({
  live: window.__mic.getTracks().some((tr) => tr.readyState === 'live'),
  recording: !!document.querySelector('.chat-footer.recording'),
  hidden: document.querySelector('#rec-cancel-btn').classList.contains('hidden'),
  note: [...document.querySelectorAll('.msg.system')].some((n) => /discarded/.test(n.textContent)),
})`);
ok(!discarded.live && !discarded.recording && discarded.hidden && discarded.note,
  `discarding ends the microphone and says nothing was sent (${JSON.stringify(discarded)})`);
await sleep(2500);
ok(await voicesAtBob() === voicesBefore, 'and no voice note reaches the other side');

// Two taps while the microphone prompt is open must not open two streams:
// the first would be orphaned, live, with no button left to stop it.
await alice.eval(`(() => {
  const real = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  window.__mics = [];
  navigator.mediaDevices.getUserMedia = (c) => new Promise((resolve) => setTimeout(async () => {
    const stream = await real(c);
    window.__mics.push(stream);
    resolve(stream);
  }, 800));
  window.__restoreGum = () => { navigator.mediaDevices.getUserMedia = real; };
  document.querySelector('#record-btn').click();
  document.querySelector('#record-btn').click();
  return true;
})()`);
await waitFor(() => alice.eval(`!!document.querySelector('.chat-footer.recording')`), { timeout: 10000 });
await sleep(1200);
await alice.eval(`document.querySelector('#rec-cancel-btn').click(); window.__restoreGum(); true`);
const mics = await alice.eval(`window.__mics.map((m) => m.getTracks().some((tr) => tr.readyState === 'live'))`);
ok(mics.length === 1 && !mics[0], `a double tap opens one microphone, and discard ends it (${JSON.stringify(mics)})`);


// ── Second session: a saved contact must not need a new comparison ──
// Fresh pages in the same browser contexts, so cookies and the pinned identity
// survive exactly as they would for a returning user.
//
// B is recording when A goes. The record button is also the stop button and
// is disabled once nobody verified is left, so the microphone must not be
// left running with no way to end it.
await bob.eval(`(() => {
  const real = navigator.mediaDevices.getUserMedia.bind(navigator.mediaDevices);
  navigator.mediaDevices.getUserMedia = async (c) => (window.__mic = await real(c));
  document.querySelector('#record-btn').click();
  return true;
})()`);
ok(await waitFor(() => bob.eval(`!!document.querySelector('.chat-footer.recording')`), { timeout: 10000 }),
  'B is recording a voice note');
await alice.goto(BASE + '/');
const orphaned = await waitFor(() => bob.eval(`(() => {
  const note = [...document.querySelectorAll('.msg.system')].find((n) => /nobody verified/.test(n.textContent));
  return note && {
    live: window.__mic.getTracks().some((tr) => tr.readyState === 'live'),
    recording: !!document.querySelector('.chat-footer.recording'),
  };
})()`), { timeout: 20000 });
ok(orphaned && !orphaned.live && !orphaned.recording,
  `when the peer leaves mid-recording the microphone stops and the reason is shown (${JSON.stringify(orphaned)})`);
// Left alone, B reads who went and what the room is waiting for now.
const leftNote = await waitFor(async () => (await bob.notices()).find((line) => line.includes('👋')) || false,
  { timeout: 15000 });
ok(leftNote && /^👋 \S.* (left the room|disconnected)$/.test(leftNote), `the departure names who left, first (${leftNote})`);
ok(await waitFor(() => bob.eval(`document.querySelector('#msg-input').placeholder === 'Waiting for someone to join…'`)),
  'the disabled message field says it is waiting for someone, not "Type a message"');
await bob.goto(BASE + '/');
await waitFor(() => alice.eval(`!document.querySelector('#landing').classList.contains('hidden')`));
await waitFor(() => bob.eval(`!document.querySelector('#landing').classList.contains('hidden')`));

await alice.eval(`document.querySelector('#create-room').click(); true`);
const room2 = await waitFor(async () => {
  const code = await alice.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
await bob.eval(`
  document.querySelector('#room-code-input').value = ${JSON.stringify(room2)};
  document.querySelector('#join-room').click(); true
`);
ok(await waitFor(() => bob.inChat()), 'the saved contacts reconnect in a new room');

const autoA = await waitFor(() => alice.verified(), { timeout: 30000 });
const autoB = await waitFor(() => bob.verified(), { timeout: 30000 });
ok(autoA && autoB,
  'a recognised contact unlocks without anyone comparing a code again');

const secret2 = 'second session ' + suffix;
await alice.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(secret2)};
  document.querySelector('#send-btn').click(); true
`);
ok(await waitFor(async () => (await bob.transcript()).includes(secret2)),
  'the reconnected pair exchanges messages');

ok(alice.errors.length === 0 && bob.errors.length === 0,
  `no uncaught exceptions in either peer${
    [...alice.errors, ...bob.errors].length ? ': ' + [...alice.errors, ...bob.errors][0] : ''}`);

cdp.close();
cleanup();
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
