/**
 * Guest test: someone with no account, let into one room by a link.
 *
 *   DD_URL=… DD_INVITE=… node test/browser.guest.mjs
 *
 * A guest pass is a bearer token in a link, which is exactly the kind of thing
 * that turns into a hole: a session that was meant to open one door and opens
 * the building. So this checks the feature from both ends. That it works —
 * the guest joins, compares a safety code and talks — and that the session it
 * gets is good for that room and nothing else, asked directly of the server
 * from the guest's own page rather than inferred from what the page shows.
 */

import { chooseDirectTransport, Peer, launchBrowser, waitFor, sleep } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITE = process.env.DD_INVITE || '';
const PASS = 'guest-test-passphrase-9034';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITE) {
  console.error('guest test: set DD_INVITE (one account)');
  process.exit(1);
}

const USER = `zz_gh_${Math.floor(Math.random() * 1e6)}`;
console.log(`Guest run against ${BASE} as ${USER} + a guest`);

const { cdp, cleanup } = await launchBrowser('guest');
const host = await Peer.open(cdp, 'host');
const guest = await Peer.open(cdp, 'guest');
const late = await Peer.open(cdp, 'latecomer');

await host.goto(BASE + '/');
ok(await host.register(USER, INVITE, PASS), 'the host registers');
await chooseDirectTransport(host);
await host.eval(`document.querySelector('#create-room').click(); true`);
const room = await waitFor(async () => {
  const code = await host.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
ok(room, 'the host creates a room');

console.log('\nthe link');
const plain = await waitFor(() => host.eval(`document.querySelector('.share-url')?.textContent || false`));
ok(new RegExp(`#join=${room}$`).test(plain || ''), 'the ordinary invitation carries no pass: none exists until one is asked for');
await host.eval(`document.querySelector('.guest-link-btn').click(); true`);
const link = await waitFor(() => host.eval(`(() => {
  const url = document.querySelector('.share-url')?.textContent || '';
  return /&guest=[0-9a-f]{32}$/.test(url) ? url : false;
})()`), { timeout: 10000 });
ok(link && link.includes(`#join=${room}&guest=`), 'asked for, the host gets a guest link for this room');
const box = await host.eval(`({
  intro: document.querySelector('.share-intro').textContent,
  again: !!document.querySelector('.guest-link-btn'),
  links: document.querySelectorAll('.share-link').length,
})`);
ok(/guest/i.test(box.intro) && /once/i.test(box.intro) && !box.again && box.links === 1,
  `the box says what kind of link it now holds (${box.intro})`);
ok(await waitFor(() => host.eval(`!!document.querySelector('.share-link .share-qr')`), { timeout: 10000 }),
  'and its QR code is redrawn for it');
// A second pass, for later: it must die when the host signs out.
const spare = await host.eval(`fetch('/api/guest', { method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ room: ${JSON.stringify(room)} }) }).then((r) => r.json()).then((d) => d.token)`);
ok(/^[0-9a-f]{32}$/.test(spare || ''), 'a second pass can be made for the same room');

console.log('\narriving without an account');
await guest.goto(link);
const offered = await waitFor(() => guest.eval(`(() => {
  const block = document.querySelector('#auth-guest');
  if (document.querySelector('#auth').classList.contains('hidden') || block.classList.contains('hidden')) return false;
  return { hash: location.hash, note: block.textContent.trim(), plainNote: !document.querySelector('#auth-invited').classList.contains('hidden') };
})()`), { timeout: 15000 });
ok(offered && offered.hash === '' && !offered.plainNote,
  'the visitor is offered the room as a guest, and the pass is taken out of the address bar');
await guest.eval(`document.querySelector('#guest-join-btn').click(); true`);
const landed = await waitFor(() => guest.eval(`(() => {
  const landing = document.querySelector('#landing');
  if (landing.classList.contains('hidden')) return false;
  const shown = (sel) => getComputedStyle(document.querySelector(sel)).display !== 'none';
  return {
    create: shown('#create-room'), settings: shown('#settings-btn'),
    room: document.querySelector('#room-code-input').value,
    fixed: document.querySelector('#room-code-input').readOnly,
    name: document.querySelector('#user-display').textContent,
    note: document.querySelector('#landing-invited').textContent,
  };
})()`), { timeout: 15000 });
ok(landed && !landed.create && !landed.settings && landed.room === room && landed.fixed,
  `the guest gets its one room and nothing to create or configure (${JSON.stringify(landed)})`);
ok(landed && /guest/i.test(landed.name) && /guest/i.test(landed.note), 'and is told it is a guest');

await chooseDirectTransport(guest);
await guest.eval(`document.querySelector('#join-room').click(); true`);
ok(await waitFor(() => guest.inChat()), 'the guest joins the room');

console.log('\na guest is verified like anyone else');
const sasHost = await waitFor(() => host.sas(), { timeout: 30000 });
const sasGuest = await waitFor(() => guest.sas(), { timeout: 30000 });
ok(sasHost && sasGuest && sasHost === sasGuest, `both sides derive the same safety code (${sasHost} / ${sasGuest})`);
ok(await host.verified() === false && await guest.verified() === false,
  'getting in with a pass unlocks nothing: the conversation stays locked until the code is confirmed');
await host.clickVerify();
await guest.clickVerify();
ok(await waitFor(() => host.verified()) && await waitFor(() => guest.verified()), 'both confirm the safety code');
const say = (peer, text) => peer.eval(`
  document.querySelector('#msg-input').value = ${JSON.stringify(text)};
  document.querySelector('#send-btn').click(); true
`);
await say(host, 'welcome, guest');
ok(await waitFor(async () => (await guest.transcript()).includes('welcome, guest')), 'the guest receives a message');
await say(guest, 'thanks for the link');
ok(await waitFor(async () => (await host.transcript()).includes('thanks for the link')), 'and the host receives the reply');
ok(await guest.eval(`!document.querySelector('.guest-link-btn')`), 'a guest is not offered guest links to hand on');

console.log('\nwhat the guest session can reach, asked of the server');
const reach = await guest.eval(`(async () => {
  const post = (path, body) => fetch(path, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body || {}),
  }).then((r) => r.status);
  return {
    room: await post('/api/room'),
    pass: await post('/api/guest', { room: ${JSON.stringify(room)} }),
    verifier: await post('/api/account/verifier'),
    duress: await post('/api/account/duress'),
    remove: await post('/api/account/delete'),
    others: await post('/api/account/signout-others'),
    turn: await fetch('/api/turn').then((r) => r.status),
    me: await fetch('/api/me').then((r) => r.json()),
  };
})()`);
ok(reach.room === 403, `it cannot open rooms of its own (${reach.room})`);
ok(reach.pass === 403, `it cannot mint passes (${reach.pass})`);
ok([reach.verifier, reach.duress, reach.remove, reach.others].every((s) => s === 403),
  `it cannot touch any account setting (${[reach.verifier, reach.duress, reach.remove, reach.others].join(', ')})`);
ok(reach.turn === 200, 'it can ask for relay settings, so a guest hides its address the same way an account does');
ok(reach.me.guest === true && reach.me.room === room && reach.me.username === 'guest'
  && !JSON.stringify(reach.me).includes(USER),
  `the server describes it as a guest of that room, without naming who invited it (${JSON.stringify(reach.me)})`);
const elsewhere = await guest.eval(`new Promise((resolve) => {
  const ws = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/ws');
  const seen = [];
  ws.onmessage = (e) => {
    const m = JSON.parse(e.data);
    seen.push(m.type + (m.error ? ':' + m.error : ''));
    if (m.type === 'welcome') ws.send(JSON.stringify({ type: 'join', room: '0123456789abcdef01234567' }));
    else { ws.close(); resolve(seen.join(' ')); }
  };
  ws.onerror = () => resolve('socket error');
  setTimeout(() => resolve(seen.join(' ') || 'nothing heard'), 8000);
})`);
ok(/^welcome error:invalid room code$/.test(elsewhere), `a second connection of its own cannot join any other room (${elsewhere})`);

console.log('\nthe pass works once');
await late.goto(link);
await waitFor(() => late.eval(`!document.querySelector('#auth-guest').classList.contains('hidden')`), { timeout: 15000 });
await late.eval(`document.querySelector('#guest-join-btn').click(); true`);
const refused = await waitFor(() => late.eval(`(() => {
  const err = document.querySelector('#auth-error');
  return !err.classList.contains('hidden') && err.textContent ? {
    text: err.textContent,
    offer: !document.querySelector('#auth-guest').classList.contains('hidden'),
    auth: !document.querySelector('#auth').classList.contains('hidden'),
  } : false;
})()`), { timeout: 15000 });
ok(refused && refused.auth && !refused.offer && /no longer works/i.test(refused.text),
  `someone opening the same link afterwards is told it is spent, and stays signed out (${refused && refused.text})`);
ok(await late.eval(`fetch('/api/me').then((r) => r.status)`) === 401, 'with no session of any kind');

console.log('\nreload, and leaving');
await guest.goto(BASE + '/');
const back = await waitFor(() => guest.eval(`(() => {
  const landing = document.querySelector('#landing');
  return !landing.classList.contains('hidden') && landing.classList.contains('guest')
    && document.querySelector('#room-code-input').value;
})()`), { timeout: 15000 });
ok(back === room, 'after a reload the guest is still a guest of the same room, and of no other');

// A guest of this room who opens a link to another one must not be walked
// into the room they already had: the page offers what the new link offers.
const otherRoom = 'fedcba9876543210fedcba98';
await guest.goto(`${BASE}/?other#join=${otherRoom}`); // the query forces a real navigation
const sent = await waitFor(() => guest.eval(`(() => {
  const auth = !document.querySelector('#auth').classList.contains('hidden');
  const landing = !document.querySelector('#landing').classList.contains('hidden');
  if (!auth && !landing) return false;
  return { auth, invited: !document.querySelector('#auth-invited').classList.contains('hidden') };
})()`), { timeout: 15000 });
ok(sent && sent.auth && sent.invited,
  `a guest who opens an invitation to a different room is asked to sign in, not put back in its own (${JSON.stringify(sent)})`);
await guest.goto(BASE + '/');
await waitFor(() => guest.eval(`!document.querySelector('#landing').classList.contains('hidden')`), { timeout: 15000 });
ok(await guest.eval(`document.querySelector('#user-display').dataset.i18n === 'guest.name'`),
  'the guest label follows the language switch');

await guest.eval(`document.querySelector('#logout-btn').click(); true`);
ok(await waitFor(() => guest.eval(`!document.querySelector('#auth').classList.contains('hidden')
  && document.querySelector('#auth-guest').classList.contains('hidden')`), { timeout: 10000 }),
  'signing out puts the guest back at the sign-in page, with no pass left to use');
ok(await waitFor(() => guest.eval(`fetch('/api/me').then((r) => r.status === 401)`), { timeout: 10000 }),
  'and the server no longer holds its session');

console.log('\na pass dies with the session that made it');
await host.goto(BASE + '/');
await waitFor(() => host.eval(`!document.querySelector('#landing').classList.contains('hidden')`), { timeout: 15000 });
await host.eval(`document.querySelector('#logout-btn').click(); true`);
await waitFor(() => host.eval(`fetch('/api/me').then((r) => r.status === 401)`), { timeout: 10000 });
const orphan = await late.eval(`fetch('/api/guest/redeem', { method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ token: ${JSON.stringify(spare)} }) }).then((r) => r.status)`);
ok(orphan === 403, `once the host has signed out, the link it left behind opens nothing (${orphan})`);

const errors = [...host.errors, ...guest.errors, ...late.errors];
ok(errors.length === 0, `no uncaught exceptions${errors.length ? ': ' + errors[0] : ''}`);

cdp.close();
cleanup();
await sleep(100);
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
