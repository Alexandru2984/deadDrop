/**
 * Messages left for an offline contact.
 *
 *   DD_URL=… DD_INVITE=… DD_INVITE2=… node test/browser.drops.mjs
 *
 * Two people meet once, compare the safety code and save each other. From
 * then on either can leave the other a message that waits on the server until
 * collected. This checks the whole of it between two real browsers: the keys
 * handed over in the verified session, a message left while the other is not
 * in any room, what the server was given, collecting it, and that collecting
 * is the end of it.
 */

import { chooseDirectTransport, Peer, launchBrowser, waitFor, sleep } from './lib/browser.mjs';

const BASE = process.env.DD_URL || 'http://127.0.0.1:8100';
const INVITES = [process.env.DD_INVITE || '', process.env.DD_INVITE2 || ''];
const PASS = 'drops-test-passphrase-5521';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

if (!INVITES[0] || !INVITES[1]) {
  console.error('drops test: set DD_INVITE and DD_INVITE2 (one account each)');
  process.exit(1);
}

const suffix = Math.floor(Math.random() * 1e6);
const USERS = [`zz_da_${suffix}`, `zz_db_${suffix}`];
console.log(`Drops run against ${BASE} as ${USERS[0]} + ${USERS[1]}`);

const { cdp, cleanup } = await launchBrowser('drops');
const alice = await Peer.open(cdp, 'alice');
const bob = await Peer.open(cdp, 'bob');

const home = async (peer, contactName) => {
  await peer.goto(BASE + '/');
  await peer.eval(`window.prompt = () => ${JSON.stringify(contactName)}; true`);
  await waitFor(() => peer.eval(`!document.querySelector('#landing').classList.contains('hidden')`), { timeout: 15000 });
};

await alice.goto(BASE + '/');
await bob.goto(BASE + '/');
ok(await alice.register(USERS[0], INVITES[0], PASS), 'A registers');
ok(await bob.register(USERS[1], INVITES[1], PASS), 'B registers');
await alice.eval(`window.prompt = () => 'Bob'; true`);
await bob.eval(`window.prompt = () => 'Alice'; true`);

console.log('\nbefore they have met');
ok(await alice.eval(`document.querySelector('#drops-compose').classList.contains('hidden')`),
  'with saved contacts off, there is nobody to leave a message for and nothing is shown');
await alice.enableSavedContacts();
await bob.enableSavedContacts();
ok(await alice.eval(`document.querySelector('#drops-compose').classList.contains('hidden')`),
  'nor with them on, until someone has been met and saved');

console.log('\nmeeting once');
// From here Bob's storage is slow, as a phone's or Tor Browser's can be: every
// opening of the database answers 300 ms late. Changes to his record of Alice
// then take long enough that the ones starting together overlap — every run,
// rather than the once in ten that made an inbox key go missing.
await bob.eval(`(() => {
  const open = IDBFactory.prototype.open;
  const onsuccess = Object.getOwnPropertyDescriptor(IDBRequest.prototype, 'onsuccess');
  IDBFactory.prototype.open = function (...args) {
    const request = open.apply(this, args);
    Object.defineProperty(request, 'onsuccess', {
      configurable: true,
      get() { return onsuccess.get.call(this); },
      set(fn) { onsuccess.set.call(this, fn && ((e) => setTimeout(() => fn.call(this, e), 300))); },
    });
    return request;
  };
  return true;
})()`);
await chooseDirectTransport(alice);
await chooseDirectTransport(bob);
await alice.eval(`document.querySelector('#create-room').click(); true`);
const room = await waitFor(async () => {
  const code = await alice.eval(`document.querySelector('#room-code').textContent`);
  return code && code.length === 24 ? code : false;
});
await bob.eval(`
  document.querySelector('#room-code-input').value = ${JSON.stringify(room)};
  document.querySelector('#join-room').click(); true
`);
ok(await waitFor(() => bob.inChat()), 'they meet in a room');
await waitFor(() => alice.sas(), { timeout: 30000 });
await waitFor(() => bob.sas(), { timeout: 30000 });
await alice.clickVerify();
await bob.clickVerify();
ok(await waitFor(() => alice.verified()) && await waitFor(() => bob.verified()), 'compare the safety code');
ok(await waitFor(async () => (await alice.notices()).some((n) => n.includes('Bob')) && (await bob.notices()).some((n) => n.includes('Alice')), { timeout: 15000 }),
  'and save each other as contacts');
// The inbox keys travel over the verified channel just after. Each side mints
// a key to its own inbox and accepts the other's at about the same moment,
// both into the one record it keeps for that contact: done at once, the
// second write undid the first, and a lost inbox key meant the contact's
// messages could never be opened. Both keys, on both sides, and still both
// after a moment more.
const keys = (peer) => peer.eval(`(async () => {
  const db = await new Promise((resolve, reject) => {
    const r = indexedDB.open('deaddrop-identity');
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
  try {
    const all = await new Promise((resolve, reject) => {
      const q = db.transaction('drops').objectStore('drops').getAll();
      q.onsuccess = () => resolve(q.result);
      q.onerror = () => reject(q.error);
    });
    return all.map((r) => ({ inbox: (r.inbox || []).length, outbox: !!r.outbox }));
  } finally { db.close(); }
})()`);
const bothKeys = async (peer) => {
  const records = await keys(peer);
  return records.length === 1 && records[0].inbox === 1 && records[0].outbox;
};
await waitFor(async () => await bothKeys(alice) && await bothKeys(bob), { timeout: 10000 });
await sleep(1000);
ok(await bothKeys(alice) && await bothKeys(bob),
  `each keeps the key to its own inbox and to the other's (${JSON.stringify([await keys(alice), await keys(bob)])})`);

console.log('\na message left while the other is away');
await home(bob, 'Alice');
// Bob is on the landing page, in no room: offline as far as Alice can tell.
await home(alice, 'Bob');
const compose = await waitFor(() => alice.eval(`(() => {
  const box = document.querySelector('#drops-compose');
  if (box.classList.contains('hidden')) return false;
  return [...document.querySelectorAll('#drops-to option')].map((o) => o.textContent);
})()`), { timeout: 15000 });
ok(compose && compose.length === 1 && compose[0] === 'Bob', `A can leave a message for the contact she met (${JSON.stringify(compose)})`);

await alice.eval(`(() => {
  window.__dropBodies = [];
  const real = window.fetch;
  window.fetch = (url, init) => {
    if (String(url) === '/api/drop') window.__dropBodies.push(init.body);
    return real(url, init);
  };
  return true;
})()`);
const SECRET = `meet me at the usual place ${suffix}`;
const leave = (text, readTtl = '0') => alice.eval(`(() => {
  document.querySelector('#drops-compose').open = true;
  document.querySelector('#drops-text').value = ${JSON.stringify(text)};
  document.querySelector('#drops-expiry').value = '86400';
  document.querySelector('#drops-read').value = ${JSON.stringify(readTtl)};
  document.querySelector('#drops-send').click();
  return true;
})()`);
await leave(SECRET, '30');
const status = await waitFor(() => alice.eval(`(() => {
  const el = document.querySelector('#drops-status');
  return !el.classList.contains('hidden') && el.textContent ? { text: el.textContent, ok: el.classList.contains('ok') } : false;
})()`), { timeout: 15000 });
ok(status?.ok && /Left for Bob/.test(status.text) && /a day/.test(status.text), `A is told it was left, and for how long it waits (${status?.text})`);
ok(await alice.eval(`document.querySelector('#drops-text').value === ''`), 'and the composer is emptied');
const bodies = await alice.eval(`window.__dropBodies`);
const sent = bodies.length === 1 && JSON.parse(bodies[0]);
ok(sent && /^[0-9a-f]{32}$/.test(sent.id) && sent.ttl === 86400
  && !bodies[0].includes('meet me') && !bodies[0].includes(USERS[1]) && !bodies[0].includes('Bob'),
  'the server is given a sealed box under a meaningless name — no text, no recipient');

console.log('\ncollecting it');
await home(bob, 'Alice');
const waiting = await waitFor(() => bob.eval(`(() => {
  const rows = [...document.querySelectorAll('.drop-waiting')];
  return rows.length ? rows.map((r) => r.querySelector('.drop-from').textContent) : false;
})()`), { timeout: 15000 });
ok(waiting && waiting.length === 1 && /Alice left you a message/.test(waiting[0]),
  `B is told Alice left him a message, before anything is opened (${JSON.stringify(waiting)})`);
ok(await bob.eval(`!document.body.textContent.includes(${JSON.stringify(SECRET)})`), 'its text stays sealed until he opens it');
await bob.eval(`document.querySelector('.drop-waiting button').click(); true`);
const opened = await waitFor(() => bob.eval(`(() => {
  const card = document.querySelector('.drop-opened');
  return card ? {
    from: card.querySelector('.drop-from').textContent,
    text: card.querySelector('.drop-text').textContent,
    countdown: card.querySelector('.drop-countdown')?.textContent || null,
  } : false;
})()`), { timeout: 15000 });
ok(opened && opened.text === SECRET && /Alice/.test(opened.from), `opening it shows what Alice wrote (${opened?.text})`);
ok(opened && /^\d+s$/.test(opened.countdown || ''), `with the time it stays on screen counting down (${opened?.countdown})`);

await home(bob, 'Alice');
await sleep(1500);
ok(await bob.eval(`!document.querySelector('.drop-waiting') && !document.body.textContent.includes(${JSON.stringify(SECRET)})`),
  'once collected it is gone: a reload shows nothing waiting and nothing kept');

console.log('\nseveral at once, opened in any order');
await home(alice, 'Bob');
await waitFor(() => alice.eval(`!document.querySelector('#drops-compose').classList.contains('hidden')`), { timeout: 15000 });
for (const n of [1, 2, 3]) {
  await leave(`note ${n} ${suffix}`);
  await waitFor(() => alice.eval(`document.querySelector('#drops-text').value === ''`), { timeout: 15000 });
}
await home(bob, 'Alice');
const three = await waitFor(() => bob.eval(`document.querySelectorAll('.drop-waiting').length === 3`), { timeout: 15000 });
ok(three, 'three messages left are three waiting');
await bob.eval(`document.querySelectorAll('.drop-waiting button')[2].click(); true`);
await waitFor(() => bob.eval(`document.querySelectorAll('.drop-opened').length === 1`), { timeout: 15000 });
await bob.eval(`document.querySelector('.drop-waiting button').click(); true`);
await waitFor(() => bob.eval(`document.querySelectorAll('.drop-opened').length === 2`), { timeout: 15000 });
await bob.eval(`document.querySelector('.drop-waiting button').click(); true`);
const texts = await waitFor(() => bob.eval(`(() => {
  const all = [...document.querySelectorAll('.drop-opened .drop-text')].map((n) => n.textContent);
  return all.length === 3 ? all.sort() : false;
})()`), { timeout: 15000 });
ok(texts && texts.join('|') === [1, 2, 3].map((n) => `note ${n} ${suffix}`).join('|'),
  `opened out of order, every one opens (${JSON.stringify(texts)})`);
await bob.eval(`document.querySelector('.drop-opened button').click(); true`);
ok(await bob.eval(`document.querySelectorAll('.drop-opened').length === 2`), 'and one can be closed, which takes it off the screen');

console.log('\nwhat a panic wipe leaves');
await leave(`after the wipe ${suffix}`);
await waitFor(() => alice.eval(`document.querySelector('#drops-text').value === ''`), { timeout: 15000 });
await bob.eval(`for (let i = 0; i < 3; i++) window.dispatchEvent(new KeyboardEvent('keydown', { key: 'Escape' })); true`);
await waitFor(() => bob.eval(`!document.querySelector('#auth')?.classList.contains('hidden')`), { timeout: 20000 });
await sleep(500);
const afterWipe = await bob.eval(`(async () => {
  const dbs = await indexedDB.databases();
  if (!dbs.some((d) => d.name === 'deaddrop-identity')) return 'no store';
  return await new Promise((resolve) => {
    const req = indexedDB.open('deaddrop-identity');
    req.onsuccess = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains('drops')) { db.close(); resolve('no drops store'); return; }
      const all = db.transaction('drops').objectStore('drops').count();
      all.onsuccess = () => { db.close(); resolve(all.result); };
    };
    req.onerror = () => resolve('unreadable');
  });
})()`);
ok(afterWipe === 'no store' || afterWipe === 'no drops store' || afterWipe === 0,
  `a panic wipe takes every inbox key with it (${afterWipe})`);

const errors = [...alice.errors, ...bob.errors];
ok(errors.length === 0, `no uncaught exceptions${errors.length ? ': ' + errors[0] : ''}`);

cdp.close();
cleanup();
await sleep(100);
console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
