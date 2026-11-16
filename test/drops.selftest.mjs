/**
 * Messages left for an offline contact: the ratchet, the names, and what a
 * device seized afterwards can and cannot open.
 */

import {
  mintInbox, acceptCapability, sealDrop, namesToCheck, openDrop, tidyRecord, DROP_WINDOW, MAX_DROP_TEXT,
} from '../web/js/drops.js';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };
const rejects = async (fn) => { try { await fn(); return false; } catch { return true; } };

// Alice opens an inbox for Bob and hands him its capability.
let alice = mintInbox(null);
const capability = alice.capability;
let aliceRecord = alice.record;
let bobRecord = acceptCapability(null, capability);

console.log('leaving and collecting');
ok(bobRecord?.outbox && capability.n === 0 && typeof capability.chain === 'string',
  'a contact takes the inbox it was handed');
ok(acceptCapability(null, { chain: capability.chain, n: 3 }) === null
  && acceptCapability(null, { chain: 'AAAA', n: 0 }) === null,
  'a capability that does not start a fresh chain, or is not 32 bytes, is refused');

const sent = [];
for (const text of ['first', 'second', 'third']) {
  const sealed = await sealDrop(bobRecord, { text, readTtl: 30, burn: text === 'second' });
  sent.push(sealed);
  bobRecord = sealed.advance();
}
ok(new Set(sent.map((s) => s.id)).size === 3 && sent.every((s) => /^[0-9a-f]{32}$/.test(s.id)),
  'every message has a name of its own');
const lengths = new Set(sent.map((s) => s.box.length));
ok(lengths.size === 1, `messages of different lengths are boxes of one size (${[...lengths]})`);

const names = await namesToCheck(aliceRecord);
ok(names.length === DROP_WINDOW && sent.every((s, i) => names[i].id === s.id),
  'the recipient knows the next names to look for without being told');

// Collected out of order: the third first, then the first, then the second.
let opened = await openDrop(aliceRecord, names[2], sent[2].box, sent[2].iv);
aliceRecord = opened.record;
ok(opened.message.text === 'third' && opened.message.readTtl === 30, 'a later message opens before earlier ones');
const afterSkip = await namesToCheck(aliceRecord);
ok(afterSkip.some((n) => n.id === sent[0].id) && afterSkip.some((n) => n.id === sent[1].id),
  'the ones skipped on the way are still looked for');
opened = await openDrop(aliceRecord, names[0], sent[0].box, sent[0].iv);
aliceRecord = opened.record;
opened = await openDrop(aliceRecord, names[1], sent[1].box, sent[1].iv);
aliceRecord = opened.record;
ok(opened.message.text === 'second' && opened.message.burn === true, 'and open when they turn up');
ok(aliceRecord.inbox[0].skipped.length === 0, 'and once collected their keys are gone');

console.log('what a box cannot be made to do');
const replay = await rejects(() => openDrop(aliceRecord, names[1], sent[1].box, sent[1].iv));
ok(replay, 'a box opened once does not open again');
const fourth = await sealDrop(bobRecord, { text: 'fourth' });
const nextNames = await namesToCheck(aliceRecord);
ok(await rejects(() => openDrop(aliceRecord, { ...nextNames[0] }, fourth.box.replace(/^./, (c) => (c === 'A' ? 'B' : 'A')), fourth.iv)),
  'a box altered on the server does not open');
ok(await rejects(() => openDrop(aliceRecord, { ...nextNames[1], id: fourth.id }, fourth.box, fourth.iv)),
  'nor does one filed under another position');
const unchanged = tidyRecord(aliceRecord);
ok(unchanged.inbox[0].next === 3, 'and a box that does not open moves nothing on');
ok(await rejects(() => sealDrop(bobRecord, { text: 'x'.repeat(MAX_DROP_TEXT + 1) })), 'a message over the limit is refused');
ok(await rejects(() => sealDrop(tidyRecord(null), { text: 'hello' })), 'nothing can be left without an inbox to leave it in');

console.log('a device seized afterwards');
// Everything Alice's browser holds now, handed to someone who also recorded
// every box the server ever stored.
const seized = tidyRecord(aliceRecord);
const fromSeized = await namesToCheck(seized);
for (const [i, s] of sent.entries()) {
  const tries = await Promise.all(fromSeized.map((name) => openDrop(seized, name, s.box, s.iv).then(() => true, () => false)));
  ok(!tries.some(Boolean), `message ${i + 1}, already collected, cannot be opened from what remains`);
}
ok(!fromSeized.some((n) => sent.some((s) => s.id === n.id)), 'nor are its old names among the ones it can still derive');

console.log('a fresh inbox at every meeting');
alice = mintInbox(aliceRecord);
aliceRecord = alice.record;
ok(aliceRecord.inbox.length === 2 && aliceRecord.inbox[1].retired > 0,
  'meeting again opens a new inbox and keeps the old one while anything could still be in it');
const stillQueued = fourth;
const oldNames = await namesToCheck(aliceRecord);
ok(oldNames.some((n) => n.id === stillQueued.id), 'a message left in the old inbox is still found');
const later = tidyRecord(aliceRecord, Date.now() + 8 * 24 * 3600 * 1000);
ok(later.inbox.length === 1, 'and the old one goes once nothing left in it could still be waiting');
bobRecord = acceptCapability(bobRecord, alice.capability);
const viaNew = await sealDrop(bobRecord, { text: 'new inbox' });
const newNames = await namesToCheck(aliceRecord);
const target = newNames.find((n) => n.id === viaNew.id);
ok(target && target.inbox === aliceRecord.inbox[0].id, 'the contact now leaves messages in the new one');
ok((await openDrop(aliceRecord, target, viaNew.box, viaNew.iv)).message.text === 'new inbox', 'which open');
for (let i = 0; i < 3; i++) aliceRecord = mintInbox(aliceRecord).record;
ok(aliceRecord.inbox.length === 3, 'at most three inboxes are kept per contact');

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
