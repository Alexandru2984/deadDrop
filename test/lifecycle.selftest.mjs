/** Bounded file-transfer and peer-scoped message lifecycle self-test. */

import {
  FileTransferManager, assertFileSizeBinding, safeFileMeta,
  PART_SIZE, MAX_FILE_SIZE, AUTO_ACCEPT_SIZE, MAX_PART_WIRE_BYTES, SEND_PACE, partsFor,
} from '../web/js/filetransfer.js';
import { MAX_BYTES_PER_WINDOW, MAX_MESSAGES_PER_WINDOW, MAX_DATA_CHANNEL_MESSAGE } from '../web/js/peer.js';
import { CryptoLayer, PROTOCOL_VERSION } from '../web/js/crypto.js';
import { Handshake } from '../web/js/handshake.js';
import { MessageManager } from '../web/js/messages.js';
import { scrubbedName } from '../web/js/scrub.js';

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log('  ✓', message);
  else { console.error('  ✗', message); failures++; }
};

const id = () => crypto.randomUUID();
const rejectsSizeBinding = (...args) => {
  try { assertFileSizeBinding(...args); return false; } catch { return true; }
};

/** Two crypto layers that completed a real handshake with each other. */
async function pairedLayers() {
  const a = new CryptoLayer(), b = new CryptoLayer();
  const outA = [], outB = [];
  const hsA = new Handshake(a, (m) => outA.push(m), { onEstablished() {}, onError() {} });
  const hsB = new Handshake(b, (m) => outB.push(m), { onEstablished() {}, onError() {} });
  await hsA.start();
  await hsB.start();
  for (let guard = 0; guard < 50 && (outA.length || outB.length); guard++) {
    while (outA.length) await hsB.handle(outA.shift());
    while (outB.length) await hsA.handle(outB.shift());
  }
  if (!a.established || !b.established) throw new Error('handshake did not complete');
  return { a, b };
}

/** A file whose bytes are a function of their position, read lazily. */
function patterned(size, name = 'data.bin', type = 'application/octet-stream') {
  const bytes = new Uint8Array(size);
  for (let i = 0; i < size; i++) bytes[i] = (i * 31 + 7) & 0xff;
  return new File([bytes], name, { type });
}

/**
 * One sender and one receiver joined by an in-order channel. The receiver
 * does what the app does with each event; `answer` decides offers.
 */
function link(cryptoA, cryptoB, { answer = () => 'accept' } = {}) {
  const sender = new FileTransferManager();
  const receiver = new FileTransferManager();
  const wire = [];
  const events = [];
  let chain = Promise.resolve();
  const peer = {
    dc: { readyState: 'open', bufferedAmount: 0, addEventListener() {}, removeEventListener() {} },
    async send(message) {
      wire.push(message);
      chain = chain.then(async () => {
        const result = await receiver.handleMessage(structuredClone(message), 'from-a');
        if (!result) return;
        events.push(result);
        if (result.event === 'offer') {
          const meta = safeFileMeta(JSON.parse(await cryptoB.decrypt(result.meta.ciphertext, result.meta.iv, result.meta.epoch)));
          const choice = answer(result);
          if (choice === 'accept' && receiver.accept('from-a', result.id, cryptoB, meta) === 'ok') {
            sender.accepted('to-b', result.id);
          } else if (choice === 'refuse') {
            receiver.decline('from-a', result.id);
            sender.abortOutbound(result.id, 'to-b');
          }
        }
      });
      return JSON.stringify(message).length;
    },
  };
  const send = (file, fileId = id()) => sender.send(file, fileId, cryptoA, peer, 0, false, null, 'to-b');
  return { sender, receiver, wire, events, peer, send, settled: () => chain };
}

const { a, b } = await pairedLayers();

console.log('a file goes in sealed parts, and arrives whole');
{
  const size = 3 * PART_SIZE + 123;
  const file = patterned(size, 'notes.bin');
  const t = link(a, b);
  const sent = await t.send(file);
  await t.settled();
  ok(sent === true, 'the sender reports the whole file sent');
  ok(t.wire.map((m) => m.type).join(',') === 'file-offer,file-part,file-part,file-part,file-part,file-done',
    `an offer, one part per ${PART_SIZE / 1024} KB, and an end marker (${t.wire.map((m) => m.type).join(',')})`);
  const done = t.events.find((e) => e.event === 'complete');
  const got = done && new Uint8Array(await done.blob.arrayBuffer());
  const want = new Uint8Array(await file.arrayBuffer());
  ok(got && got.length === want.length && got.every((v, i) => v === want[i]),
    'the received file is byte for byte what was sent');
  ok(t.receiver.inbound.size === 0 && t.receiver._inboundBytes === 0,
    'a finished file releases what the receiver had set aside for it');
  ok(t.wire.filter((m) => m.type === 'file-part').every((m) => !m.data.includes('notes')),
    'the name is not in any part');
}

{
  const t = link(a, b);
  await t.send(new File([], 'empty.txt', { type: 'text/plain' }));
  await t.settled();
  const done = t.events.find((e) => e.event === 'complete');
  ok(done && done.blob.size === 0 && t.wire.map((m) => m.type).join(',') === 'file-offer,file-done',
    'an empty file is an offer and an end marker');
}

console.log('nothing large is sent before the receiver says yes');
{
  const big = { size: AUTO_ACCEPT_SIZE + 1, name: 'film.mp4', type: 'video/mp4', slice: () => new Blob([]) };
  let offered = null;
  const t = link(a, b, { answer: (offer) => { offered = offer; return 'wait'; } });
  const fileId = id();
  const sending = t.send(big, fileId);
  await new Promise((r) => setTimeout(r, 50));
  await t.settled();
  ok(offered?.ask === true, 'an offer above the old limit asks the person');
  ok(t.wire.length === 1 && t.wire[0].type === 'file-offer', 'and nothing but the offer has gone');
  ok(t.receiver.offers.size === 1 && t.receiver.inbound.size === 0 && t.receiver._inboundBytes === 0,
    'an unanswered offer reserves nothing');
  // The person refuses: the app declines and the sender is told.
  t.receiver.decline('from-a', fileId);
  t.sender.abortOutbound(fileId, 'to-b');
  ok(await sending === false, 'a refused offer ends the send without an error');
  ok(t.sender.outbound.size === 0, 'and the sender forgets it');
}
{
  let asked = null;
  const t = link(a, b, { answer: (offer) => { asked = offer.ask; return 'accept'; } });
  await t.send(patterned(1000));
  ok(asked === false, 'a small file is taken without asking, as before');
}

console.log('parts cannot be moved, swapped or cut short');
{
  // Part 0 of one file, presented as part 0 of another.
  const first = link(a, b);
  await first.send(patterned(2 * PART_SIZE));
  const stolen = first.wire.find((m) => m.type === 'file-part' && m.index === 0);
  const victim = id();
  const r = new FileTransferManager();
  // Stage an accepted offer for `victim` the way the channel would.
  const offer = { type: 'file-offer', id: victim, meta: first.wire[0].meta, size: 2 * PART_SIZE, parts: 2, ttl: 0, burnAfterReading: false };
  await r.handleMessage(offer, 'from-a');
  r.accept('from-a', victim, b, safeFileMeta({ fileName: 'x', fileType: '', fileSize: 2 * PART_SIZE }));
  const moved = await r.handleMessage({ ...stolen, id: victim }, 'from-a');
  ok(moved?.event === 'error' && r.inbound.size === 0,
    'a part of another file is refused, and the transfer dropped');

  // The right file, the parts out of order.
  const fileId = id();
  await r.handleMessage({ ...offer, id: fileId }, 'from-a');
  r.accept('from-a', fileId, b, safeFileMeta({ fileName: 'x', fileType: '', fileSize: 2 * PART_SIZE }));
  const parts = [];
  for (let index = 0; index < 2; index++) {
    const sealed = await a.encryptPart(new Uint8Array(PART_SIZE), fileId, index, 2);
    parts.push({ type: 'file-part', id: fileId, index, data: Buffer.from(sealed.ciphertext).toString('base64'), iv: sealed.iv, epoch: sealed.epoch });
  }
  const swapped = await r.handleMessage({ ...parts[1], index: 0 }, 'from-a');
  ok(swapped?.event === 'error', 'a part sent as another position fails to authenticate');

  // Cut short: the end marker before the last part.
  const cut = id();
  await r.handleMessage({ ...offer, id: cut }, 'from-a');
  r.accept('from-a', cut, b, safeFileMeta({ fileName: 'x', fileType: '', fileSize: 2 * PART_SIZE }));
  const sealed = await a.encryptPart(new Uint8Array(PART_SIZE), cut, 0, 2);
  await r.handleMessage({ type: 'file-part', id: cut, index: 0, data: Buffer.from(sealed.ciphertext).toString('base64'), iv: sealed.iv, epoch: sealed.epoch }, 'from-a');
  const early = await r.handleMessage({ type: 'file-done', id: cut }, 'from-a');
  ok(early?.event === 'error' && r.inbound.size === 0 && r._inboundBytes === 0,
    'a file that ends early is refused, not delivered short');
}

console.log('what a peer can make this side hold');
{
  const r = new FileTransferManager();
  const meta = { ciphertext: 'AA==', iv: Buffer.alloc(12).toString('base64'), epoch: 0 };
  const offerOf = (fileId, size) => ({ type: 'file-offer', id: fileId, meta, size, parts: partsFor(size), ttl: 0, burnAfterReading: false });
  ok(await r.handleMessage(offerOf(id(), MAX_FILE_SIZE + 1), 'p') === null, 'an offer over the limit is ignored');
  ok(await r.handleMessage({ ...offerOf(id(), 1000), parts: 2 }, 'p') === null, 'an offer whose part count does not match its size is ignored');
  ok(await r.handleMessage({ ...offerOf('not-a-uuid', 1000) }, 'p') === null, 'a malformed transfer ID is ignored');
  const shared = id();
  ok((await r.handleMessage(offerOf(shared, 1000), 'peer-a'))?.event === 'offer'
    && (await r.handleMessage(offerOf(shared, 1000), 'peer-b'))?.event === 'offer',
    'the same ID from two peers is two independent offers');
  ok(await r.handleMessage(offerOf(shared, 1000), 'peer-a') === null, 'a duplicate from the same peer is ignored');
  for (let i = 0; i < 6; i++) await r.handleMessage(offerOf(id(), 1000), 'peer-a');
  ok((await r.handleMessage(offerOf(id(), 1000), 'peer-a'))?.event === 'busy',
    'past eight unanswered offers, the next is turned away and the sender told');
  r.abortScope('peer-a');
  r.abortScope('peer-b');
  ok(r.offers.size === 0, 'a peer leaving takes its offers with it');

  const bigOne = id(), bigTwo = id();
  await r.handleMessage(offerOf(bigOne, MAX_FILE_SIZE), 'p');
  await r.handleMessage(offerOf(bigTwo, MAX_FILE_SIZE), 'p');
  ok(r.accept('p', bigOne, b, {}) === 'ok', 'one file at the size limit can be accepted');
  ok(r.accept('p', bigTwo, b, {}) === 'busy' && r.offers.size === 1,
    'a second one waits: accepting it is refused while the first arrives, and its offer stays');
  ok(r.discardInbound('p', bigOne) && r._inboundBytes === 0, 'refusing the first releases what it held');
  ok(r.accept('p', bigTwo, b, {}) === 'ok', 'and the second can then be taken');
  r.destroyAll();
  ok(r.inbound.size === 0 && r.offers.size === 0 && r._inboundBytes === 0, 'wiping drops everything');
}

console.log('authenticated file-size binding');
assertFileSizeBinding(25, 25);
ok(true, 'metadata that names the offered size is accepted');
ok(rejectsSizeBinding(0, 25), 'metadata cannot show a size other than the one offered and budgeted');
ok(rejectsSizeBinding(25.5, 25.5), 'fractional sizes are rejected');
ok(rejectsSizeBinding(MAX_FILE_SIZE + 1, MAX_FILE_SIZE + 1), 'sizes over the limit are rejected');

console.log('a part fits the channel, and the sender stays under the receiver\'s limit');
{
  const fileId = id();
  const sealed = await a.encryptPart(new Uint8Array(PART_SIZE), fileId, 0, 1);
  const inner = {
    type: 'file-part', id: fileId, index: partsFor(MAX_FILE_SIZE) - 1,
    data: Buffer.from(sealed.ciphertext).toString('base64'), iv: sealed.iv, epoch: 999999,
  };
  const outer = await a.seal(inner, a.sendEpoch, Number.MAX_SAFE_INTEGER);
  const wire = JSON.stringify({ type: 'enc', v: PROTOCOL_VERSION, c: outer.ciphertext, iv: outer.iv, e: outer.epoch }).length;
  ok(wire <= MAX_PART_WIRE_BYTES, `a full part is ${wire} bytes on the wire, within the ${MAX_PART_WIRE_BYTES} the sender paces by`);
  ok(MAX_PART_WIRE_BYTES < MAX_DATA_CHANNEL_MESSAGE, 'and within what a receiver accepts in one message');
  ok(SEND_PACE.bytes <= MAX_BYTES_PER_WINDOW / 2 && SEND_PACE.messages <= MAX_MESSAGES_PER_WINDOW / 2,
    'a sender paces at most half the receiver\'s limit, so unaligned windows cannot add up past it');
}

console.log('peer-scoped message destruction');
const notifications = [];
const messages = new MessageManager((wireId, peerId) => notifications.push({ wireId, peerId }));
messages.add('peer-a:wire', null, 0, false, false, null, { wireId: 'wire', peerId: 'peer-a' });
messages.destroy('peer-a:wire');
ok(notifications[0]?.wireId === 'wire' && notifications[0]?.peerId === 'peer-a',
   'inbound destruction notifies only its source peer');
messages.add('self:wire', null, 0, false, true, null, { wireId: 'wire' });
messages.remoteDestroy('self:wire');
ok(notifications.length === 1, 'remote destruction does not echo back');

console.log('timed messages keep wall-clock time');
// A phone asleep stops the timers, not the clock. Coming back must take what
// ran out meanwhile, and only that.
const timed = new MessageManager(() => {});
timed.add('short', null, 10, false, true);
timed.add('long', null, 300, false, true);
timed.add('untimed', null, 0, false, true);
timed.sweep(Date.now() + 5_000);
ok(timed.has('short'), 'a message with time left survives a sweep');
timed.sweep(Date.now() + 11_000);
ok(!timed.has('short') && timed.has('long') && timed.has('untimed'),
   'a sweep after its deadline destroys an expired message, and only that one');
timed.destroyAll();

console.log('a received timer waits until the message can be seen');
const waiting = new MessageManager(() => {});
waiting.add('unseen', null, 10, false, false, null, { deferTtl: true });
waiting.sweep(Date.now() + 60_000);
ok(waiting.has('unseen'), 'an unseen timed message outlives its timer while nobody can see it');
waiting.startTtl('unseen');
waiting.sweep(Date.now() + 11_000);
ok(!waiting.has('unseen'), 'once seen, its timer runs from that moment');
waiting.add('forgotten', null, 10, false, false, null, { deferTtl: true });
waiting.sweep(Date.now() + 10 * 60_000 + 11_000);
ok(!waiting.has('forgotten'), 'but a tab left unseen for ten minutes starts it anyway');
waiting.destroyAll();

console.log('burn after reading');
const burns = new MessageManager(() => {});
burns.add('in', null, 0, true, false);
burns.markRead('in', 50);
burns.markRead('in', 60_000); // a second look must not restart or add a clock
burns.add('out', null, 0, true, true);
burns.markRead('out', 50);
await new Promise((r) => setTimeout(r, 150));
ok(!burns.has('in'), 'a received burn message goes once its reading time is up');
ok(burns.has('out'), 'our own copy waits for the reader, not for us');
burns.destroyAll();

console.log('received file metadata');
for (const declared of ['text/html', 'image/svg+xml', 'application/xhtml+xml', 'application/pdf', 'TEXT/HTML']) {
  ok(safeFileMeta({ fileName: 'x', fileType: declared, fileSize: 1 }).fileType === 'application/octet-stream',
     `a peer-declared ${declared} is downloaded, never rendered at this origin`);
}
ok(safeFileMeta({ fileName: 'v.webm', fileType: 'audio/webm;codecs=opus', fileSize: 1 }).fileType === 'audio/webm',
   'a voice note with codec parameters still plays inline');
ok(safeFileMeta({ fileName: 'p.png', fileType: 'image/png', fileSize: 1 }).fileType === 'image/png',
   'raster images keep their preview');
const spoofed = safeFileMeta({ fileName: 'invoice\u202Efdp.exe', fileType: 'image/png', fileSize: 1 }).fileName;
ok(!/[\u202a-\u202e\u2066-\u2069]/.test(spoofed) && spoofed.endsWith('.exe'),
   'a right-to-left override cannot disguise the real extension');
ok(safeFileMeta({ fileName: '../../.bashrc', fileType: '', fileSize: 1 }).fileName === '_.._.bashrc',
   'path separators and leading dots are neutralised');
ok(safeFileMeta({ fileName: '\u200b\u0000', fileType: '', fileSize: 1 }).fileName === '__',
   'invisible and control characters are made visible');
ok(safeFileMeta({ fileName: 42, fileType: null, fileSize: -1 })?.fileName === 'file',
   'malformed metadata falls back to safe defaults');

console.log('scrubbed photo names');
for (const [name, type] of [
  ['IMG_20261014_153212.jpg', 'image/jpeg'],
  ['PXL_20261014_153212123.jpg', 'image/jpeg'],
  ['Screenshot_2026-10-14-15-32-12.png', 'image/png'],
  ['Screenshot 2026-10-14 at 15.32.12.png', 'image/png'],
  ['WhatsApp Image 2026-10-14 at 15.32.12.jpeg', 'image/jpeg'],
  ['signal-2026-10-14-153212.jpg', 'image/jpeg'],
  ['DSC_0042.JPG', 'image/jpeg'],
  ['1791987292317.webp', 'image/webp'],
]) {
  ok(/^photo\.(jpg|png|webp)$/.test(scrubbedName(name, type)), `a device-generated name is not sent (${name} → ${scrubbedName(name, type)})`);
}
ok(scrubbedName('cat.jpg', 'image/jpeg') === 'cat.jpg', 'a name a person chose is kept');
ok(scrubbedName('holiday plan v2.png', 'image/png') === 'holiday plan v2.png', 'ordinary words and small numbers are kept');
ok(scrubbedName('', 'image/webp') === 'photo.webp', 'a missing name gets a neutral one');

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
