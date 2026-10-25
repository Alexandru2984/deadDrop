/** Bounded file-transfer and peer-scoped message lifecycle self-test. */

import { FileTransferManager, assertFileSizeBinding, safeFileMeta } from '../web/js/filetransfer.js';
import { MessageManager } from '../web/js/messages.js';
import { scrubbedName } from '../web/js/scrub.js';

let failures = 0;
const ok = (condition, message) => {
  if (condition) console.log('  ✓', message);
  else { console.error('  ✗', message); failures++; }
};

const iv = Buffer.alloc(12).toString('base64');
const id = () => crypto.randomUUID();
const rejectsSizeBinding = (...args) => {
  try { assertFileSizeBinding(...args); return false; } catch { return true; }
};
const header = (transferId) => ({
  type: 'file',
  id: transferId,
  meta: { ciphertext: 'AA==', iv, epoch: 0 },
  fileIv: iv,
  fileEpoch: 0,
  totalChunks: 1,
  totalSize: 16,
  ttl: 0,
  burnAfterReading: false,
});

console.log('peer-scoped, bounded inbound files');
const manager = new FileTransferManager();
const sharedId = id();
ok(manager.handleMessage(header(sharedId), 'peer-a')?.event === 'start',
   'first peer starts a transfer');
ok(manager.handleMessage(header(sharedId), 'peer-b')?.event === 'start',
   'same wire ID from a different peer has an independent scope');
ok(manager.handleMessage(header(sharedId), 'peer-a') === null,
   'duplicate active ID from the same peer is rejected');

const data = Buffer.alloc(16).toString('base64');
ok(manager.handleMessage({ type: 'file-chunk', id: sharedId, index: 0, data: 'AAAA' }, 'peer-a')?.event === 'error',
   'wrong-sized encoded chunk aborts and releases the transfer');
ok(manager.handleMessage(header(sharedId), 'peer-a')?.event === 'start',
   'peer can start a clean transfer after the rejected one');
ok(manager.handleMessage({ type: 'file-chunk', id: sharedId, index: 0, data }, 'peer-a')?.received === 1,
   'canonical chunk is accepted');
const completed = manager.handleMessage({ type: 'file-end', id: sharedId }, 'peer-a');
ok(completed?.event === 'complete' && completed.scope === 'peer-a',
   'completed ciphertext retains its authenticated peer scope');
new Uint8Array(completed.ciphertext).fill(0);

manager.handleMessage({ type: 'file-chunk', id: sharedId, index: 0, data }, 'peer-b');
manager.handleMessage({ type: 'file-end', id: sharedId }, 'peer-b');
ok(manager.inbound.size === 0 && manager._reservedInboundBytes === 0,
   'completed transfers release the global receive budget');
ok(manager.handleMessage({ ...header('not-a-uuid') }, 'peer-a') === null,
   'non-canonical transfer IDs are rejected');

const activeIds = Array.from({ length: 5 }, () => id());
for (let i = 0; i < 4; i++) manager.handleMessage(header(activeIds[i]), 'peer-a');
ok(manager.handleMessage(header(activeIds[4]), 'peer-a') === null,
   'global active-transfer limit rejects the fifth allocation');
manager.abortScope('peer-a');
ok(manager.inbound.size === 0 && manager._reservedInboundBytes === 0,
   'disconnecting a peer wipes its reserved ciphertext buffers');

console.log('authenticated file-size binding');
assertFileSizeBinding(25, 41, 25);
ok(true, 'matching metadata, ciphertext tag, and plaintext sizes are accepted');
ok(rejectsSizeBinding(0, 41, 25),
   'under-reported metadata cannot bypass the retained-Blob memory budget');
ok(rejectsSizeBinding(25.5, 41, 25),
   'fractional file sizes are rejected');
ok(rejectsSizeBinding(25, 41, 24),
   'decrypted bytes must exactly match authenticated metadata');

console.log('awaited outbound flow');
const sent = [];
const fakePeer = {
  dc: {
    readyState: 'open',
    bufferedAmount: 0,
    addEventListener() {},
    removeEventListener() {},
  },
  async send(message) { sent.push(message); },
};
const fakeCrypto = {
  async encryptBinary() { return { ciphertext: new Uint8Array(16).buffer, iv, epoch: 0 }; },
  async encrypt() { return { ciphertext: 'AA==', iv, epoch: 0 }; },
};
const fakeFile = {
  size: 0,
  name: 'empty.txt',
  type: 'text/plain',
  async arrayBuffer() { return new ArrayBuffer(0); },
};
await manager.send(fakeFile, id(), fakeCrypto, fakePeer, 0, false, null, 'peer-a');
ok(sent.map((message) => message.type).join(',') === 'file,file-chunk,file-end',
   'header, every chunk, and end marker are awaited in order');

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
