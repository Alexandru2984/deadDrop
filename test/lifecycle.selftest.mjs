/** Bounded file-transfer and peer-scoped message lifecycle self-test. */

import { FileTransferManager, assertFileSizeBinding } from '../web/js/filetransfer.js';
import { MessageManager } from '../web/js/messages.js';

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

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
