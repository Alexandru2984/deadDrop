/**
 * A minimal ZIP writer for tests, independent of the one in web/js/docscrub.js.
 *
 * It writes what real tools write and the scrubber has to cope with:
 * deflated parts, data descriptors, an extended-timestamp extra field, a
 * real modification time, a comment on every part and one on the archive.
 */

import { deflateRawSync } from 'node:zlib';

export function crc32(buf) {
  let c = ~0;
  for (const b of buf) { c ^= b; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; }
  return ~c >>> 0;
}
export function zip(files, { comment = 'archive comment' } = {}) {
  const le = (n, w) => { const b = Buffer.alloc(w); w === 2 ? b.writeUInt16LE(n) : b.writeUInt32LE(n); return b; };
  const local = [];
  const central = [];
  let offset = 0;
  for (const { name, data, deflate = true, descriptor = false } of files) {
    const raw = Buffer.from(data);
    const body = deflate ? deflateRawSync(raw) : raw;
    const nameB = Buffer.from(name);
    const extra = Buffer.from([0x55, 0x54, 5, 0, 1, ...le(1760000000, 4)]); // extended timestamp
    const crc = crc32(raw);
    const flags = descriptor ? 0x0808 : 0x0800;
    const time = le((14 << 11) | (32 << 5), 2);
    const date = le(((2026 - 1980) << 9) | (10 << 5) | 27, 2);
    const head = Buffer.concat([le(0x04034b50, 4), le(20, 2), le(flags, 2), le(deflate ? 8 : 0, 2), time, date,
      le(descriptor ? 0 : crc, 4), le(descriptor ? 0 : body.length, 4), le(descriptor ? 0 : raw.length, 4),
      le(nameB.length, 2), le(extra.length, 2), nameB, extra]);
    const tail = descriptor ? Buffer.concat([le(0x08074b50, 4), le(crc, 4), le(body.length, 4), le(raw.length, 4)]) : Buffer.alloc(0);
    local.push(head, body, tail);
    const fileComment = Buffer.from('made on ALICE-LAPTOP');
    central.push(Buffer.concat([le(0x02014b50, 4), le(0x031e, 2), le(20, 2), le(flags, 2), le(deflate ? 8 : 0, 2), time, date,
      le(crc, 4), le(body.length, 4), le(raw.length, 4), le(nameB.length, 2), le(extra.length, 2),
      le(fileComment.length, 2), le(0, 2), le(0, 2), le((0o100644 << 16) >>> 0, 4), le(offset, 4), nameB, extra, fileComment]));
    offset += head.length + body.length + tail.length;
  }
  const cd = Buffer.concat(central);
  const commentB = Buffer.from(comment);
  return Buffer.concat([...local, cd, le(0x06054b50, 4), le(0, 2), le(0, 2), le(files.length, 2), le(files.length, 2),
    le(cd.length, 4), le(offset, 4), le(commentB.length, 2), commentB]);
}
