/**
 * Movie and document metadata removal, on files built byte by byte.
 *
 *   node test/scrub.selftest.mjs
 *
 * A phone video says where it was shot (©xyz under udta, or Apple's location
 * key under meta), when (every movie, track and media header), and on what.
 * The scrubber blanks those in place. What has to hold: none of it survives,
 * not one byte moves — so the sample offsets the player reads still point at
 * the same media — and anything that is not a well-formed movie is refused
 * rather than sent as it was.
 *
 * An office document says who wrote it, for which company and when, in its
 * property parts. Those are emptied; every other part must come out byte for
 * byte, the archive must still be one any ZIP reader accepts — checked with
 * Python's zipfile, which shares no code with ours — and an archive that
 * cannot be read is put to the person rather than sent unasked.
 */

import { scrubMovie, scrubbedName, isScrubbable, scrubFile, typeOf } from '../web/js/scrub.js';
import { deflateRawSync } from 'node:zlib';
import { zip } from './lib/zip.mjs';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let failures = 0;
const ok = (c, m) => { if (c) console.log('  ✓', m); else { console.error('  ✗', m); failures++; } };

const enc = new TextEncoder();
const u32 = (n) => [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255];
function box(type, ...parts) {
  const body = parts.flatMap((p) => (typeof p === 'string' ? [...enc.encode(p)] : [...p]));
  return [...u32(8 + body.length), ...enc.encode(type), ...body];
}
// A FullBox header whose first fields are creation and modification time.
const timed = (type, version, ...rest) => box(type, [version, 0, 0, 0],
  version === 1 ? [0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef, 0, 0, 0, 0, 0xca, 0xfe, 0xba, 0xbe]
    : [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe], ...rest);

const GPS = '+44.4268+026.1025/';
const media = [...enc.encode('MEDIA-PAYLOAD-UNTOUCHED'), 1, 2, 3, 4, 5];
const movie = new Uint8Array([
  ...box('ftyp', 'isom', [0, 0, 2, 0], 'isommp41'),
  ...box('moov',
    timed('mvhd', 0, new Array(88).fill(7)),
    box('udta', box('©xyz', [0, 18, 0x15, 0xc7], GPS), box('©mod', 'Pixel 9 Pro')),
    box('meta', [0, 0, 0, 0], box('hdlr', new Array(20).fill(0)),
      box('keys', 'com.apple.quicktime.location.ISO6709'), box('ilst', GPS)),
    box('trak',
      timed('tkhd', 1, new Array(80).fill(9)),
      box('mdia', timed('mdhd', 0, [0, 0, 0x3e, 0x80, 0, 0, 0, 0]), box('hdlr', 'vide-handler')),
      box('udta', 'track-owner-serial-SN123456')),
    box('uuid', 'XMP-<exif:GPSLatitude>44,25.6N</exif:GPSLatitude>')),
  ...box('mdat', media),
]);

const file = new File([movie], 'VID_20261014_153212.mp4', { type: 'video/mp4' });
ok(isScrubbable(file), 'an MP4 is one of the files scrubbed before sending');
const out = await scrubMovie(file);
const bytes = new Uint8Array(await out.arrayBuffer());
const text = new TextDecoder('latin1').decode(bytes);

ok(bytes.length === movie.length, `nothing is added or removed (${movie.length} → ${bytes.length} bytes)`);
ok(!text.includes(GPS) && !text.includes('GPSLatitude') && !text.includes('location.ISO6709'),
  'no location survives: not in udta, not in meta, not in XMP');
ok(!text.includes('Pixel 9') && !text.includes('SN123456'), 'nor the device or a serial number');
ok(!text.includes('\xde\xad\xbe\xef') && !text.includes('\xca\xfe\xba\xbe'),
  'the creation and modification times are zero in every header, version 0 and 1');
const mdatAt = text.indexOf('mdat');
ok(mdatAt === movie.length - media.length - 4
  && bytes.subarray(mdatAt + 4).every((b, i) => b === media[i]),
  'the media sits where it was, byte for byte');
ok(text.includes('mvhd') && text.includes('tkhd') && text.includes('mdhd') && text.includes('hdlr'),
  'the boxes a player needs are all still there');
ok((text.match(/free/g) || []).length === 4, 'each blanked box reads as free space');
ok(out.name === 'video.mp4' && out.lastModified === 0,
  `a camera-generated name goes too (${out.name})`);
ok(scrubbedName('holiday.mov', 'video/quicktime') === 'holiday.mov', 'a name a person chose is kept');

// Not a movie, or a broken one: refused, never sent as it was.
const refused = async (bytesIn, name) => {
  try { await scrubMovie(new File([bytesIn], 'x.mp4', { type: 'video/mp4' })); return false; } catch { return true; }
};
ok(await refused(new Uint8Array([...box('ftyp', 'isom'), ...box('mdat', media)])), 'a file with no movie box is refused');
const overrun = movie.slice();
overrun.set(u32(0x7fffffff), 0);
ok(await refused(overrun), 'a box claiming more than the file holds is refused');
ok(await refused(new Uint8Array([0, 0, 0, 4, 0x66, 0x74, 0x79, 0x70])), 'a box shorter than its own header is refused');
ok(await refused(enc.encode('not a movie at all, just text that goes on')), 'plain text is refused');

// A 64-bit size, as long recordings use.
const large = new Uint8Array([...box('ftyp', 'isom'),
  0, 0, 0, 1, ...enc.encode('moov'), 0, 0, 0, 0, 0, 0, 0, 16 + 8 + GPS.length,
  ...box('udta', GPS)]);
const largeOut = new TextDecoder('latin1').decode(new Uint8Array(await (await scrubMovie(
  new File([large], 'a.mp4', { type: 'video/mp4' }))).arrayBuffer()));
ok(!largeOut.includes(GPS), 'boxes with a 64-bit size are walked as well');

// A HEIC photo handed over with no type is still recognised by its name.
const untyped = new File([new Uint8Array(4)], 'IMG_4021.HEIC', { type: '' });
ok(typeOf(untyped) === 'image/heic' && isScrubbable(untyped),
  'a photo that arrives without a type is judged by its extension');
ok(!isScrubbable(new File(['x'], 'notes.txt', { type: 'text/plain' })), 'and a text file is left alone');

// ── Office documents ──

const AUTHOR = 'Alice Example';
const COMPANY = 'Example Holdings SRL';
const TENANT = '72f988bf-86f1-41af-91ab-2d7cd011db47';
const BODY = '<w:document><w:body><w:p><w:r><w:t>The quarterly numbers are attached.</w:t></w:r></w:p></w:body></w:document>';
const docx = zip([
  { name: '[Content_Types].xml', data: '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"/>' },
  { name: '_rels/.rels', data: '<Relationships/>' },
  { name: 'word/document.xml', data: BODY, descriptor: true },
  { name: 'docProps/core.xml', data: `<cp:coreProperties><dc:creator>${AUTHOR}</dc:creator><cp:lastModifiedBy>${AUTHOR}</cp:lastModifiedBy><dcterms:created>2026-10-27T14:32:00Z</dcterms:created></cp:coreProperties>` },
  { name: 'docProps/app.xml', data: `<Properties><Company>${COMPANY}</Company><Template>C:\\Users\\alice\\Normal.dotm</Template><TotalTime>94</TotalTime></Properties>` },
  { name: 'docProps/custom.xml', data: `<Properties><property name="MSIP_Label_SiteId"><vt:lpwstr>${TENANT}</vt:lpwstr></property></Properties>`, deflate: false },
]);
const docIn = new File([docx], 'Quarterly report.docx', { type: '' });
ok(isScrubbable(docIn) && typeOf(docIn).includes('wordprocessingml'),
  'a Word document is recognised, even arriving without a type');
const docOut = await scrubFile(docIn);
const docBytes = Buffer.from(await docOut.arrayBuffer());

const dir = mkdtempSync(join(tmpdir(), 'dd-scrub-'));
const inspect = (bytes) => {
  const path = join(dir, 'doc.zip');
  writeFileSync(path, bytes);
  // Reads every part, checks every CRC, and reports what a reader sees.
  return JSON.parse(execFileSync('python3', ['-I', '-c', `
import json, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
bad = z.testzip()
print(json.dumps({
  "bad": bad,
  "comment": z.comment.decode("latin1"),
  "parts": {i.filename: z.read(i).decode("utf-8") for i in z.infolist()},
  "times": sorted({i.date_time for i in z.infolist()}),
  "extra": sum(len(i.extra) + len(i.comment) for i in z.infolist()),
}))`, path], { encoding: 'utf8' }));
};
try {
  const seen = inspect(docBytes);
  ok(seen.bad === null, 'the rebuilt archive opens, and every part passes its checksum');
  const all = Object.values(seen.parts).join('') + seen.comment;
  ok(!all.includes(AUTHOR), 'the author and last editor are gone');
  ok(!all.includes(COMPANY) && !all.includes('alice') && !all.includes('<TotalTime>'),
    'so are the company, the template path and the editing time');
  ok(!all.includes(TENANT), "and the custom properties, with a sensitivity label's tenant ID");
  ok(!docBytes.includes('ALICE-LAPTOP') && seen.comment === '' && seen.extra === 0,
    'comments and extra fields are dropped from the archive itself');
  ok(seen.times.length === 1 && seen.times[0].join() === '1980,1,1,0,0,0',
    `every part's time is 1980-01-01 (${JSON.stringify(seen.times)})`);
  ok(seen.parts['word/document.xml'] === BODY, 'the document itself is unchanged');
  ok(/coreProperties/.test(seen.parts['docProps/core.xml']) && /extended-properties/.test(seen.parts['docProps/app.xml']),
    'the property parts are still there, empty, so Office finds what its index lists');
  ok(docOut.name === 'Quarterly report.docx' && docOut.type.includes('wordprocessingml') && docOut.lastModified === 0,
    'the name a person gave it is kept');

  // The untouched parts are copied as they were compressed, not re-packed.
  const original = deflateRawSync(Buffer.from(BODY));
  ok(docBytes.includes(original), 'other parts are carried byte for byte, still compressed');

  // OpenDocument: meta.xml is emptied, keeping the version it declared, and
  // the uncompressed mimetype stays the first part, as the format requires.
  const odt = zip([
    { name: 'mimetype', data: 'application/vnd.oasis.opendocument.text', deflate: false },
    { name: 'content.xml', data: '<office:document-content office:version="1.3"/>' },
    { name: 'meta.xml', data: `<office:document-meta office:version="1.3"><office:meta><meta:initial-creator>${AUTHOR}</meta:initial-creator><dc:creator>${AUTHOR}</dc:creator><meta:editing-duration>PT1H2M</meta:editing-duration></office:meta></office:document-meta>` },
  ]);
  const odtOut = Buffer.from(await (await scrubFile(new File([odt], 'notes.odt', { type: 'application/vnd.oasis.opendocument.text' }))).arrayBuffer());
  const odtSeen = inspect(odtOut);
  ok(odtSeen.bad === null && !JSON.stringify(odtSeen.parts).includes(AUTHOR) && !odtSeen.parts['meta.xml'].includes('PT1H2M'),
    'an OpenDocument file loses its creator and editing time');
  ok(odtSeen.parts['meta.xml'].includes('office:version="1.3"'), 'and keeps the version its meta part declared');
  ok(odtOut.subarray(30, 38).toString() === 'mimetype' && odtOut.readUInt16LE(8) === 0,
    'mimetype is still first and stored');
} finally {
  rmSync(dir, { recursive: true, force: true });
}

// What cannot be read is put to the person, never sent as if it were clean.
const asked = async (bytes, name = 'x.docx') => {
  try { await scrubFile(new File([bytes], name, { type: '' })); return 'sent'; } catch (e) { return e.undecodable && e.prompt; }
};
ok(await asked(Buffer.concat([Buffer.from([0xd0, 0xcf, 0x11, 0xe0, 0xa1, 0xb1, 0x1a, 0xe1]), Buffer.alloc(512)])) === 'scrub.cannotReadDoc',
  'a password-protected document (not a ZIP at all) is put to the person');
ok(await asked(zip([{ name: 'readme.txt', data: 'hi' }])) === 'scrub.cannotReadDoc',
  'so is a ZIP that is not an office document');
const encrypted = Buffer.from(docx);
encrypted.writeUInt16LE(encrypted.readUInt16LE(encrypted.indexOf(Buffer.from([0x50, 0x4b, 1, 2])) + 8) | 1,
  encrypted.indexOf(Buffer.from([0x50, 0x4b, 1, 2])) + 8);
ok(await asked(encrypted) === 'scrub.cannotReadDoc', 'and one with an encrypted part');
const truncated = docx.subarray(0, docx.length - 40);
ok(await asked(truncated) === 'scrub.cannotReadDoc', 'and a truncated one');
const tricky = zip([
  { name: '[Content_Types].xml', data: '<Types/>' },
  { name: 'constructor', data: 'kept' },
]);
const trickySeen = Buffer.from(await (await scrubFile(new File([tricky], 't.xlsx', { type: '' }))).arrayBuffer());
ok(trickySeen.includes(deflateRawSync(Buffer.from('kept'))), 'a part named like an object property is copied, not mistaken');

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
