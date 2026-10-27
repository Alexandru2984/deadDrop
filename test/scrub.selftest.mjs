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
import { zip, crc32 } from './lib/zip.mjs';
import { blankJpegMeta, jpegEnd, stripPngMeta } from '../web/js/imagemeta.js';
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

// ── Photos inside documents ──

// A JPEG as a phone writes it: JFIF, EXIF with the orientation and a GPS
// position, XMP naming the author, a colour profile, IPTC, Adobe's flag and a
// comment — then the picture itself.
const GPS_TEXT = '44.4268N 26.1025E';
const seg = (marker, body) => {
  const b = Buffer.from(body, 'latin1');
  return Buffer.concat([Buffer.from([0xff, marker, (b.length + 2) >> 8, (b.length + 2) & 255]), b]);
};
const exifBody = (orientation) => {
  // Big-endian TIFF, IFD0 with Orientation and a pointer-free ASCII tag.
  const ifd = Buffer.alloc(2 + 2 * 12 + 4);
  ifd.writeUInt16BE(2, 0);
  ifd.writeUInt16BE(0x0112, 2); ifd.writeUInt16BE(3, 4); ifd.writeUInt32BE(1, 6); ifd.writeUInt16BE(orientation, 10);
  ifd.writeUInt16BE(0x010f, 14); ifd.writeUInt16BE(2, 16); ifd.writeUInt32BE(GPS_TEXT.length + 1, 18); ifd.writeUInt32BE(8 + ifd.length, 22);
  return 'Exif\0\0' + Buffer.concat([Buffer.from('MM\0\x2a\0\0\0\x08', 'latin1'), ifd, Buffer.from(GPS_TEXT + '\0')]).toString('latin1');
};
const SCAN = Buffer.from([0xff, 0xda, 0, 8, 1, 1, 0, 0, 0x3f, 0, 0x12, 0x34, 0x56, 0xff, 0xd9]);
const ICC = 'ICC_PROFILE\0\x01\x01colour-profile-bytes';
const jpeg = (orientation = 6) => Buffer.concat([
  Buffer.from([0xff, 0xd8]),
  seg(0xe0, 'JFIF\0\x01\x01\0\0\x01\0\x01\0\0'),
  seg(0xe1, exifBody(orientation)),
  seg(0xe1, `http://ns.adobe.com/xap/1.0/\0<x:xmpmeta><dc:creator>${AUTHOR}</dc:creator></x:xmpmeta>`),
  seg(0xe2, ICC),
  seg(0xed, `Photoshop 3.0\x008BIM IPTC by-line ${AUTHOR}`),
  seg(0xee, 'Adobe\0\x64\0\0\0\0\x01'),
  seg(0xfe, 'Shot on Alice-Phone'),
  SCAN,
]);
const photo = jpeg();
const cleaned = Buffer.from(photo);
ok(blankJpegMeta(cleaned) && cleaned.length === photo.length, 'a JPEG is cleaned in place, keeping its length');
const cleanedText = cleaned.toString('latin1');
ok(!cleanedText.includes(GPS_TEXT) && !cleanedText.includes(AUTHOR) && !cleanedText.includes('Alice-Phone') && !cleanedText.includes('xmpmeta'),
  'its EXIF position, XMP author, IPTC and comment are gone');
ok(cleanedText.includes('JFIF') && cleanedText.includes(ICC) && cleanedText.includes('Adobe\0') && cleaned.subarray(-SCAN.length).equals(SCAN),
  'what a decoder needs is kept: JFIF, the colour profile, Adobe’s flag, the picture');
// The orientation survives in a minimal EXIF of its own, read independently.
const exifAt = cleaned.indexOf('Exif\0\0MM', 0, 'latin1');
ok(exifAt > 0 && cleaned.readUInt16BE(exifAt + 16) === 0x0112 && cleaned.readUInt16BE(exifAt + 24) === 6,
  'and a portrait photo keeps its orientation, alone');
const unrotated = Buffer.from(jpeg(1));
blankJpegMeta(unrotated);
ok(unrotated.indexOf('Exif', 0, 'latin1') < 0, 'an upright one keeps no EXIF at all');
const inPdf = Buffer.from(photo);
blankJpegMeta(inPdf, 0, inPdf.length, { keepOrientation: false });
ok(inPdf.indexOf('Exif', 0, 'latin1') < 0, 'and inside a PDF, which ignores orientation, none either');
ok(!blankJpegMeta(Buffer.from('not a jpeg at all')), 'something that is not a JPEG is left alone');
const cut = Buffer.from(photo.subarray(0, 40));
ok((() => { try { blankJpegMeta(cut); return true; } catch { return false; } })(), 'a truncated JPEG does not throw');

const chunk = (type, data) => {
  const body = Buffer.concat([Buffer.from(type, 'latin1'), Buffer.from(data, 'latin1')]);
  const len = Buffer.alloc(4); len.writeUInt32BE(body.length - 4);
  const crc = Buffer.alloc(4); crc.writeUInt32BE(crc32(body));
  return Buffer.concat([len, body, crc]);
};
const IHDR = chunk('IHDR', '\0\0\0\x01\0\0\0\x01\x08\x02\0\0\0');
const IDAT = chunk('IDAT', 'pixels');
const IEND = chunk('IEND', '');
const png = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), IHDR,
  chunk('tEXt', `Author\0${AUTHOR}`), chunk('eXIf', exifBody(1)), chunk('iTXt', 'XML:com.adobe.xmp\0\0\0\0\0<x/>'),
  chunk('tIME', '\x07\xea\x0a\x1b\x0e\x20\0'), IDAT, IEND]);
const pngOut = Buffer.from(stripPngMeta(png));
ok(!pngOut.includes(AUTHOR) && !pngOut.includes('eXIf') && !pngOut.includes('iTXt') && !pngOut.includes('tIME'),
  'a PNG loses its text, EXIF and time chunks');
ok(pngOut.equals(Buffer.concat([png.subarray(0, 8), IHDR, IDAT, IEND])), 'and keeps every other chunk byte for byte');
ok(stripPngMeta(Buffer.concat([png.subarray(0, 8), IHDR, IDAT, IEND])) === null, 'a clean PNG is left as it is');

// Pasted into a Word document, then into a PDF.
const withPhoto = zip([
  { name: '[Content_Types].xml', data: '<Types/>' },
  { name: 'word/document.xml', data: BODY },
  { name: 'word/media/image1.jpeg', data: photo },
  { name: 'word/media/image2.png', data: png, deflate: false },
]);
const withPhotoOut = Buffer.from(await (await scrubFile(new File([withPhoto], 'Trip.docx', { type: '' }))).arrayBuffer());
const dir2 = mkdtempSync(join(tmpdir(), 'dd-scrub-'));
try {
  writeFileSync(join(dir2, 'd.zip'), withPhotoOut);
  const seen = JSON.parse(execFileSync('python3', ['-I', '-c', `
import json, sys, zipfile
z = zipfile.ZipFile(sys.argv[1])
print(json.dumps({"bad": z.testzip(), "jpeg": z.read("word/media/image1.jpeg").hex(), "png": z.read("word/media/image2.png").hex()}))`,
  join(dir2, 'd.zip')], { encoding: 'utf8' }));
  const inDocJpeg = Buffer.from(seen.jpeg, 'hex');
  ok(seen.bad === null && inDocJpeg.equals(cleaned), 'a photo inside a Word document is cleaned the same way');
  ok(Buffer.from(seen.png, 'hex').equals(pngOut), 'and a PNG inside it too');
} finally {
  rmSync(dir2, { recursive: true, force: true });
}
const pdfWithPhoto = Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj\n<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /Filter /DCTDecode /Length ' + photo.length + ' >>\nstream\n', 'latin1'),
  photo, Buffer.from('\nendstream\nendobj\n%%EOF\n', 'latin1')]);
const pdfPhotoOut = Buffer.from(await (await scrubFile(new File([pdfWithPhoto], 'trip.pdf', { type: '' }))).arrayBuffer());
ok(pdfPhotoOut.length === pdfWithPhoto.length && !pdfPhotoOut.includes(GPS_TEXT) && !pdfPhotoOut.includes(AUTHOR)
  && pdfPhotoOut.includes(ICC, 0, 'latin1'), 'and a photo inside a PDF, in place');

// What a phone puts after the picture: a motion photo's video, Samsung's
// capture times. The end is found through a progressive file's several scans,
// stuffed bytes and restart markers.
const progressive = Buffer.concat([
  Buffer.from([0xff, 0xd8]), seg(0xe0, 'JFIF\0\x01\x01\0\0\x01\0\x01\0\0'),
  Buffer.from([0xff, 0xda, 0, 8, 1, 1, 0, 0, 0x3f, 0, 0x11, 0xff, 0x00, 0x22, 0xff, 0xd0, 0x33]),
  seg(0xc4, '\0huffman'),
  Buffer.from([0xff, 0xda, 0, 8, 1, 1, 0, 1, 0x3f, 0, 0x44, 0xff, 0x00, 0xff, 0xd9]),
]);
ok(jpegEnd(progressive) === progressive.length, 'the end of a progressive JPEG is found past every scan');
const MOTION = 'ftypmp42 ... ©xyz+44.4268+026.1025/ ... MotionPhoto_Data SEFT Image_UTC_Data1761576000000';
const trailed = Buffer.concat([photo, Buffer.from(MOTION, 'latin1')]);
const trailedDoc = Buffer.from(await (await scrubFile(new File([zip([
  { name: '[Content_Types].xml', data: '<Types/>' },
  { name: 'ppt/media/image1.jpg', data: trailed },
])], 'Deck.pptx', { type: '' }))).arrayBuffer());
ok(!trailedDoc.includes('MotionPhoto') && !trailedDoc.includes('44.4268') && trailedDoc.includes(cleaned),
  'in a document, what follows the picture is cut off');
const trailedPdf = Buffer.concat([Buffer.from('%PDF-1.7\n1 0 obj\n<< /Subtype /Image /Filter /DCTDecode /Length ' + trailed.length + ' >>\nstream\n', 'latin1'),
  trailed, Buffer.from('\nendstream\nendobj\n%%EOF\n', 'latin1')]);
const trailedPdfOut = Buffer.from(await (await scrubFile(new File([trailedPdf], 't.pdf', { type: '' }))).arrayBuffer());
ok(trailedPdfOut.length === trailedPdf.length && !trailedPdfOut.includes('MotionPhoto') && !trailedPdfOut.includes('44.4268'),
  'in a PDF it is zeroed, keeping the length');

// ReportLab writes JPEGs out in ASCII85: cleaned through it, in place, with
// line breaks and 'z' groups kept, and checked by Python's own decoder.
const a85 = (buf) => {
  let out = '';
  for (let i = 0; i < buf.length; i += 4) {
    const chunk = buf.subarray(i, i + 4);
    const padded = Buffer.concat([chunk, Buffer.alloc(4 - chunk.length)]);
    let v = padded.readUInt32BE(0);
    if (v === 0 && chunk.length === 4) { out += 'z'; continue; }
    const d = [];
    for (let k = 0; k < 5; k++) { d.unshift(String.fromCharCode(33 + (v % 85))); v = Math.floor(v / 85); }
    out += d.slice(0, chunk.length + 1).join('');
  }
  return out.replace(/(.{64})/g, '$1\n') + '~>';
};
const photoA85 = a85(photo);
const pdfA85 = Buffer.from('%PDF-1.3\n3 0 obj\n<< /Subtype /Image /Filter [ /ASCII85Decode /DCTDecode ] /Length ' + photoA85.length +
  ' >>\nstream\n' + photoA85 + '\nendstream\nendobj\n%%EOF\n', 'latin1');
const pdfA85Out = Buffer.from(await (await scrubFile(new File([pdfA85], 'rl.pdf', { type: '' }))).arrayBuffer()).toString('latin1');
const a85Data = pdfA85Out.slice(pdfA85Out.indexOf('stream\n') + 7, pdfA85Out.indexOf('~>'));
const a85Decoded = Buffer.from(execFileSync('python3', ['-I', '-c',
  'import base64, sys; sys.stdout.write(base64.a85decode(sys.stdin.read().encode(), ignorechars=b" \\n").hex())'],
{ input: a85Data, encoding: 'utf8' }), 'hex');
const cleanedFlat = Buffer.from(photo);
blankJpegMeta(cleanedFlat, 0, cleanedFlat.length, { keepOrientation: false });
ok(pdfA85Out.length === pdfA85.length && a85Decoded.equals(cleanedFlat) && a85Data.split('\n').every((l, i, all) => l.length === 64 || i === all.length - 1),
  'a photo written in ASCII85 inside a PDF is cleaned through it, every line where it was');

// ── PDF ──

// A PDF built object by object with a real cross-reference table, then saved
// again incrementally, as an editor does: the first revision's information
// dictionary stays in the file.
function pdf(objects, { info = 5, update = null, extraTrailer = '' } = {}) {
  let out = '%PDF-1.7\n%\xe2\xe3\xcf\xd3\n';
  const offsets = {};
  for (const [num, body] of objects) { offsets[num] = out.length; out += `${num} 0 obj\n${body}\nendobj\n`; }
  const xref = (offs, prev) => {
    const at = out.length;
    out += 'xref\n';
    for (const [num, off] of Object.entries(offs)) out += `${num} 1\n${String(off).padStart(10, '0')} 00000 n \n`;
    out += `trailer\n<< /Size 20 /Root 1 0 R /Info ${info} 0 R ${extraTrailer}${prev == null ? '' : `/Prev ${prev}`} >>\nstartxref\n${at}\n%%EOF\n`;
    return at;
  };
  const first = xref(offsets, null);
  if (update) {
    const offs = {};
    for (const [num, body] of update) { offs[num] = out.length; out += `${num} 0 obj\n${body}\nendobj\n`; }
    xref(offs, first);
  }
  return Buffer.from(out, 'latin1');
}
const XMP = `<?xpacket begin="\ufeff" id="W5M0MpCehiHzreSzNTczkc9d"?><x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF><rdf:Description><dc:creator>${AUTHOR}</dc:creator><xmp:CreatorTool>Microsoft Word for Microsoft 365</xmp:CreatorTool></rdf:Description></rdf:RDF></x:xmpmeta><?xpacket end="w"?>`;
const xmpPacked = deflateRawSync(Buffer.from(`<x:xmpmeta>${AUTHOR}</x:xmpmeta>`));
const CONTENT = 'BT /F1 12 Tf 72 720 Td (The quarterly numbers are attached.) Tj ET';
const hexAuthor = Buffer.from('\ufeff' + AUTHOR, 'utf16le').swap16().toString('hex').toUpperCase();
const report = pdf([
  [1, '<< /Type /Catalog /Pages 2 0 R /Metadata 6 0 R >>'],
  [2, '<< /Type /Pages /Kids [3 0 R] /Count 1 >>'],
  [3, '<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Metadata 7 0 R >>'],
  [4, `<< /Length ${CONTENT.length} >>\nstream\n${CONTENT}\nendstream`],
  [5, `<< /Title (Microsoft Word - Quarterly \\(draft\\) final3.docx) /Author <${hexAuthor}> /Creator (Microsoft Word for Microsoft 365) /Producer (Microsoft Word for Microsoft 365) /CreationDate (D:20261027143200+02'00') /ModDate (D:20261027150000+02'00') /Company (${COMPANY}) /Manager 9 0 R /Trapped /False >>`],
  [6, `<< /Type /Metadata /Subtype /XML /Length ${Buffer.byteLength(XMP, 'latin1')} >>\nstream\n${XMP}\nendstream`],
  [7, `<< /Type /Metadata /Subtype /XML /Filter /FlateDecode /Length ${xmpPacked.length} >>\nstream\n${xmpPacked.toString('latin1')}\nendstream`],
  [9, '(Bob Manager)'],
], { update: [[5, `<< /Author (${AUTHOR}) /Producer (Adobe Acrobat Pro 2026) /ModDate (D:20261028090000Z) >>`]] });

const pdfIn = new File([report], 'report.pdf', { type: '' });
ok(isScrubbable(pdfIn) && typeOf(pdfIn) === 'application/pdf', 'a PDF is recognised, even arriving without a type');
const pdfOut = Buffer.from(await (await scrubFile(pdfIn)).arrayBuffer());
const pdfText = pdfOut.toString('latin1');
ok(pdfOut.length === report.length, 'the PDF keeps its exact length');
ok(!pdfText.includes(AUTHOR) && !pdfText.includes(hexAuthor), 'the author is gone, as text and as UTF-16 hex, in both revisions');
ok(!/Microsoft Word|Acrobat|D:2026|final3|Bob Manager/.test(pdfText) && !pdfText.includes(COMPANY),
  'so are the programs, the dates, the title naming the source file, a value held as its own object, and custom keys');
ok(!pdfText.includes('xpacket') && !pdfOut.includes(xmpPacked), 'both metadata streams are blanked, compressed or not');
ok(!/\/Filter\s*\/FlateDecode/.test(pdfText), 'and the blanked compressed one no longer claims a filter');
ok(pdfText.includes(CONTENT), 'the page content is untouched');
let pdfDiff = 0;
for (let i = 0; i < report.length; i++) if (report[i] !== pdfOut[i] && pdfOut[i] !== 0x20) pdfDiff++;
ok(pdfDiff === 0, 'every changed byte became a space');
const offsetsLand = (t) => {
  const offs = [...t.matchAll(/^(\d{10}) 00000 n /gm)].map(([, off]) => Number(off));
  return offs.length === 9 && offs.every((off) => /^\d+ 0 obj/.test(t.slice(off)));
};
ok(offsetsLand(report.toString('latin1')) && offsetsLand(pdfText), 'every cross-reference offset still lands on its object');
ok(/\/Title \(\s+\)/.test(pdfText) && /\/Author <\s+>/.test(pdfText) && pdfText.includes('/Trapped /False'),
  'strings become spaces inside their own delimiters; names are left');

const pdfAsked = async (bytes) => {
  try { await scrubFile(new File([bytes], 'x.pdf', { type: 'application/pdf' })); return 'sent'; } catch (e) { return e.undecodable && e.prompt; }
};
ok(await pdfAsked(pdf([[1, '<< /Type /Catalog >>'], [5, '<< /Author (A) >>']], { extraTrailer: '/Encrypt 8 0 R ' })) === 'scrub.cannotReadDoc',
  'an encrypted PDF is put to the person');
ok(await pdfAsked(pdf([[1, '<< /Type /Catalog >>'], [5, '<< /Author (A) >>'], [8, '<< /Type /Sig /ByteRange [0 10 20 30] /Contents <00> >>']])) === 'scrub.signedDoc',
  'so is a signed one, which a change would break');
ok(await pdfAsked(pdf([[1, '<< /Type /Catalog >>'], [3, '<< /Type /ObjStm /N 1 /First 4 /Length 0 >>\nstream\n\nendstream']])) === 'scrub.cannotReadDoc',
  'and one whose information dictionary is inside a compressed object stream');
ok(await pdfAsked(Buffer.from('just text, not a PDF')) === 'scrub.cannotReadDoc', 'and something that is not a PDF at all');
const bare = pdf([[1, '<< /Type /Catalog >>'], [5, '<< >>']]);
ok(Buffer.from(await (await scrubFile(new File([bare], 'b.pdf', { type: 'application/pdf' }))).arrayBuffer()).equals(bare),
  'a PDF with nothing to remove goes unchanged');

// Office documents can be signed too, and the signature covers their properties.
ok(await asked(zip([{ name: '[Content_Types].xml', data: '<Types/>' }, { name: '_xmlsignatures/sig1.xml', data: '<Signature/>' }])) === 'scrub.signedDoc',
  'a signed Word document is put to the person rather than have its signature broken');

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
