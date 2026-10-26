/**
 * Movie metadata removal, on files built box by box.
 *
 *   node test/scrub.selftest.mjs
 *
 * A phone video says where it was shot (©xyz under udta, or Apple's location
 * key under meta), when (every movie, track and media header), and on what.
 * The scrubber blanks those in place. What has to hold: none of it survives,
 * not one byte moves — so the sample offsets the player reads still point at
 * the same media — and anything that is not a well-formed movie is refused
 * rather than sent as it was.
 */

import { scrubMovie, scrubbedName, isScrubbable } from '../web/js/scrub.js';

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

console.log(failures === 0 ? '\nALL PASS ✅' : `\n${failures} FAILURE(S) ❌`);
process.exit(failures === 0 ? 0 : 1);
