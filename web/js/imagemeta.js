/**
 * Dead Drop — remove a photo's metadata without decoding it.
 *
 * A phone photo pasted into a Word document or a slide is kept as the
 * original JPEG, EXIF and all: where it was taken, when, and on which phone.
 * A PDF made from that document carries the same JPEG again. The canvas
 * re-encoding used for photos sent on their own cannot reach inside those,
 * and would change pixels the document's layout depends on.
 *
 * Instead the descriptive segments are blanked where they lie: EXIF, XMP,
 * Photoshop's IPTC block, makers' own segments and comments become zeros of
 * the same length, so
 * the picture and every byte after it stay where they were. What decoding
 * needs — the JFIF header, the colour profile, Adobe's colour-transform flag —
 * is kept. A photo's orientation can be kept in a minimal EXIF of its own, so
 * a portrait shot pasted into a document does not turn on its side.
 *
 * A PNG or WebP keeps only the chunks it takes to draw it — colour profile
 * and animation frames included — and loses the rest outright: text, EXIF,
 * XMP, times, makers' private chunks. Neither format has a length to keep.
 * Re-encoding them through a canvas instead used to turn an animated sticker
 * into its first frame.
 */

const APP0 = 0xe0;
const APP1 = 0xe1;
const APP2 = 0xe2;
const APP14 = 0xee;
const COM = 0xfe;
const ICC_PROFILE = [0x49, 0x43, 0x43, 0x5f, 0x50, 0x52, 0x4f, 0x46, 0x49, 0x4c, 0x45, 0]; // "ICC_PROFILE\0"

// Every application segment and comment says something about where the
// picture came from — EXIF, XMP, IPTC, a maker's notes, a multi-picture
// index — except the three a decoder reads to draw it.
function isDescriptive(bytes, marker, body, segEnd) {
  if (marker === COM) return true;
  if (marker < APP0 || marker > 0xef || marker === APP0 || marker === APP14) return false;
  if (marker === APP2) return segEnd - body < ICC_PROFILE.length || ICC_PROFILE.some((b, i) => bytes[body + i] !== b);
  return true;
}
const SOS = 0xda;
const EOI = 0xd9;

/**
 * Walks the JPEG in bytes[start, end) segment by segment — through every
 * scan of a progressive file, past stuffed bytes and restart markers —
 * calling visit(marker, body, segEnd) for each segment with a length.
 * Returns the index just past the end-of-image marker, or -1 when the walk
 * could not reach it.
 */
function walkJpeg(bytes, start, end, visit) {
  if (end - start < 4 || bytes[start] !== 0xff || bytes[start + 1] !== 0xd8) return -1;
  let pos = start + 2;
  let scanning = false;
  while (pos + 1 < end) {
    if (scanning) {
      // Entropy-coded data: 0xFF is followed by a stuffed zero, a restart
      // marker or another 0xFF; anything else is the next marker.
      if (bytes[pos] !== 0xff) { pos++; continue; }
      const next = bytes[pos + 1];
      if (next === 0 || next === 0xff || (next >= 0xd0 && next <= 0xd7)) { pos += next === 0xff ? 1 : 2; continue; }
      scanning = false;
      continue;
    }
    if (bytes[pos] !== 0xff) return -1;
    const marker = bytes[pos + 1];
    if (marker === 0xff) { pos++; continue; } // fill byte
    if (marker === EOI) return pos + 2;
    // Standalone markers carry no length.
    if (marker === 0x01 || (marker >= 0xd0 && marker <= 0xd7)) { pos += 2; continue; }
    if (pos + 4 > end) return -1;
    const segEnd = pos + 2 + ((bytes[pos + 2] << 8) | bytes[pos + 3]);
    if (segEnd > end || segEnd < pos + 4) return -1;
    visit(marker, pos + 4, segEnd);
    pos = segEnd;
    if (marker === SOS) scanning = true;
  }
  return -1;
}

/**
 * Blanks the metadata segments of the JPEG in bytes[start, end), in place —
 * those between the scans of a progressive file too. Returns true when
 * anything was blanked.
 */
export function blankJpegMeta(bytes, start = 0, end = bytes.length, { keepOrientation = true } = {}) {
  let changed = false;
  walkJpeg(bytes, start, end, (marker, body, segEnd) => {
    if (!isDescriptive(bytes, marker, body, segEnd)) return;
    const orientation = keepOrientation && marker === APP1 ? exifOrientation(bytes, body, segEnd) : 0;
    bytes.fill(0, body, segEnd);
    if (orientation > 1) writeOrientation(bytes, body, segEnd, orientation);
    changed = true;
  });
  return changed;
}

/**
 * Where the picture in bytes[start, end) ends: just past its EOI marker, or
 * -1 when it cannot be found. Phones put more after it — a motion photo's
 * video, with its own location; Samsung's block of capture times; the
 * depth and gain maps of a multi-picture file — which no decoder reads.
 */
export function jpegEnd(bytes, start = 0, end = bytes.length) {
  return walkJpeg(bytes, start, end, () => {});
}

/**
 * A clean copy of a JPEG sent on its own: descriptive segments blanked, the
 * orientation kept, and cut at the end of the picture. Lossless — the colour
 * profile and every pixel stay as the camera wrote them. Null when the file
 * cannot be walked to its end, so the caller re-encodes it instead.
 */
export function cleanJpeg(input) {
  const bytes = input.slice();
  const end = jpegEnd(bytes);
  if (end < 0) return null;
  blankJpegMeta(bytes, 0, end);
  return bytes.subarray(0, end);
}

const EXIF_HEADER = [0x45, 0x78, 0x69, 0x66, 0, 0]; // "Exif\0\0"

/** The orientation tag of the EXIF block in [start, end), or 0. */
function exifOrientation(bytes, start, end) {
  if (end - start < 14 || EXIF_HEADER.some((b, i) => bytes[start + i] !== b)) return 0;
  return tiffOrientation(bytes, start + 6, end);
}

/** The orientation tag of the TIFF structure at `tiff`, or 0. */
function tiffOrientation(bytes, tiff, end) {
  if (end - tiff < 8) return 0;
  const little = bytes[tiff] === 0x49 && bytes[tiff + 1] === 0x49;
  if (!little && !(bytes[tiff] === 0x4d && bytes[tiff + 1] === 0x4d)) return 0;
  const u16 = (at) => (at + 2 > end ? -1 : little ? bytes[at] | (bytes[at + 1] << 8) : (bytes[at] << 8) | bytes[at + 1]);
  const u32 = (at) => (at + 4 > end ? -1 : little
    ? (bytes[at] | (bytes[at + 1] << 8) | (bytes[at + 2] << 16) | (bytes[at + 3] << 24)) >>> 0
    : ((bytes[at] << 24) | (bytes[at + 1] << 16) | (bytes[at + 2] << 8) | bytes[at + 3]) >>> 0);
  const ifd = u32(tiff + 4);
  if (ifd < 8 || tiff + ifd + 2 > end) return 0;
  const count = u16(tiff + ifd);
  for (let i = 0; i < count; i++) {
    const entry = tiff + ifd + 2 + i * 12;
    if (entry + 12 > end) return 0;
    if (u16(entry) === 0x0112) {
      const value = u16(entry + 8);
      return value >= 1 && value <= 8 ? value : 0;
    }
  }
  return 0;
}

/** A minimal EXIF holding only the orientation, at the start of a blank segment. */
function writeOrientation(bytes, start, end, orientation) {
  const exif = [
    ...EXIF_HEADER,
    0x4d, 0x4d, 0, 0x2a, 0, 0, 0, 8, // big-endian TIFF, IFD0 at 8
    0, 1, // one entry
    0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, orientation, 0, 0, // Orientation, SHORT, 1
    0, 0, 0, 0, // no next IFD
  ];
  if (end - start >= exif.length) bytes.set(exif, start);
}

const PNG_SIGNATURE = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
// What it takes to draw a PNG, colour-managed and animated. Everything else —
// text, EXIF, XMP, times, a maker's private chunks, content credentials — is
// description, and goes.
const PNG_KEPT = new Set([
  'IHDR', 'PLTE', 'IDAT', 'IEND', 'tRNS', 'cHRM', 'gAMA', 'iCCP', 'sBIT', 'sRGB',
  'cICP', 'mDCV', 'cLLI', 'bKGD', 'pHYs', 'sPLT', 'hIST', 'acTL', 'fcTL', 'fdAT',
]);

/**
 * A copy of the PNG with only the chunks it needs to be drawn, ending at
 * IEND. Null when it is not a PNG this can walk to its end, or when it says
 * it is turned on its side — then it is re-encoded, which applies that.
 */
export function cleanPng(bytes) {
  if (bytes.length < 8 || PNG_SIGNATURE.some((b, i) => bytes[i] !== b)) return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const kept = [bytes.subarray(0, 8)];
  let pos = 8;
  for (;;) {
    if (pos + 12 > bytes.length) return null;
    const length = view.getUint32(pos);
    const chunkEnd = pos + 12 + length;
    if (chunkEnd > bytes.length) return null;
    const type = String.fromCharCode(...bytes.subarray(pos + 4, pos + 8));
    if (type === 'eXIf' && tiffOrientation(bytes, pos + 8, pos + 8 + length) > 1) return null;
    if (PNG_KEPT.has(type)) kept.push(bytes.subarray(pos, chunkEnd));
    pos = chunkEnd;
    if (type === 'IEND') break;
  }
  return concat(kept);
}

/** The PNG without its descriptive chunks, or null when it had none. */
export function stripPngMeta(bytes) {
  const out = cleanPng(bytes);
  return out && out.length !== bytes.length ? out : null;
}

// What it takes to draw a WebP, still or animated.
const WEBP_KEPT = new Set(['VP8 ', 'VP8L', 'VP8X', 'ALPH', 'ICCP', 'ANIM', 'ANMF']);
const WEBP_EXIF = 0x08;
const WEBP_XMP = 0x04;

/**
 * A copy of the WebP without its EXIF, XMP and unknown chunks, its header
 * flags and size made to match. Null when it is not a WebP this can walk, or
 * when its EXIF turns it on its side — then it is re-encoded.
 */
export function cleanWebp(bytes) {
  const tag = (at) => String.fromCharCode(...bytes.subarray(at, at + 4));
  if (bytes.length < 20 || tag(0) !== 'RIFF' || tag(8) !== 'WEBP') return null;
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const riffEnd = 8 + view.getUint32(4, true);
  if (riffEnd > bytes.length) return null;
  const kept = [];
  let pos = 12;
  while (pos + 8 <= riffEnd) {
    const length = view.getUint32(pos + 4, true);
    const chunkEnd = pos + 8 + length + (length & 1);
    if (chunkEnd > riffEnd) return null;
    const type = tag(pos);
    if (type === 'EXIF') {
      const data = pos + 8;
      const tiff = EXIF_HEADER.every((b, i) => bytes[data + i] === b) ? data + 6 : data;
      if (tiffOrientation(bytes, tiff, data + length) > 1) return null;
    }
    if (WEBP_KEPT.has(type)) kept.push(bytes.slice(pos, chunkEnd));
    pos = chunkEnd;
  }
  if (pos !== riffEnd || !kept.length) return null;
  const vp8x = kept.find((c) => String.fromCharCode(...c.subarray(0, 4)) === 'VP8X');
  if (vp8x) vp8x[8] &= ~(WEBP_EXIF | WEBP_XMP);
  const body = concat(kept);
  const out = new Uint8Array(12 + body.length);
  out.set(bytes.subarray(0, 12));
  new DataView(out.buffer).setUint32(4, 4 + body.length, true);
  out.set(body, 12);
  return out;
}

function concat(parts) {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) { out.set(part, at); at += part.length; }
  return out;
}
