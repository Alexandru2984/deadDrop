/**
 * Dead Drop — remove what a photo says about where it was taken.
 *
 * A phone camera writes EXIF into every JPEG: GPS coordinates to a few metres,
 * the time, the device model and often its serial number. PNG and WebP carry
 * the same in eXIf/XMP chunks. End-to-end encryption delivers all of it to the
 * other person intact, and a peer is exactly who should not get a home address
 * from a picture of a cat.
 *
 * Re-encoding through a canvas keeps the pixels and nothing else. Orientation
 * is applied while decoding, so a portrait photo stays upright without the tag
 * that used to say so.
 *
 * A video from a phone carries the same in its MPEG-4 or QuickTime boxes:
 * ©xyz under udta, com.apple.quicktime.location in meta, XMP in a uuid box,
 * and the capture time in every movie, track and media header. Those are
 * blanked where they lie — zeroed and renamed `free`, which every player
 * skips — so no byte moves and every sample offset stays valid. Timed
 * metadata tracks that some action cameras record are left as they are.
 */

// Formats a canvas can write back without changing what kind of file it is.
const SCRUBBABLE = new Set(['image/jpeg', 'image/png', 'image/webp']);
// A decoded image costs four bytes a pixel. A small file can declare a huge
// canvas; refuse rather than let a 25 MB PNG ask for gigabytes.
const MAX_PIXELS = 50_000_000;
const JPEG_QUALITY = 0.92;

// MPEG-4 and QuickTime, as phones and voice recorders write them.
const MOVIES = new Set(['video/mp4', 'video/quicktime', 'video/3gpp', 'audio/mp4', 'audio/x-m4a']);

const EXT = {
  'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp',
  'video/mp4': 'mp4', 'video/quicktime': 'mov', 'video/3gpp': '3gp',
  'audio/mp4': 'm4a', 'audio/x-m4a': 'm4a',
};

// Names a camera, a screenshot tool or a messaging app writes by itself. They
// carry the same thing EXIF did — IMG_20261014_153212, PXL_…, Screenshot
// 2026-10-14 at 15.32.12 — the moment it was taken, and often which phone.
const GENERATED_PREFIX = /^(img|pxl|dsc|dscn|dcim|mvimg|vid|photo|image|screenshot|screen ?shot|scr|captura|whatsapp ?image|signal|telegram|snapchat|fb_img)[-_ .]/i;
const DATE_OR_TIME = /\d{8}|\d{6}[-_]\d{6}|\d{4}[-_.]\d{2}[-_.]\d{2}|\d{2}[.:]\d{2}[.:]\d{2}|\d{10,}/;

/**
 * The name to send a scrubbed image under. A name a person chose ("cat.jpg")
 * is kept; one a device generated, with the capture time in it, becomes
 * "photo.<ext>" — stripping EXIF and then sending the timestamp in the file
 * name would be keeping half the promise.
 */
export function scrubbedName(name, type) {
  const kind = String(type || '').toLowerCase();
  const ext = EXT[kind] || 'jpg';
  const stem = kind.startsWith('video/') ? 'video' : kind.startsWith('audio/') ? 'recording' : 'photo';
  const base = String(name || '').replace(/\.[^.]*$/, '');
  if (!base || GENERATED_PREFIX.test(base) || DATE_OR_TIME.test(base)) return `${stem}.${ext}`;
  return String(name);
}

/** True when `file` is a picture or a movie this module rewrites before sending. */
export function isScrubbable(file) {
  const type = String(file?.type || '').toLowerCase();
  return SCRUBBABLE.has(type) || MOVIES.has(type);
}

/** A metadata-free copy of `file`, whichever kind it is; see the two below. */
export function scrubFile(file) {
  return MOVIES.has(String(file?.type || '').toLowerCase()) ? scrubMovie(file) : scrubImage(file);
}

// Boxes that hold nothing but description: where, when, which device.
const BLANK = new Set(['udta', 'meta', 'uuid']);
// Headers with a creation and a modification time right after version/flags.
const TIMED = new Set(['mvhd', 'tkhd', 'mdhd']);
// Boxes made only of other boxes, on the way down to the ones above.
const NESTED = new Set(['moov', 'trak', 'mdia']);
const FREE = [0x66, 0x72, 0x65, 0x65];

/**
 * Returns `file` with its descriptive boxes blanked in place. Throws when the
 * file is not a well-formed movie: sending it unscrubbed would be quietly
 * breaking the promise, as with an image that cannot be rewritten.
 */
export async function scrubMovie(file) {
  const type = String(file.type).toLowerCase();
  const bytes = new Uint8Array(await file.arrayBuffer());
  if (!blankBoxes(bytes, 0, bytes.length, 0).has('moov')) throw new Error('no movie box');
  return new File([bytes], scrubbedName(file.name, type), { type, lastModified: 0 });
}

/** Walks the boxes in [start, end); returns the types seen at this level. */
function blankBoxes(bytes, start, end, depth) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const seen = new Set();
  let pos = start;
  while (end - pos >= 8) {
    let size = view.getUint32(pos);
    const type = String.fromCharCode(...bytes.subarray(pos + 4, pos + 8));
    let header = 8;
    if (size === 1) {
      if (end - pos < 16) throw new Error('truncated box');
      const large = view.getBigUint64(pos + 8);
      if (large > BigInt(end - pos)) throw new Error('box overruns its parent');
      size = Number(large);
      header = 16;
    } else if (size === 0) {
      size = end - pos; // runs to the end of its parent
    }
    if (size < header || size > end - pos) throw new Error('malformed box');
    const body = pos + header;
    const boxEnd = pos + size;
    seen.add(type);
    if (BLANK.has(type)) {
      bytes.set(FREE, pos + 4);
      bytes.fill(0, body, boxEnd);
    } else if (TIMED.has(type) && boxEnd - body >= 4) {
      const span = bytes[body] === 1 ? 16 : 8;
      if (boxEnd - body >= 4 + span) bytes.fill(0, body + 4, body + 4 + span);
    } else if (NESTED.has(type) && depth < 8) {
      blankBoxes(bytes, body, boxEnd, depth + 1);
    }
    pos = boxEnd;
  }
  return seen;
}

/**
 * Returns a metadata-free copy of `file`, or `file` itself when its type is not
 * one we rewrite. Throws when a rewritable image cannot be rewritten: sending
 * the original instead would be quietly doing the thing the user turned this
 * on to prevent.
 */
export async function scrubImage(file) {
  if (!isScrubbable(file)) return file;
  const type = file.type.toLowerCase();
  const bitmap = await createImageBitmap(file, { imageOrientation: 'from-image' });
  try {
    if (!bitmap.width || !bitmap.height || bitmap.width * bitmap.height > MAX_PIXELS) {
      throw new Error('image dimensions out of range');
    }
    const blob = await encode(bitmap, type);
    if (!blob || blob.type !== type) throw new Error('re-encoding failed');
    return new File([blob], scrubbedName(file.name, type), { type, lastModified: 0 });
  } finally {
    bitmap.close?.();
  }
}

async function encode(bitmap, type) {
  const quality = type === 'image/png' ? undefined : JPEG_QUALITY;
  if (typeof OffscreenCanvas === 'function') {
    const canvas = new OffscreenCanvas(bitmap.width, bitmap.height);
    canvas.getContext('2d').drawImage(bitmap, 0, 0);
    return canvas.convertToBlob({ type, quality });
  }
  const canvas = document.createElement('canvas');
  canvas.width = bitmap.width;
  canvas.height = bitmap.height;
  canvas.getContext('2d').drawImage(bitmap, 0, 0);
  try {
    return await new Promise((resolve) => canvas.toBlob(resolve, type, quality));
  } finally {
    canvas.width = 0;
    canvas.height = 0;
  }
}
