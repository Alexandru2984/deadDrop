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
 */

// Formats a canvas can write back without changing what kind of file it is.
const SCRUBBABLE = new Set(['image/jpeg', 'image/png', 'image/webp']);
// A decoded image costs four bytes a pixel. A small file can declare a huge
// canvas; refuse rather than let a 25 MB PNG ask for gigabytes.
const MAX_PIXELS = 50_000_000;
const JPEG_QUALITY = 0.92;

const EXT = { 'image/jpeg': 'jpg', 'image/png': 'png', 'image/webp': 'webp' };

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
  const ext = EXT[String(type || '').toLowerCase()] || 'jpg';
  const base = String(name || '').replace(/\.[^.]*$/, '');
  if (!base || GENERATED_PREFIX.test(base) || DATE_OR_TIME.test(base)) return `photo.${ext}`;
  return String(name);
}

/** True when `file` is an image this module rewrites before sending. */
export function isScrubbable(file) {
  return SCRUBBABLE.has(String(file?.type || '').toLowerCase());
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
