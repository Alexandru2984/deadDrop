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
    return new File([blob], file.name, { type, lastModified: 0 });
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
