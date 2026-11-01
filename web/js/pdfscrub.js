/**
 * Dead Drop — remove what a PDF says about who made it.
 *
 * A PDF's document information dictionary names its author, the program that
 * wrote it and the one that converted it ("Microsoft Word - CV_final3.docx"),
 * when it was created and last changed, and whatever custom keys the tool
 * added. An XMP metadata stream repeats all of it, often with more.
 *
 * Nothing is moved: every string in the information dictionary becomes
 * spaces inside its own delimiters, and every metadata stream's bytes become
 * spaces. The file keeps its length and every byte offset its cross-reference
 * table points at, so it opens exactly as before. Earlier revisions of an
 * edited PDF are cleaned too — an incremental save keeps the old dictionary
 * in the file.
 *
 * A photo placed in the document is stored as the original JPEG, EXIF and
 * all; its descriptive segments are blanked the same way (imagemeta.js).
 *
 * Ghostscript, qpdf and Acrobat's reduced-size saving keep the information
 * dictionary inside a compressed object stream. That stream is inflated, its
 * strings blanked the same way, and compressed again into the bytes it had:
 * what it no longer needs is left as whitespace before `endstream`, and its
 * length says so, so every offset in the file still holds.
 *
 * Some PDFs cannot be cleaned this way: an encrypted one, one whose object
 * stream is compressed in a way this cannot write back, and one that is
 * digitally signed, where any change breaks the signature. Those are put to
 * the person, never sent as if they were clean.
 */

import { blankJpegMeta, jpegEnd } from './imagemeta.js';

const SPACE = 0x20;
// Keys whose string value says who, with what, or when, wherever they occur:
// an information dictionary no trailer points at any more, or an attached
// file's own dates.
const SWEPT = /\/(?:Author|Creator|Producer|CreationDate|ModDate|LastModified|Company|SourceModified)\s*(?=[(<])/g;

function unreadable(why, prompt = 'scrub.cannotReadDoc') {
  return Object.assign(new Error(why), { undecodable: true, prompt });
}

/** A copy of `file` with its information dictionary and XMP blanked. */
export async function scrubPdf(file) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  // One character per byte, so an index into the text is an index into the file.
  const text = new TextDecoder('latin1').decode(bytes);
  if (!text.slice(0, 1024).includes('%PDF-')) throw unreadable('not a PDF');
  if (/\/Encrypt\s*(?:\d+\s+\d+\s+R|<<)/.test(text)) throw unreadable('encrypted');
  if (/\/ByteRange\s*\[/.test(text)) throw unreadable('signed', 'scrub.signedDoc');

  const blank = (start, end) => bytes.fill(SPACE, start, end);
  const blankString = (start, end) => blank(start + 1, end - 1);

  // Every information dictionary any revision's trailer names, with every
  // value it keeps as an object of its own (`/Author 15 0 R`), wherever each
  // lies: in plain text, or in a compressed object stream.
  const packed = new ObjectStreams(bytes, text);
  const cleaned = new Set();
  const clean = async (num, gen, isInfo) => {
    if (cleaned.has(`${num} ${gen}`)) return;
    cleaned.add(`${num} ${gen}`);
    const refs = [];
    const plain = objects(text, num, gen);
    for (const at of plain) {
      if (text.startsWith('<<', at)) walkDict(text, at, blankString, (n, g) => refs.push([n, g]));
      else if (isInfo) throw unreadable('information is not a dictionary');
      else if (text[at] === '(' || (text[at] === '<' && text[at + 1] !== '<')) blankString(at, stringEnd(text, at));
    }
    if (!plain.length && !await packed.blank(num, gen, isInfo, refs)) {
      throw unreadable(isInfo ? 'information dictionary not found' : 'information value not found');
    }
    for (const [n, g] of refs) await clean(n, g, false);
  };
  const infos = new Set([...text.matchAll(/\/Info\s+(\d+)\s+(\d+)\s+R/g)].map(([, num, gen]) => `${num} ${gen}`));
  for (const info of infos) await clean(...info.split(' '), true);
  await packed.writeBack();

  for (const match of text.matchAll(SWEPT)) {
    const at = match.index + match[0].length;
    if (text[at] === '<' && text[at + 1] === '<') continue;
    blankString(at, stringEnd(text, at));
  }

  // Metadata streams — the document's XMP, and any a page or image carries —
  // and JPEG images.
  for (const match of text.matchAll(/\d+\s+\d+\s+obj\s*<</g)) {
    const dictStart = match.index + match[0].length - 2;
    const dictEnd = dictEndOf(text, dictStart);
    if (dictEnd < 0) continue;
    const dict = text.slice(dictStart, dictEnd);
    // A JPEG image: a PDF draws it by its own matrix, so its EXIF
    // orientation means nothing here and goes with the rest.
    if (/\/Subtype\s*\/Image\b/.test(dict)) {
      const plain = /\/Filter\s*(?:\/DCTDecode|\[\s*\/DCTDecode\s*\])(?![A-Za-z])/.test(dict);
      const a85 = /\/Filter\s*\[\s*\/ASCII85Decode\s*\/DCTDecode\s*\]/.test(dict);
      const data = (plain || a85) && streamData(text, dictEnd, dict);
      if (data && plain) {
        blankJpegMeta(bytes, data.start, data.end, { keepOrientation: false });
        // Whatever a phone put after the picture, zeroed in place.
        const end = jpegEnd(bytes, data.start, data.end);
        if (end > 0) bytes.fill(0, end, data.end);
      }
      if (data && a85) blankA85Jpeg(bytes, text, data.start, data.end);
      continue;
    }
    if (!/\/Type\s*\/Metadata\b/.test(dict)) continue;
    const data = streamData(text, dictEnd, dict);
    if (!data) throw unreadable('metadata stream without data');
    blank(data.start, data.end);
    // Spaces under a compression filter would not decode: the stream becomes
    // a plain one, which a run of spaces is.
    const filter = /\/Filter\s*(?:\/[^\s/[\]<>()]+|\[[^\]]*\])/.exec(dict);
    if (filter) blank(dictStart + filter.index, dictStart + filter.index + filter[0].length);
    if (/\/DecodeParms\b/.test(dict)) throw unreadable('metadata stream with decode parameters');
  }

  // Any XMP packet still standing, wherever it was embedded.
  for (const match of text.matchAll(/<\?xpacket begin=/g)) {
    const close = text.indexOf('<?xpacket end=', match.index);
    const end = close < 0 ? -1 : text.indexOf('?>', close);
    if (end < 0) throw unreadable('unterminated XMP packet');
    blank(match.index, end + 2);
  }

  return new File([bytes], file.name, { type: 'application/pdf', lastModified: 0 });
}

/**
 * The same for a JPEG written out in ASCII85, as ReportLab does. Every
 * group of five characters stands for four bytes, so the picture is decoded,
 * cleaned, and each changed group written back over its own characters —
 * line breaks and all stay where they were, and so does every offset.
 */
function blankA85Jpeg(bytes, text, start, end) {
  const groups = [];
  let digits = [];
  let at = start;
  if (text.startsWith('<~', at)) at += 2;
  for (; at < end; at++) {
    const c = text.charCodeAt(at);
    if (c === 0x7e) break; // ~> ends the data
    if (c === 0x7a && !digits.length) { groups.push({ zero: true }); continue; }
    if (c < 0x21 || c > 0x75) continue; // whitespace
    digits.push(at);
    if (digits.length === 5) { groups.push({ digits }); digits = []; }
  }
  if (digits.length === 1) return;
  if (digits.length) groups.push({ digits });

  const decoded = new Uint8Array(groups.length * 4);
  let length = 0;
  for (const g of groups) {
    if (g.zero) { length += 4; continue; }
    let value = 0;
    for (let i = 0; i < 5; i++) value = value * 85 + (i < g.digits.length ? text.charCodeAt(g.digits[i]) - 33 : 84);
    if (value > 0xffffffff) return;
    const n = g.digits.length - 1;
    for (let i = 0; i < n; i++) decoded[length + i] = (value >>> (24 - 8 * i)) & 0xff;
    g.at = length;
    length += n;
  }
  const picture = decoded.subarray(0, length);
  const before = picture.slice();
  const blanked = blankJpegMeta(picture, 0, length, { keepOrientation: false });
  const pictureEnd = jpegEnd(picture);
  if (pictureEnd > 0 && pictureEnd < length) picture.fill(0, pictureEnd);
  else if (!blanked) return;
  for (const g of groups) {
    if (g.zero) continue; // only ever blanked to zero, which it already is
    const n = g.digits.length - 1;
    if (picture.subarray(g.at, g.at + n).every((b, i) => b === before[g.at + i])) continue;
    let value = 0;
    for (let i = 0; i < 4; i++) value = value * 256 + (i < n ? picture[g.at + i] : 0);
    for (let i = 4; i >= 0; i--) {
      if (i < g.digits.length) bytes[g.digits[i]] = 33 + (value % 85);
      value = Math.floor(value / 85);
    }
  }
}

/**
 * The compressed object streams of a PDF 1.5 file, each inflated when first
 * needed. One whose strings were blanked is compressed again into the bytes
 * it had; see the top of this file.
 */
class ObjectStreams {
  constructor(bytes, text) {
    this.bytes = bytes;
    this.text = text;
    this.streams = null;
  }

  /**
   * Blank the strings of object `num` wherever an object stream holds it,
   * noting the objects it refers to in `refs`. False when no stream holds it
   * — or when one that might could not be read.
   */
  async blank(num, gen, isInfo, refs) {
    if (gen !== '0') return false; // an object in a stream is always generation 0
    let found = false;
    let unread = false;
    for (const stream of this._list()) {
      if (!await this._open(stream)) {
        unread = true;
        continue;
      }
      const at = stream.starts.get(num);
      if (at === undefined) continue;
      found = true;
      const { decoded, view } = stream;
      const blankString = (start, end) => {
        decoded.fill(SPACE, start + 1, end - 1);
        stream.dirty = true;
      };
      let i = at;
      while (/\s/.test(view[i] ?? '')) i++;
      if (view.startsWith('<<', i)) walkDict(view, i, blankString, (n, g) => refs.push([n, g]));
      else if (isInfo) throw unreadable('information is not a dictionary');
      else if (view[i] === '(' || (view[i] === '<' && view[i + 1] !== '<')) blankString(i, stringEnd(view, i));
    }
    return found && !unread;
  }

  /** Compress every changed stream back into its place. */
  async writeBack() {
    for (const stream of this.streams ?? []) {
      if (!stream.dirty) continue;
      const packed = await squeeze(stream.decoded, 'CompressionStream');
      const { start, end } = stream.data;
      if (packed.length > end - start) throw unreadable('object stream does not fit once cleaned');
      this._setLength(stream, packed.length);
      this.bytes.set(packed, start);
      this.bytes.fill(SPACE, start + packed.length, end);
      if (start + packed.length < end) this.bytes[start + packed.length] = 0x0a;
    }
  }

  _list() {
    if (this.streams) return this.streams;
    this.streams = [];
    for (const match of this.text.matchAll(/\d+\s+\d+\s+obj\s*<</g)) {
      const dictStart = match.index + match[0].length - 2;
      const dictEnd = dictEndOf(this.text, dictStart);
      if (dictEnd < 0) continue;
      const dict = this.text.slice(dictStart, dictEnd);
      if (/\/Type\s*\/ObjStm(?![A-Za-z])/.test(dict)) this.streams.push({ dictStart, dictEnd, dict });
    }
    return this.streams;
  }

  /** Inflate a stream and index its objects; false when that cannot be done. */
  async _open(stream) {
    if (stream.opened !== undefined) return stream.opened;
    stream.opened = false;
    const { dict } = stream;
    // Plain Flate only: a predictor or a second filter could not be written back.
    if (!/\/Filter\s*(?:\/FlateDecode|\[\s*\/FlateDecode\s*\])(?![A-Za-z])/.test(dict) || /\/DecodeParms\b/.test(dict)) return false;
    const count = /\/N\s+(\d+)(?!\d|\s+\d+\s+R)/.exec(dict);
    const first = /\/First\s+(\d+)(?!\d|\s+\d+\s+R)/.exec(dict);
    const data = streamData(this.text, stream.dictEnd, dict);
    if (!count || !first || !data) return false;
    let decoded;
    try {
      decoded = await squeeze(this.bytes.subarray(data.start, data.end), 'DecompressionStream');
    } catch {
      return false;
    }
    const view = new TextDecoder('latin1').decode(decoded);
    const numbers = view.slice(0, Number(first[1])).match(/\d+/g) ?? [];
    if (numbers.length < 2 * Number(count[1])) return false;
    stream.starts = new Map();
    for (let i = 0; i < Number(count[1]); i++) {
      stream.starts.set(numbers[2 * i], Number(first[1]) + Number(numbers[2 * i + 1]));
    }
    Object.assign(stream, { data, decoded, view, opened: true });
    return true;
  }

  /** Write the stream's new /Length over the old one, in the same width. */
  _setLength(stream, length) {
    const direct = /\/Length\s+(\d+)(?!\d|\s+\d+\s+R)/.exec(stream.dict);
    let at;
    let width;
    if (direct) {
      at = stream.dictStart + direct.index + direct[0].length - direct[1].length;
      width = direct[1].length;
    } else {
      const ref = /\/Length\s+(\d+)\s+(\d+)\s+R/.exec(stream.dict);
      const held = ref ? objects(this.text, ref[1], ref[2]) : [];
      const digits = held.length === 1 ? /^\d+/.exec(this.text.slice(held[0], held[0] + 24)) : null;
      if (!digits) throw unreadable('object stream length cannot be rewritten');
      at = held[0];
      width = digits[0].length;
    }
    const text = String(length).padEnd(width, ' ');
    if (text.length > width) throw unreadable('object stream length cannot be rewritten');
    for (let i = 0; i < width; i++) this.bytes[at + i] = text.charCodeAt(i);
  }
}

// Bounded either way: a small stream that inflates to gigabytes is refused.
const MAX_OBJECT_STREAM = 32 << 20;

/** `bytes` through a zlib (de)compression stream. */
async function squeeze(bytes, kind) {
  const Stream = kind === 'CompressionStream' ? CompressionStream : DecompressionStream;
  const reader = new Blob([bytes]).stream().pipeThrough(new Stream('deflate')).getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > MAX_OBJECT_STREAM) throw unreadable('object stream too large');
      chunks.push(value);
    }
  } finally {
    reader.cancel().catch(() => {});
  }
  return new Uint8Array(await new Blob(chunks).arrayBuffer());
}

/** Where each `num gen obj` body begins, in every revision. */
function objects(text, num, gen) {
  const at = [];
  const re = new RegExp(`(?:^|[^0-9])${num}\\s+${gen}\\s+obj\\s*`, 'g');
  for (const m of text.matchAll(re)) at.push(m.index + m[0].length);
  return at;
}

/** Index just past the `>>` closing the dictionary at `start`, or -1. */
function dictEndOf(text, start) {
  try {
    return walkDict(text, start, () => {}, () => {});
  } catch {
    return -1;
  }
}

/**
 * Walks the dictionary opening at `start`, calling onString(start, end) for
 * every literal and hex string at any depth and onRef(num, gen) for every
 * indirect reference. Returns the index just past its closing `>>`.
 */
function walkDict(text, start, onString, onRef) {
  let depth = 0;
  let i = start;
  while (i < text.length) {
    const c = text[i];
    if (c === '%') {
      while (i < text.length && text[i] !== '\n' && text[i] !== '\r') i++;
    } else if (c === '(') {
      const end = stringEnd(text, i);
      onString(i, end);
      i = end;
    } else if (c === '<' && text[i + 1] === '<') {
      depth++;
      i += 2;
    } else if (c === '>' && text[i + 1] === '>') {
      depth--;
      i += 2;
      if (depth === 0) return i;
    } else if (c === '<') {
      const end = stringEnd(text, i);
      onString(i, end);
      i = end;
    } else if (/\d/.test(c) && !/[\d.]/.test(text[i - 1])) {
      const ref = /^(\d+)\s+(\d+)\s+R(?![A-Za-z])/.exec(text.slice(i, i + 24));
      if (ref) {
        onRef(ref[1], ref[2]);
        i += ref[0].length;
      } else {
        i++;
      }
    } else {
      i++;
    }
  }
  throw unreadable('unterminated dictionary');
}

/** Index just past the literal `( … )` or hex `< … >` string at `start`. */
function stringEnd(text, start) {
  if (text[start] === '<') {
    const end = text.indexOf('>', start);
    if (end < 0) throw unreadable('unterminated string');
    return end + 1;
  }
  let nest = 0;
  for (let i = start; i < text.length; i++) {
    const c = text[i];
    if (c === '\\') i++;
    else if (c === '(') nest++;
    else if (c === ')' && --nest === 0) return i + 1;
  }
  throw unreadable('unterminated string');
}

/** The data of the stream whose dictionary ends at `dictEnd`. */
function streamData(text, dictEnd, dict) {
  const head = /^\s*stream(\r\n|\n)/.exec(text.slice(dictEnd, dictEnd + 64));
  if (!head) return null;
  const start = dictEnd + head[0].length;
  const length = /\/Length\s+(\d+)(?!\d|\s+\d+\s+R)/.exec(dict);
  if (length) {
    const end = start + Number(length[1]);
    if (/^\s*endstream/.test(text.slice(end, end + 32))) return { start, end };
  }
  // An indirect /Length, or a wrong one: up to the end-of-line before endstream.
  const close = text.indexOf('endstream', start);
  if (close < 0) return null;
  let end = close;
  if (text[end - 1] === '\n') end--;
  if (text[end - 1] === '\r') end--;
  return { start, end: Math.max(start, end) };
}
