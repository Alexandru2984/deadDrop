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
 * Some PDFs cannot be cleaned this way: an encrypted one, one that keeps its
 * information dictionary inside a compressed object stream, and one that is
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

  // Every information dictionary any revision's trailer names.
  const infos = new Set([...text.matchAll(/\/Info\s+(\d+)\s+(\d+)\s+R/g)].map(([, num, gen]) => `${num} ${gen}`));
  for (const info of infos) {
    const [num, gen] = info.split(' ');
    const found = objects(text, num, gen);
    if (!found.length) throw unreadable('information dictionary in an object stream');
    for (const at of found) {
      if (!text.startsWith('<<', at)) throw unreadable('information is not a dictionary');
      walkDict(text, at, blankString, (refNum, refGen) => {
        // A value kept as its own object: `/Author 15 0 R`.
        const held = objects(text, refNum, refGen);
        if (!held.length) throw unreadable('information value in an object stream');
        for (const v of held) {
          if (text[v] === '(' || (text[v] === '<' && text[v + 1] !== '<')) blankString(v, stringEnd(text, v));
        }
      });
    }
  }

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
  const length = /\/Length\s+(\d+)(?!\s+\d+\s+R)/.exec(dict);
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
