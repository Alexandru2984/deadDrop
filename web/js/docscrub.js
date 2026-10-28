/**
 * Dead Drop — remove what an office document says about who wrote it.
 *
 * A .docx, .xlsx or .pptx is a ZIP archive, and so is a LibreOffice .odt,
 * .ods or .odp. Beside the content they carry a property sheet: the author's
 * name and the last person to save it, their company and manager, the
 * template's path on their disk, when it was created, saved and printed, how
 * many minutes it was edited for, and custom properties — where a company's
 * sensitivity label puts its tenant ID. The archive adds a timestamp to every
 * file inside it, and some tools add more in "extra" fields.
 *
 * The archive is rebuilt with every part copied byte for byte, compressed as
 * it was, except the property parts, which are replaced by empty ones. Every
 * entry's time becomes 1980-01-01, the earliest a ZIP can say, and extra
 * fields and comments are dropped. What the document says — its text, its
 * comments and tracked changes with their authors' names — is left alone:
 * that is content, and the person sending it can see it.
 *
 * Only the standard places are cleaned (docProps/ for Office, meta.xml for
 * OpenDocument), which is where Word, Excel, PowerPoint, LibreOffice and
 * Google Docs all put them.
 *
 * A few more places say who the person is where they cannot see it, and are
 * rewritten too: where Word found the template — a path on their disk, with
 * their user name — the folder Excel last saved the workbook in, the work
 * e-mail or Microsoft account behind each comment author's name, and the
 * printer the document was set up for, with what its driver keeps about the
 * user.
 *
 * Pictures inside are cleaned too: a phone photo pasted into a document is
 * kept as the original JPEG, with where and when it was taken. See
 * imagemeta.js.
 */

import { blankJpegMeta, jpegEnd, stripPngMeta } from './imagemeta.js';

export const DOCUMENTS = new Set([
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  'application/vnd.ms-word.document.macroenabled.12',
  'application/vnd.ms-excel.sheet.macroenabled.12',
  'application/vnd.ms-powerpoint.presentation.macroenabled.12',
  'application/vnd.oasis.opendocument.text',
  'application/vnd.oasis.opendocument.spreadsheet',
  'application/vnd.oasis.opendocument.presentation',
]);

export const DOCUMENT_EXTENSIONS = {
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  xlsx: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
  pptx: 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
  docm: 'application/vnd.ms-word.document.macroenabled.12',
  xlsm: 'application/vnd.ms-excel.sheet.macroenabled.12',
  pptm: 'application/vnd.ms-powerpoint.presentation.macroenabled.12',
  odt: 'application/vnd.oasis.opendocument.text',
  ods: 'application/vnd.oasis.opendocument.spreadsheet',
  odp: 'application/vnd.oasis.opendocument.presentation',
};

const XML = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\r\n';
const OOXML_EMPTY = new Map(Object.entries({
  'docProps/core.xml': XML + '<cp:coreProperties ' +
    'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" ' +
    'xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:dcterms="http://purl.org/dc/terms/" ' +
    'xmlns:dcmitype="http://purl.org/dc/dcmitype/" ' +
    'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"/>',
  'docProps/app.xml': XML + '<Properties ' +
    'xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" ' +
    'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>',
  'docProps/custom.xml': XML + '<Properties ' +
    'xmlns="http://schemas.openxmlformats.org/officeDocument/2006/custom-properties" ' +
    'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes"/>',
}));
const odfMeta = (version) => '<?xml version="1.0" encoding="UTF-8"?>\n' +
  '<office:document-meta xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0"' +
  (version ? ` office:version="${version}"` : '') + '><office:meta/></office:document-meta>';

const LOCAL = 0x04034b50;
const CENTRAL = 0x02014b50;
const END = 0x06054b50;
const END64_LOCATOR = 0x07064b50;
// 1980-01-01 00:00:00 in MS-DOS date and time.
const DOS_DATE = (0 << 9) | (1 << 5) | 1;
const DOS_TIME = 0;
const MAX_META_BYTES = 1 << 20;
const MAX_PART_BYTES = 16 << 20;
// Where Word, Excel, PowerPoint and LibreOffice keep pictures, thumbnails
// included.
const PICTURE = /\.(jpe?g|png)$/i;
// Office's copy of the printer's settings, one per document or sheet.
const PRINTER = /^(?:word|xl|ppt)\/printerSettings\/[^/]+\.bin$/i;

// Office parts that name the person out of sight, each with what removes it.
const HIDDEN = [
  [/^word\/_rels\/settings\.xml\.rels$/, withoutLocalPaths],
  [/^xl\/workbook\.xml$/, withoutSavedFolder],
  [/^(?:word\/people|xl\/persons\/[^/]+|ppt\/authors|ppt\/commentAuthors)\.xml$/, withoutAccounts],
];

/** Thrown for anything that is not a plain, readable document archive. */
function unreadable(why) {
  // A password-protected Office file is not a ZIP at all. The person is asked
  // whether to send it as it is, rather than refused or sent unasked.
  return Object.assign(new Error(why), { undecodable: true, prompt: 'scrub.cannotReadDoc' });
}

/** A copy of `file` with its property parts emptied; see above. */
export async function scrubDocument(file, type) {
  const bytes = new Uint8Array(await file.arrayBuffer());
  const entries = readArchive(bytes);
  const names = new Set(entries.map((e) => e.name));
  const odf = entries[0]?.name === 'mimetype';
  if (!odf && !names.has('[Content_Types].xml')) throw unreadable('not an office document');
  // A signature covers the property parts; emptying them would break it.
  if ([...names].some((n) => n.startsWith('_xmlsignatures/') || n === 'META-INF/documentsignatures.xml')) {
    throw Object.assign(new Error('signed'), { undecodable: true, prompt: 'scrub.signedDoc' });
  }

  const out = [];
  const central = [];
  let offset = 0;
  for (const entry of entries) {
    const replacement = await replacementFor(bytes, entry, odf);
    let data;
    let method = entry.method;
    let crc = entry.crc;
    let size = entry.size;
    if (replacement === null) {
      data = bytes.subarray(entry.dataStart, entry.dataStart + entry.compressedSize);
    } else {
      data = typeof replacement === 'string' ? new TextEncoder().encode(replacement) : replacement;
      method = 0;
      crc = crc32(data);
      size = data.length;
    }
    // Only UTF-8 names survive from the flags; a data descriptor is not
    // needed now that the sizes are known up front.
    const flags = entry.flags & 0x0800;
    const fields = {
      versionNeeded: entry.versionNeeded, flags, method, crc,
      compressedSize: data.length, size, name: entry.rawName,
    };
    out.push(localHeader(fields), data);
    central.push(centralHeader(fields, offset));
    offset += 30 + entry.rawName.length + data.length;
  }
  const centralSize = central.reduce((n, c) => n + c.length, 0);
  out.push(...central, endRecord(entries.length, centralSize, offset));
  return new File(out, file.name, { type, lastModified: 0 });
}

/** What a part becomes — a string or bytes — or null to copy it as it is. */
async function replacementFor(bytes, entry, odf) {
  const { name } = entry;
  if (odf) {
    if (name === 'meta.xml') {
      const text = new TextDecoder().decode(await contentOf(bytes, entry, MAX_META_BYTES));
      return odfMeta(/office:version="([0-9.]{1,8})"/.exec(text)?.[1]);
    }
    if (name === 'settings.xml') return rewritten(bytes, entry, withoutOdfPrinter);
  } else {
    if (OOXML_EMPTY.has(name)) return OOXML_EMPTY.get(name);
    const hidden = HIDDEN.find(([pattern]) => pattern.test(name));
    if (hidden) return rewritten(bytes, entry, hidden[1]);
    if (PRINTER.test(name)) return withoutPrinter(await partOf(bytes, entry));
  }
  if (!PICTURE.test(name)) return null;
  const picture = await partOf(bytes, entry);
  if (/\.png$/i.test(name)) return stripPngMeta(picture);
  const blanked = blankJpegMeta(picture);
  const end = jpegEnd(picture);
  if (end > 0 && end < picture.length) return picture.subarray(0, end);
  return blanked ? picture : null;
}

/** An XML part passed through `rewrite`, or null when that changed nothing. */
async function rewritten(bytes, entry, rewrite) {
  let text;
  try {
    // Kept with its byte-order mark, if it had one, so it is written back too.
    text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(await partOf(bytes, entry));
  } catch (err) {
    if (err.undecodable) throw err;
    throw unreadable(`${entry.name} is not UTF-8`);
  }
  const out = rewrite(text);
  return out === text ? null : out;
}

/** A whole part, for one that is rewritten rather than only read. */
function partOf(bytes, entry) {
  if (entry.size > MAX_PART_BYTES) throw unreadable(`${entry.name} is too large`);
  return contentOf(bytes, entry);
}

// An attribute's value, in either quotes; `name` is a regular expression.
const attribute = (name) => new RegExp(`(\\s${name}\\s*=\\s*)(?:"([^"]*)"|'([^']*)')`);
const valueOf = (tag, name) => {
  const m = attribute(name).exec(tag);
  return m ? (m[2] ?? m[3]) : null;
};
const withValue = (tag, name, value) =>
  tag.replace(attribute(name), (_, head) => `${head}"${value.replace(/"/g, '&quot;')}"`);

/**
 * Word's links to files outside the document — the template it was made
 * from, a mail merge's data — point into the author's home folder:
 * file:///C:/Users/alice/AppData/Roaming/Microsoft/Templates/Normal.dotm.
 * Each keeps only its file name. The recipient has no such file either way,
 * and Word goes on without it.
 */
function withoutLocalPaths(xml) {
  return xml.replace(/<Relationship\b[^>]*>/g, (tag) => {
    const target = valueOf(tag, 'Target');
    if (valueOf(tag, 'TargetMode') !== 'External' || target === null) return tag;
    const file = target.split(/[\\/]/).pop();
    return file === target ? tag : withValue(tag, 'Target', file);
  });
}

/** Excel's note of the folder it last saved the workbook in, which it only reads back to show. */
function withoutSavedFolder(xml) {
  return xml
    .replace(/<mc:AlternateContent\b[^>]*>\s*<mc:Choice\b[^>]*>\s*<x15ac:absPath\b[^>]*\/>\s*<\/mc:Choice>\s*<\/mc:AlternateContent>/g, '')
    .replace(/<[\w.-]+:absPath\b[^>]*>/g, (tag) => withValue(tag, 'url', ''));
}

/**
 * Behind each comment author's name, Office keeps the account they were
 * signed in with: a work e-mail with a directory ID, or a Microsoft
 * account's number. Each becomes what Office itself writes for someone not
 * signed in — provider "None", and the name as the ID — so the comments
 * still show who wrote them, and nothing more.
 */
function withoutAccounts(xml) {
  let name = '';
  return xml.replace(/<[A-Za-z_][^>]*>/g, (tag) => {
    // The name is on the same element (Excel, PowerPoint) or the one
    // around it (Word, PowerPoint's older comments).
    name = valueOf(tag, '(?:[\\w.-]+:)?(?:name|displayName|author)') ?? name;
    if (valueOf(tag, '(?:[\\w.-]+:)?userId') === null) return tag;
    const out = withValue(tag, '(?:[\\w.-]+:)?userId', name);
    return valueOf(out, '(?:[\\w.-]+:)?providerId') === null ? out : withValue(out, '(?:[\\w.-]+:)?providerId', 'None');
  });
}

/** LibreOffice's record of the printer: its name, and its settings with the driver's own. */
function withoutOdfPrinter(xml) {
  return xml.replace(/(<config:config-item\b[^>]*\sconfig:name="Printer(?:Name|Setup)"(?:[^>]*[^>/])?>)[^<]+(?=<\/config:config-item>)/g, '$1');
}

/**
 * A printer's settings as Windows keeps them, a DEVMODE: the printer's name
 * — on a company network, the office and floor — and a block of the
 * driver's own, where some keep the user's name or code for job
 * accounting. Both are zeroed; paper, orientation and the rest stay. Null
 * when it does not look like one.
 */
function withoutPrinter(bytes) {
  if (bytes.length < 72) return null;
  const out = bytes.slice();
  const view = new DataView(out.buffer);
  const size = view.getUint16(68, true);
  const driverExtra = view.getUint16(70, true);
  if (size < 148 || size + driverExtra > out.length) return null;
  out.fill(0, 0, 64);
  out.fill(0, size, size + driverExtra);
  return out;
}

/** Entries in the order they lie in the file, checked against its bounds. */
function readArchive(bytes) {
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  let end = -1;
  for (let i = bytes.length - 22; i >= Math.max(0, bytes.length - 22 - 0xffff); i--) {
    if (view.getUint32(i, true) === END) { end = i; break; }
  }
  if (end < 0) throw unreadable('no end of archive');
  if (end >= 20 && view.getUint32(end - 20, true) === END64_LOCATOR) throw unreadable('ZIP64');
  const count = view.getUint16(end + 10, true);
  const centralSize = view.getUint32(end + 12, true);
  const centralStart = view.getUint32(end + 16, true);
  if (view.getUint16(end + 4, true) !== 0 || view.getUint16(end + 6, true) !== 0
      || view.getUint16(end + 8, true) !== count) throw unreadable('split archive');
  if (centralStart + centralSize > end) throw unreadable('directory overruns the archive');

  const entries = [];
  let pos = centralStart;
  for (let i = 0; i < count; i++) {
    if (pos + 46 > centralStart + centralSize || view.getUint32(pos, true) !== CENTRAL) {
      throw unreadable('malformed directory');
    }
    const flags = view.getUint16(pos + 8, true);
    const nameLength = view.getUint16(pos + 28, true);
    const extraLength = view.getUint16(pos + 30, true);
    const commentLength = view.getUint16(pos + 32, true);
    const localStart = view.getUint32(pos + 42, true);
    const compressedSize = view.getUint32(pos + 20, true);
    if (pos + 46 + nameLength + extraLength + commentLength > centralStart + centralSize) {
      throw unreadable('malformed directory');
    }
    if (flags & 0x0001) throw unreadable('encrypted entry');
    const rawName = bytes.slice(pos + 46, pos + 46 + nameLength);
    if (localStart + 30 > centralStart || view.getUint32(localStart, true) !== LOCAL) {
      throw unreadable('malformed entry');
    }
    const dataStart = localStart + 30 + view.getUint16(localStart + 26, true)
      + view.getUint16(localStart + 28, true);
    if (dataStart + compressedSize > centralStart) throw unreadable('entry overruns the archive');
    entries.push({
      versionNeeded: view.getUint16(pos + 6, true),
      flags,
      method: view.getUint16(pos + 10, true),
      crc: view.getUint32(pos + 16, true),
      compressedSize,
      size: view.getUint32(pos + 24, true),
      rawName,
      name: new TextDecoder().decode(rawName),
      localStart,
      dataStart,
    });
    pos += 46 + nameLength + extraLength + commentLength;
  }
  entries.sort((a, b) => a.localStart - b.localStart);
  for (let i = 1; i < entries.length; i++) {
    const prev = entries[i - 1];
    if (prev.dataStart + prev.compressedSize > entries[i].localStart) throw unreadable('overlapping entries');
  }
  return entries;
}

/**
 * A part's uncompressed bytes, as a copy of its own. With `cap`, reading
 * stops there; without, a part that inflates past the size the directory
 * gave it is refused rather than let fill memory.
 */
async function contentOf(bytes, entry, cap = 0) {
  const raw = bytes.subarray(entry.dataStart, entry.dataStart + entry.compressedSize);
  if (entry.method === 0) return raw.slice(0, cap || raw.length);
  if (entry.method !== 8 || typeof DecompressionStream !== 'function') throw unreadable(`cannot read ${entry.name}`);
  const limit = cap || entry.size;
  const reader = new Blob([raw]).stream().pipeThrough(new DecompressionStream('deflate-raw')).getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.length;
      if (total > limit) {
        if (!cap) throw new Error('larger than declared');
        break;
      }
      chunks.push(value);
    }
  } catch {
    throw unreadable(`cannot read ${entry.name}`);
  } finally {
    reader.cancel().catch(() => {});
  }
  return new Uint8Array(await new Blob(chunks).arrayBuffer()).slice(0, limit);
}

function localHeader({ versionNeeded, flags, method, crc, compressedSize, size, name }) {
  const h = new DataView(new ArrayBuffer(30 + name.length));
  h.setUint32(0, LOCAL, true);
  h.setUint16(4, versionNeeded, true);
  h.setUint16(6, flags, true);
  h.setUint16(8, method, true);
  h.setUint16(10, DOS_TIME, true);
  h.setUint16(12, DOS_DATE, true);
  h.setUint32(14, crc, true);
  h.setUint32(18, compressedSize, true);
  h.setUint32(22, size, true);
  h.setUint16(26, name.length, true);
  h.setUint16(28, 0, true);
  new Uint8Array(h.buffer).set(name, 30);
  return new Uint8Array(h.buffer);
}

function centralHeader({ versionNeeded, flags, method, crc, compressedSize, size, name }, offset) {
  const h = new DataView(new ArrayBuffer(46 + name.length));
  h.setUint32(0, CENTRAL, true);
  // Made by: version 2.0, MS-DOS — the host says nothing about the sender's.
  h.setUint16(4, 20, true);
  h.setUint16(6, versionNeeded, true);
  h.setUint16(8, flags, true);
  h.setUint16(10, method, true);
  h.setUint16(12, DOS_TIME, true);
  h.setUint16(14, DOS_DATE, true);
  h.setUint32(16, crc, true);
  h.setUint32(20, compressedSize, true);
  h.setUint32(24, size, true);
  h.setUint16(28, name.length, true);
  // Extra, comment, disk, internal and external attributes: all zero.
  h.setUint32(42, offset, true);
  new Uint8Array(h.buffer).set(name, 46);
  return new Uint8Array(h.buffer);
}

function endRecord(count, centralSize, centralStart) {
  const h = new DataView(new ArrayBuffer(22));
  h.setUint32(0, END, true);
  h.setUint16(8, count, true);
  h.setUint16(10, count, true);
  h.setUint32(12, centralSize, true);
  h.setUint32(16, centralStart, true);
  return new Uint8Array(h.buffer);
}

let CRC_TABLE;
function crc32(bytes) {
  if (!CRC_TABLE) {
    CRC_TABLE = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
      CRC_TABLE[n] = c >>> 0;
    }
  }
  let crc = 0xffffffff;
  for (const byte of bytes) crc = CRC_TABLE[(crc ^ byte) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}
