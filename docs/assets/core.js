// Qassas core: the algorithms behind the in-browser labs.
// Pure functions with no DOM access, shared by the site and the Node tests,
// and kept byte compatible with the Python toolkit so both give the same answers.

const enc = new TextEncoder();

// ---------------------------------------------------------------- hashing

const subtle = globalThis.crypto && globalThis.crypto.subtle;

export async function sha(algo, bytes) {
  const buf = await subtle.digest(algo, bytes);
  return hex(new Uint8Array(buf));
}

export function hex(bytes, sep = '') {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += (i && sep ? sep : '') + bytes[i].toString(16).padStart(2, '0');
  return s;
}

// MD5 is not in Web Crypto. A compact RFC 1321 implementation, for comparison with
// older reports only: MD5 collisions are practical, so evidence also records SHA-256.
const MD5_S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
const MD5_K = Array.from({ length: 64 }, (_, i) => Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0);

export function md5(bytes) {
  const len = bytes.length;
  const padded = new Uint8Array(((len + 72) >>> 6) << 6);
  padded.set(bytes);
  padded[len] = 0x80;
  const bits = len * 8;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, bits >>> 0, true);
  view.setUint32(padded.length - 4, Math.floor(bits / 2 ** 32), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  const m = new Uint32Array(16);
  for (let off = 0; off < padded.length; off += 64) {
    for (let j = 0; j < 16; j++) m[j] = view.getUint32(off + j * 4, true);
    let a = a0, b = b0, c = c0, d = d0;
    for (let i = 0; i < 64; i++) {
      let f, g;
      if (i < 16) { f = (b & c) | (~b & d); g = i; }
      else if (i < 32) { f = (d & b) | (~d & c); g = (5 * i + 1) % 16; }
      else if (i < 48) { f = b ^ c ^ d; g = (3 * i + 5) % 16; }
      else { f = c ^ (b | ~d); g = (7 * i) % 16; }
      const tmp = d;
      d = c;
      c = b;
      const x = (a + f + MD5_K[i] + m[g]) >>> 0;
      const s = MD5_S[(i >>> 4) * 4 + (i % 4)];
      b = (b + ((x << s) | (x >>> (32 - s)))) >>> 0;
      a = tmp;
    }
    a0 = (a0 + a) >>> 0; b0 = (b0 + b) >>> 0; c0 = (c0 + c) >>> 0; d0 = (d0 + d) >>> 0;
  }
  const out = new Uint8Array(16);
  const ov = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((w, i) => ov.setUint32(i * 4, w, true));
  return hex(out);
}

export async function hashAll(bytes) {
  return { md5: md5(bytes), sha1: await sha('SHA-1', bytes), sha256: await sha('SHA-256', bytes) };
}

// Bits that differ between two hex digests of equal length.
export function bitDiff(h1, h2) {
  let n = 0;
  for (let i = 0; i < h1.length; i++) {
    let x = parseInt(h1[i], 16) ^ parseInt(h2[i], 16);
    while (x) { n += x & 1; x >>= 1; }
  }
  return n;
}

// ---------------------------------------------------------------- signatures

function hexBytes(h) {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.substr(i * 2, 2), 16);
  return out;
}

function startsAt(data, offset, magic) {
  if (data.length < offset + magic.length) return false;
  for (let i = 0; i < magic.length; i++) if (data[offset + i] !== magic[i]) return false;
  return true;
}

function containsAscii(data, text) {
  const t = enc.encode(text);
  outer: for (let i = 0; i + t.length <= data.length; i++) {
    for (let j = 0; j < t.length; j++) if (data[i + j] !== t[j]) continue outer;
    return true;
  }
  return false;
}

export function prepareSignatures(list) {
  const sigs = list.map((s) => ({ ...s, magic: hexBytes(s.hex), alsoMagic: s.also ? hexBytes(s.also.hex) : null }));
  sigs.sort((a, b) => {
    const wa = a.magic.length + (a.also || a.zip_member ? 8 : 0);
    const wb = b.magic.length + (b.also || b.zip_member ? 8 : 0);
    return wb - wa || (a.id < b.id ? -1 : 1);
  });
  return sigs;
}

// Same verdict as qassas.signatures: detected type, expected extensions and match status.
export function identify(sigs, data, name) {
  let found = null;
  for (const s of sigs) {
    if (!startsAt(data, s.offset, s.magic)) continue;
    if (s.alsoMagic && !startsAt(data, s.also.offset, s.alsoMagic)) continue;
    if (s.zip_member && !containsAscii(data, s.zip_member)) continue;
    found = s;
    break;
  }
  const dot = name.lastIndexOf('.');
  const ext = dot > 0 ? name.slice(dot + 1).toLowerCase() : '';
  let status = 'unknown';
  if (found) status = found.ext.includes(ext) ? 'match' : 'mismatch';
  return {
    detected: found ? found.id : null,
    description: found ? found.name : null,
    expected: found ? found.ext : [],
    magicLength: found ? found.magic.length : 0,
    magicOffset: found ? found.offset : 0,
    extension: ext,
    status,
  };
}

// ---------------------------------------------------------------- EXIF

const TIFF_SIZE = { 1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8 };

function readIfd(view, start, offset, le) {
  const out = {};
  const count = view.getUint16(start + offset, le);
  for (let k = 0; k < count; k++) {
    const p = start + offset + 2 + 12 * k;
    const tag = view.getUint16(p, le);
    const type = view.getUint16(p + 2, le);
    const n = view.getUint32(p + 4, le);
    const size = (TIFF_SIZE[type] || 1) * n;
    const at = size <= 4 ? p + 8 : start + view.getUint32(p + 8, le);
    let val;
    if (type === 2) {
      let s = '';
      for (let i = 0; i < n; i++) { const c = view.getUint8(at + i); if (c) s += String.fromCharCode(c); }
      val = s.trim();
    } else if (type === 3) {
      val = Array.from({ length: n }, (_, i) => view.getUint16(at + 2 * i, le));
    } else if (type === 4) {
      val = Array.from({ length: n }, (_, i) => view.getUint32(at + 4 * i, le));
    } else if (type === 5 || type === 10) {
      val = Array.from({ length: n }, (_, i) => {
        const a = type === 5 ? view.getUint32(at + 8 * i, le) : view.getInt32(at + 8 * i, le);
        const b = type === 5 ? view.getUint32(at + 8 * i + 4, le) : view.getInt32(at + 8 * i + 4, le);
        return b ? a / b : 0;
      });
    } else {
      val = Array.from({ length: Math.min(n, 64) }, (_, i) => view.getUint8(at + i));
    }
    out[tag] = Array.isArray(val) && val.length === 1 ? val[0] : val;
  }
  return out;
}

function dms(v, ref) {
  if (!Array.isArray(v) || v.length !== 3) return null;
  const d = v[0] + v[1] / 60 + v[2] / 3600;
  return Math.round((ref === 'S' || ref === 'W' ? -d : d) * 1e6) / 1e6;
}

export function readExif(data) {
  if (data[0] !== 0xff || data[1] !== 0xd8) return null;
  const view = new DataView(data.buffer, data.byteOffset, data.byteLength);
  let i = 2;
  while (i + 4 <= data.length && data[i] === 0xff) {
    const marker = data[i + 1];
    const len = view.getUint16(i + 2, false);
    if (marker === 0xe1 && startsAt(data, i + 4, enc.encode('Exif\0\0'))) {
      const start = i + 10;
      const le = data[start] === 0x49;
      const ifd0 = readIfd(view, start, view.getUint32(start + 4, le), le);
      const out = { make: ifd0[0x010f], model: ifd0[0x0110], software: ifd0[0x0131], datetime: ifd0[0x0132] };
      if (ifd0[0x8769]) {
        const ex = readIfd(view, start, ifd0[0x8769], le);
        out.datetime_original = ex[0x9003];
        out.offset_time_original = ex[0x9011];
      }
      if (ifd0[0x8825]) {
        const g = readIfd(view, start, ifd0[0x8825], le);
        const lat = dms(g[2], g[1]);
        const lon = dms(g[4], g[3]);
        if (lat !== null && lon !== null) out.gps = { lat, lon };
      }
      for (const k of Object.keys(out)) if (out[k] === undefined) delete out[k];
      return out;
    }
    if (marker === 0xda) break;
    i += 2 + len;
  }
  return {};
}

export function exifToUtc(text, offset) {
  const m = /^(\d{4}):(\d\d):(\d\d) (\d\d):(\d\d):(\d\d)$/.exec(text || '');
  if (!m) return null;
  const off = /^([+-])(\d\d):(\d\d)$/.exec(offset || '');
  const sign = off ? (off[1] === '+' ? 1 : -1) : 0;
  const mins = off ? sign * (Number(off[2]) * 60 + Number(off[3])) : 0;
  const t = Date.UTC(+m[1], +m[2] - 1, +m[3], +m[4], +m[5], +m[6]) - mins * 60000;
  return { utc: new Date(t).toISOString().replace('.000Z', 'Z'), assumed: !off };
}

export function distanceKm(lat1, lon1, lat2, lon2) {
  const r = 6371;
  const rad = Math.PI / 180;
  const dp = (lat2 - lat1) * rad;
  const dl = (lon2 - lon1) * rad;
  const a = Math.sin(dp / 2) ** 2 + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dl / 2) ** 2;
  return 2 * r * Math.asin(Math.sqrt(a));
}

export function nearestAreas(areas, lat, lon, n = 3) {
  return areas
    .map((a) => ({ ...a, km: Math.round(distanceKm(lat, lon, a.lat, a.lon) * 100) / 100 }))
    .sort((x, y) => x.km - y.km)
    .slice(0, n);
}

// ---------------------------------------------------------------- custody

const CUSTODY_FIELDS = ['seq', 'time_utc', 'action', 'item', 'by', 'to', 'location', 'note', 'item_sha256', 'prev'];
export const GENESIS = '0'.repeat(64);

// Mirrors Python json.dumps(sort_keys=True, separators=(',', ':'), ensure_ascii=False).
export function canonical(entry) {
  const body = {};
  for (const k of [...CUSTODY_FIELDS].sort()) body[k] = entry[k] === undefined ? null : entry[k];
  return JSON.stringify(body);
}

export async function entryHash(entry) {
  return sha('SHA-256', enc.encode(canonical(entry)));
}

export async function verifyCustody(entries) {
  const problems = [];
  let prev = GENESIS;
  let prevTime = null;
  const firstHash = {};
  for (let i = 0; i < entries.length; i++) {
    const e = entries[i];
    if (e.seq !== i + 1) problems.push({ seq: e.seq, code: 'sequence' });
    if (e.prev !== prev) problems.push({ seq: e.seq, code: 'broken_link' });
    const actual = await entryHash(e);
    if (e.hash !== actual) problems.push({ seq: e.seq, code: 'entry_altered', expected: e.hash, actual });
    const t = Date.parse(e.time_utc);
    if (Number.isNaN(t)) problems.push({ seq: e.seq, code: 'bad_time' });
    else {
      if (prevTime !== null && t < prevTime) problems.push({ seq: e.seq, code: 'time_reversed' });
      prevTime = t;
    }
    if (e.item_sha256) {
      if (firstHash[e.item] && firstHash[e.item] !== e.item_sha256) problems.push({ seq: e.seq, code: 'item_hash_changed' });
      if (!firstHash[e.item]) firstHash[e.item] = e.item_sha256;
    }
    prev = e.hash;
  }
  return problems;
}

// ---------------------------------------------------------------- answers

const HARAKAT = /[ً-ْ]/g;

// Mirrors qassas.lab.normalise so a browser check equals a command line check.
export function normaliseAnswer(text) {
  let t = String(text).normalize('NFKC').trim().toLowerCase().replace(HARAKAT, '');
  t = t.replace(/[أإآ]/g, 'ا').replace(/ة/g, 'ه').replace(/\\/g, '/').replace(/["']/g, '');
  t = t.split(/\s+/).filter(Boolean).join(' ');
  return t.replace(/\.+$/, '');
}

export async function answerHash(caseId, qid, text) {
  return sha('SHA-256', enc.encode(`qassas:${caseId}:${qid}:${normaliseAnswer(text)}`));
}

// ---------------------------------------------------------------- time

export function toZone(isoUtc, zone) {
  const t = Date.parse(isoUtc);
  if (zone === 'utc') return new Date(t).toISOString().slice(0, 19).replace('T', ' ') + ' UTC';
  return new Date(t + 3 * 3600000).toISOString().slice(0, 19).replace('T', ' ') + ' +03';
}
