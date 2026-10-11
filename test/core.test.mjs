// Parity tests: the browser algorithms in docs/assets/core.js must agree with the Python toolkit.
// Run: node --test test/
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import * as core from '../docs/assets/core.js';

const root = fileURLToPath(new URL('../', import.meta.url));
const docs = join(root, 'docs');
const bundle = JSON.parse(readFileSync(join(docs, 'data/bundle.json'), 'utf8'));
const file = (p) => new Uint8Array(readFileSync(join(docs, 'labs/case-01', p)));

function python(code) {
  const r = spawnSync('python3', ['-c', code], { cwd: root, encoding: 'utf8' });
  assert.equal(r.status, 0, r.stderr);
  return JSON.parse(r.stdout);
}

const SAMPLES = ['evidence/Documents/invoice_0921.jpg', 'evidence/Pictures/IMG_2038.jpg', 'evidence/Documents/Tender_2026_Final.pdf',
  'evidence/Recent/Tender_Update.lnk', 'evidence/Network/capture.pcap', 'carved/deleted_photo.jpg'];

test('hashes match hashlib', async () => {
  const py = python(`import json,hashlib
paths=${JSON.stringify(SAMPLES)}
print(json.dumps({p:{a:hashlib.new(a,open('docs/labs/case-01/'+p,'rb').read()).hexdigest() for a in ('md5','sha1','sha256')} for p in paths}))`);
  for (const p of SAMPLES) assert.deepEqual(await core.hashAll(file(p)), py[p], p);
  assert.equal(core.md5(new Uint8Array()), 'd41d8cd98f00b204e9800998ecf8427e');
});

test('signature verdicts match qassas.signatures', () => {
  const sigs = core.prepareSignatures(bundle.signatures);
  const py = python(`import json
from qassas import signatures
paths=${JSON.stringify(SAMPLES)}
print(json.dumps({p:signatures.identify('docs/labs/case-01/'+p) for p in paths}))`);
  for (const p of SAMPLES) {
    const v = core.identify(sigs, file(p), p.split('/').pop());
    assert.equal(v.detected, py[p].detected, p);
    assert.equal(v.status, py[p].status, p);
  }
});

test('EXIF and the nearest area match qassas.metadata', () => {
  const py = python(`import json
from qassas import metadata
print(json.dumps(metadata.extract('docs/labs/case-01/carved/deleted_photo.jpg')))`);
  const m = core.readExif(file('carved/deleted_photo.jpg'));
  assert.equal(m.datetime_original, py.datetime_original);
  assert.equal(m.offset_time_original, py.offset_time_original);
  assert.deepEqual([m.gps.lat, m.gps.lon], [py.gps.lat, py.gps.lon]);
  assert.equal(core.nearestAreas(bundle.areas, m.gps.lat, m.gps.lon)[0].name.en, py.gps.nearest_area.en);
  assert.equal(core.exifToUtc(m.datetime_original, m.offset_time_original).utc, '2026-10-03T16:12:40Z');
});

test('custody hashes match Python byte for byte', async () => {
  const log = readFileSync(join(docs, 'labs/case-01/custody/custody.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  for (const e of log) assert.equal(await core.entryHash(e), e.hash, `entry ${e.seq}`);
  assert.deepEqual(await core.verifyCustody(log), []);
  const archived = readFileSync(join(docs, 'labs/case-01/custody/custody_archive_copy.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
  assert.deepEqual((await core.verifyCustody(archived)).map((p) => [p.seq, p.code]), [[5, 'entry_altered']]);
  const arabic = { ...log[0], note: 'خُتم الكيس رقم QS-B-0041 "مرة" \\ أخرى' };
  const py = python(`import json,sys
from qassas import custody
e=json.loads(${JSON.stringify(JSON.stringify(arabic))})
print(json.dumps(custody.entry_hash(e)))`);
  assert.equal(await core.entryHash(arabic), py);
});

test('answer normalisation and hashes match qassas.lab', async () => {
  const inputs = ['  السَّالمِيّة ', 'Salmiya.', 'C:\\Users\\fahad\\Downloads\\Tender_Update\\update.exe', 'إجابة  آخرة', '"09:27"'];
  const py = python(`import json
from qassas import lab
xs=${JSON.stringify(inputs)}
print(json.dumps([[lab.normalise(x), lab.answer_hash('q03', x)] for x in xs]))`);
  for (let i = 0; i < inputs.length; i++) {
    assert.equal(core.normaliseAnswer(inputs[i]), py[i][0], inputs[i]);
    assert.equal(await core.answerHash('case-01', 'q03', inputs[i]), py[i][1], inputs[i]);
  }
});

test('bit difference counts', () => {
  assert.equal(core.bitDiff('00', 'ff'), 8);
  assert.equal(core.bitDiff('a0', 'a0'), 0);
});

test('time zones', () => {
  assert.equal(core.toZone('2026-10-04T05:42:09+00:00', 'kuwait'), '2026-10-04 08:42:09 +03');
  assert.equal(core.toZone('2026-10-04T05:42:09+00:00', 'utc'), '2026-10-04 05:42:09 UTC');
});
