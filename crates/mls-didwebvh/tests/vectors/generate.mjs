// Generates the did_webvh interop vectors for
// draft-atwood-mls-didwebvh-credential-00, independently of mimid's Rust
// code: its own JCS (RFC 8785), base58btc, multihash, did:webvh v1.0 entry
// construction (spec-v1.0 at decentralized-identity/didwebvh 91f3cba) and
// eddsa-jcs-2022 proofs, using only Node's built-in crypto.
//
// Every expected outcome is written down here from the draft's text, with
// the section it comes from, not computed by a verifier.
//
// Usage: node generate.mjs   (writes vectors.json beside this file)
// Deterministic: keys are derived from fixed names, times are fixed.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OUT = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------- JCS
// RFC 8785: ES6 serialization of primitives, object members sorted by
// UTF-16 code units (JavaScript's default string order), no whitespace.
function jcs(value) {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(jcs).join(',') + ']';
  const keys = Object.keys(value).sort();
  return '{' + keys.map((k) => JSON.stringify(k) + ':' + jcs(value[k])).join(',') + '}';
}

// ---------------------------------------------------------------- base58btc
const B58 = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
function b58(bytes) {
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let s = '';
  while (n > 0n) {
    s = B58[Number(n % 58n)] + s;
    n /= 58n;
  }
  for (const b of bytes) {
    if (b !== 0) break;
    s = '1' + s;
  }
  return s;
}

const sha256 = (data) => crypto.createHash('sha256').update(data).digest();
// base58btc(multihash(SHA-256(text)))
const multihash = (text) => b58(Buffer.concat([Buffer.from([0x12, 0x20]), sha256(Buffer.from(text, 'utf8'))]));

// ---------------------------------------------------------------- keys
const PKCS8_ED25519 = Buffer.from('302e020100300506032b657004220420', 'hex');
const keys = {};
function key(name) {
  if (keys[name]) return keys[name];
  const seed = sha256(Buffer.from('mimid-didwebvh-vector:' + name, 'utf8'));
  const priv = crypto.createPrivateKey({ key: Buffer.concat([PKCS8_ED25519, seed]), format: 'der', type: 'pkcs8' });
  const pub = crypto.createPublicKey(priv).export({ format: 'der', type: 'spki' }).subarray(-32);
  const mk = 'z' + b58(Buffer.concat([Buffer.from([0xed, 0x01]), pub]));
  keys[name] = { name, seed, pub, mk, priv };
  return keys[name];
}
const hex = (b) => Buffer.from(b).toString('hex');

// eddsa-jcs-2022 Data Integrity proof over `doc`, by `k`.
function proof(k, doc, created, { corrupt = false } = {}) {
  const config = {
    type: 'DataIntegrityProof',
    cryptosuite: 'eddsa-jcs-2022',
    verificationMethod: `did:key:${k.mk}#${k.mk}`,
    created,
    proofPurpose: 'assertionMethod',
  };
  const hashData = Buffer.concat([sha256(jcs(config)), sha256(jcs(doc))]);
  const sig = crypto.sign(null, hashData, k.priv);
  if (corrupt) sig[0] ^= 1;
  return { ...config, proofValue: 'z' + b58(sig) };
}

// Pre-rotation commitment: base58btc(multihash(multikey)).
const keyHash = (k) => multihash(k.mk);

// ---------------------------------------------------------------- DID documents
// A document listing `devices` (key names) as authorized keys: each a
// Multikey verification method referenced from `authentication`.
function document(did, devices, extra = {}) {
  return {
    '@context': ['https://www.w3.org/ns/did/v1.1'],
    id: did,
    verificationMethod: devices.map((d) => ({
      id: `${did}#${d}`,
      type: 'Multikey',
      controller: did,
      publicKeyMultibase: key(d).mk,
    })),
    authentication: devices.map((d) => `#${d}`),
    ...extra,
  };
}

// ---------------------------------------------------------------- logs
// A did:webvh v1.0 log under construction. `lines` are the exact JSONL
// lines; `entries` the parsed objects.
class Log {
  constructor() {
    this.entries = [];
    this.lines = [];
  }
  get scid() {
    return this.entries[0].parameters.scid;
  }
  get head() {
    return this.entries[this.entries.length - 1];
  }
  get did() {
    return this.head.state.id;
  }
  clone() {
    const l = new Log();
    l.entries = this.entries.map((e) => JSON.parse(JSON.stringify(e)));
    l.lines = [...this.lines];
    return l;
  }
  text() {
    return this.lines.map((l) => l + '\n').join('');
  }

  // Create (Register): genesis entry for `path` under example.com.
  static create({ path: didPath, time, params, devices, signer, docExtra, domain = 'example.com' }) {
    const did = `did:webvh:{SCID}:${domain}:${didPath}`;
    const prelim = {
      versionId: '{SCID}',
      versionTime: time,
      parameters: { method: 'did:webvh:1.0', scid: '{SCID}', ...params },
      state: document(did, devices, docExtra),
    };
    const scid = multihash(jcs(prelim));
    const entry = JSON.parse(JSON.stringify(prelim).replaceAll('{SCID}', scid));
    entry.versionId = scid;
    entry.versionId = `1-${multihash(jcs(entry))}`;
    const log = new Log();
    log.push(entry, signer, time);
    return log;
  }

  // Update (Rotate): the next entry, with `params` and a document listing
  // `devices` (or `state` given whole), signed by `signer`.
  update({ time, params = {}, devices, state, signer, docExtra, versionId, proofs }) {
    const n = this.entries.length + 1;
    const entry = {
      versionId: this.head.versionId,
      versionTime: time,
      parameters: params,
      state: state ?? document(this.did, devices, docExtra),
    };
    const hash = multihash(jcs(entry));
    entry.versionId = versionId ? versionId(n, hash) : `${n}-${hash}`;
    const log = this.clone();
    log.push(entry, signer, time, proofs);
    return log;
  }

  push(entry, signer, time, proofs) {
    entry.proof = proofs ? proofs(entry) : [proof(signer, entry, time)];
    this.entries.push(entry);
    this.lines.push(JSON.stringify(entry));
  }
}

// Witness file: for each versionId, proofs by the named witnesses.
function witnessFile(items) {
  return JSON.stringify(
    items.map(({ versionId, by, corrupt = [] }) => ({
      versionId,
      proof: by.map((w) => proof(key(w), { versionId }, '2026-11-01T00:00:30Z', { corrupt: corrupt.includes(w) })),
    })),
  );
}

// ---------------------------------------------------------------- TLS
// RFC 9420 §2.1.2 variable-length vector.
function vector(bytes) {
  const n = bytes.length;
  let prefix;
  if (n < 1 << 6) prefix = [n];
  else if (n < 1 << 14) prefix = [0x40 | (n >> 8), n & 0xff];
  else prefix = [0x80 | (n >>> 24), (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff];
  return Buffer.concat([Buffer.from(prefix), Buffer.from(bytes)]);
}
// struct { opaque did_log<V>; opaque witness_file<V>; } DIDWebVHCredential
const credentialTls = (log, wf) => Buffer.concat([vector(Buffer.from(log, 'utf8')), vector(Buffer.from(wf, 'utf8'))]);
// DIDWebVHHeads, entries sorted by scid bytes, keys sorted by bytes.
function headsTls(heads) {
  const sorted = [...heads].sort((a, b) => Buffer.compare(Buffer.from(a.scid), Buffer.from(b.scid)));
  const body = Buffer.concat(
    sorted.map((h) =>
      Buffer.concat([
        vector(Buffer.from(h.scid, 'ascii')),
        vector(Buffer.from(h.version_id, 'ascii')),
        vector(Buffer.concat([...h.authorized_keys].sort().map((k) => vector(Buffer.from(k, 'hex'))))),
      ]),
    ),
  );
  return vector(body);
}

// ---------------------------------------------------------------- scenario: alice
// Alice's controller holds update keys u1, u2, u3 ... and an offline
// recovery key r. Every entry commits to the next update key and to r
// (draft §Custody of Update Keys). Devices d1, d2, d3 hold MLS keys.
const T = (s) => `2026-11-01T00:00:${String(s).padStart(2, '0')}Z`;
const preRotation = (next) => ({ updateKeys: [key(next[0]).mk], nextKeyHashes: next.slice(1).map((n) => keyHash(key(n))) });

const aliceV1 = Log.create({
  path: 'alice',
  time: T(1),
  params: { updateKeys: [key('alice-u1').mk], nextKeyHashes: [keyHash(key('alice-u2')), keyHash(key('alice-r'))], portable: false },
  devices: ['alice-d1'],
  signer: key('alice-u1'),
});
// v2 adds d2, signed by u2 (committed in v1).
const aliceV2 = aliceV1.update({
  time: T(2),
  params: preRotation(['alice-u2', 'alice-u3', 'alice-r']),
  devices: ['alice-d1', 'alice-d2'],
  signer: key('alice-u2'),
});
// v3 revokes d2, signed by u3.
const aliceV3 = aliceV2.update({
  time: T(3),
  params: preRotation(['alice-u3', 'alice-u4', 'alice-r']),
  devices: ['alice-d1'],
  signer: key('alice-u3'),
});
// v3b: a fork of v2 by the recovery key r (committed in v2), adding d3.
const aliceV3b = aliceV2.update({
  time: T(4),
  params: preRotation(['alice-r', 'alice-u5', 'alice-r2']),
  devices: ['alice-d1', 'alice-d2', 'alice-d3'],
  signer: key('alice-r'),
});
// v4b extends the fork.
const aliceV4b = aliceV3b.update({
  time: T(5),
  params: preRotation(['alice-u5', 'alice-u6', 'alice-r2']),
  devices: ['alice-d3'],
  signer: key('alice-u5'),
});

// ---------------------------------------------------------------- scenario: bob (no pre-rotation)
const bobV1 = Log.create({
  path: 'bob',
  time: T(10),
  params: { updateKeys: [key('bob-u1').mk] },
  devices: ['bob-d1'],
  signer: key('bob-u1'),
});
const bobV2 = bobV1.update({ time: T(11), devices: ['bob-d1', 'bob-d2'], signer: key('bob-u1') });

// ---------------------------------------------------------------- scenario: carol (witnesses)
const witnessParam = {
  threshold: 2,
  witnesses: ['carol-w1', 'carol-w2', 'carol-w3'].map((w) => ({ id: `did:key:${key(w).mk}` })),
};
const carolV1 = Log.create({
  path: 'carol',
  time: T(20),
  params: { updateKeys: [key('carol-u1').mk], witness: witnessParam },
  devices: ['carol-d1'],
  signer: key('carol-u1'),
});
const carolVid = carolV1.head.versionId;

// ---------------------------------------------------------------- log vectors
const logs = [];
function addLog(name, log, { witness = '', valid, reason, keys: authorized = [], note, text }) {
  const didLog = text ?? log.text();
  logs.push({
    name,
    note,
    did_log: didLog,
    witness_file: witness,
    credential_tls: hex(credentialTls(didLog, witness)),
    valid,
    ...(valid
      ? {
          scid: log.scid,
          did: log.did,
          version_ids: log.entries.map((e) => e.versionId),
          authorized_keys: authorized.map((k) => hex(key(k).pub)).sort(),
        }
      : { reason }),
  });
}

// Valid logs.
addLog('alice-v1', aliceV1, { valid: true, keys: ['alice-d1'], note: 'genesis with pre-rotation committing to u2 and the recovery key' });
addLog('alice-v2', aliceV2, { valid: true, keys: ['alice-d1', 'alice-d2'], note: 'adds device d2, signed by a pre-rotated key' });
addLog('alice-v3', aliceV3, { valid: true, keys: ['alice-d1'], note: 'revokes device d2' });
addLog('alice-v3b', aliceV3b, { valid: true, keys: ['alice-d1', 'alice-d2', 'alice-d3'], note: 'a fork of alice-v2 by the recovery key; valid on its own' });
addLog('alice-v4b', aliceV4b, { valid: true, keys: ['alice-d3'], note: 'extends the alice-v3b fork' });
addLog('bob-v1', bobV1, { valid: true, keys: ['bob-d1'], note: 'no pre-rotation' });
addLog('bob-v2', bobV2, { valid: true, keys: ['bob-d1', 'bob-d2'], note: 'signed by the previous entry\'s update key' });
addLog('carol-v1-witnessed', carolV1, {
  witness: witnessFile([{ versionId: carolVid, by: ['carol-w1', 'carol-w2'] }]),
  valid: true,
  keys: ['carol-d1'],
  note: 'threshold 2 of 3 met',
});
addLog('carol-v1-bad-proof-ignored', carolV1, {
  witness: witnessFile([{ versionId: carolVid, by: ['carol-w1', 'carol-w2', 'carol-w3'], corrupt: ['carol-w3'] }]),
  valid: true,
  keys: ['carol-d1'],
  note: '§did:webvh Profile, Witnesses: "A witness proof that fails verification is ignored"',
});
addLog('carol-v1-extra-version-ignored', carolV1, {
  witness: witnessFile([
    { versionId: carolVid, by: ['carol-w1', 'carol-w2'] },
    { versionId: '2-QmNotInTheLogNotInTheLogNotInTheLogNotInTheLo', by: ['carol-w3'] },
  ]),
  valid: true,
  keys: ['carol-d1'],
  note: '§Log Verification item 4: "Proofs in witness_file for versionIds not in did_log are ignored"',
});
{
  const future = Log.create({
    path: 'future',
    time: '2099-01-01T00:00:00Z',
    params: { updateKeys: [key('future-u1').mk] },
    devices: ['future-d1'],
    signer: key('future-u1'),
  });
  addLog('future-version-time', future, {
    valid: true,
    keys: ['future-d1'],
    note: '§Log Verification item 3: "The verifier MUST NOT compare versionTime with its own clock"',
  });
}
{
  // Authorized keys: embedded and referenced methods, absolute and
  // relative references; and methods that must authorize nothing.
  const did = 'did:webvh:{SCID}:example.com:dave';
  const vm = (id, k, extra = {}) => ({ id, type: 'Multikey', controller: did, publicKeyMultibase: key(k).mk, ...extra });
  const docExtra = {
    verificationMethod: [
      vm(`${did}#a`, 'dave-a'),
      vm('#b', 'dave-b'),
      vm('#wrong-controller', 'dave-x1', { controller: 'did:example:someone-else' }),
      vm('#wrong-type', 'dave-x2', { type: 'Ed25519VerificationKey2020' }),
      vm('#not-in-authentication', 'dave-x3'),
    ],
    authentication: [
      '#a',
      `${did}#b`,
      vm('#c', 'dave-c'),
      '#wrong-controller',
      '#wrong-type',
      '#missing',
      'a',
      { id: '#bad-multikey', type: 'Multikey', controller: did, publicKeyMultibase: 'z' + b58(Buffer.concat([Buffer.from([0xe7, 0x01]), key('dave-x4').pub])) },
    ],
    assertionMethod: ['#not-in-authentication'],
  };
  const dave = Log.create({ path: 'dave', time: T(30), params: { updateKeys: [key('dave-u1').mk] }, devices: [], docExtra, signer: key('dave-u1') });
  addLog('dave-authorized-keys', dave, {
    valid: true,
    keys: ['dave-a', 'dave-b', 'dave-c'],
    note: '§Conventions, "Authorized key": wrong controller, wrong type, unreferenced, unresolved, non-fragment relative and non-Ed25519 methods authorize nothing and do not invalidate the document',
  });
}

// Invalid logs: the did:webvh v1.0 rules.
const reject = (name, log, reason, opts = {}) => addLog(name, log, { valid: false, reason, ...opts });
{
  const tampered = aliceV2.clone();
  const entry = JSON.parse(tampered.lines[1]);
  entry.state.authentication.push('#alice-d1');
  tampered.lines[1] = JSON.stringify(entry);
  reject('tampered-entry', tampered, 'webvh', { note: 'state changed after signing: entryHash no longer matches' });
}
reject(
  'wrong-signer',
  aliceV1.update({ time: T(2), params: preRotation(['alice-u2', 'alice-u3']), devices: ['alice-d1', 'mallory-d1'], signer: key('mallory-u1') }),
  'webvh',
  { note: 'a provider without an update key cannot authorize a device (§Provider-Issued Devices)' },
);
reject(
  'uncommitted-update-key',
  aliceV1.update({ time: T(2), params: preRotation(['mallory-u1', 'mallory-u2']), devices: ['alice-d1', 'mallory-d1'], signer: key('mallory-u1') }),
  'webvh',
  { note: 'pre-rotation: the update key was not committed by the previous entry' },
);
reject('version-time-not-increasing', aliceV1.update({ time: T(1), params: preRotation(['alice-u2', 'alice-u3']), devices: ['alice-d1'], signer: key('alice-u2') }), 'webvh', {
  note: '§Log Verification item 3: strict increase still applies',
});
reject(
  'method-0.5',
  Log.create({ path: 'old', time: T(40), params: { method: 'did:webvh:0.5', updateKeys: [key('old-u1').mk] }, devices: ['old-d1'], signer: key('old-u1') }),
  'webvh',
  { note: '§Log Verification item 2: method MUST be did:webvh:1.0' },
);
{
  const deactivated = bobV1.update({ time: T(12), params: { deactivated: true, updateKeys: [] }, devices: ['bob-d1'], signer: key('bob-u1') });
  reject('deactivated-head', deactivated, 'deactivated', { note: '§Log Verification item 5: the active deactivated MUST be false' });
  reject('after-deactivation', deactivated.update({ time: T(13), devices: ['bob-d1'], signer: key('bob-u1') }), 'webvh', {
    note: '§Log Verification item 5: no entry may follow a deactivation',
  });
}
reject('witness-threshold-not-met', carolV1, 'webvh', {
  witness: witnessFile([{ versionId: carolVid, by: ['carol-w1'] }]),
  note: 'one approval, threshold 2',
});
reject('witness-bad-proof-not-counted', carolV1, 'webvh', {
  witness: witnessFile([{ versionId: carolVid, by: ['carol-w1', 'carol-w2'], corrupt: ['carol-w2'] }]),
  note: '§did:webvh Profile, Witnesses: only valid proofs count toward the threshold',
});
reject('witness-file-missing', carolV1, 'webvh', { note: 'witnesses active and witness_file empty' });

// Invalid logs: the draft's profile. Each is otherwise a valid did:webvh
// log, so a plain v1.0 resolver would accept it.
reject('no-final-lf', bobV1, 'profile', { text: bobV1.text().slice(0, -1), note: '§did:webvh Profile, Encoding: each line ends in LF' });
reject('crlf', bobV1, 'profile', { text: bobV1.lines.map((l) => l + '\r\n').join(''), note: '§did:webvh Profile, Encoding: a single LF' });
reject('blank-line', bobV2, 'profile', { text: bobV2.lines[0] + '\n\n' + bobV2.lines[1] + '\n', note: '§did:webvh Profile, Encoding: no blank lines' });
reject('fractional-version-time', Log.create({ path: 'frac', time: '2026-11-01T00:00:01.5Z', params: { updateKeys: [key('frac-u1').mk] }, devices: ['frac-d1'], signer: key('frac-u1') }), 'profile', {
  note: '§did:webvh Profile, Encoding: versionTime is YYYY-MM-DDTHH:MM:SSZ',
});
reject('offset-version-time', Log.create({ path: 'offset', time: '2026-11-01T00:00:01+00:00', params: { updateKeys: [key('offset-u1').mk] }, devices: ['offset-d1'], signer: key('offset-u1') }), 'profile', {
  note: '§did:webvh Profile, Encoding: versionTime is YYYY-MM-DDTHH:MM:SSZ',
});
reject('leading-zero-version', bobV1.update({ time: T(11), devices: ['bob-d1'], signer: key('bob-u1'), versionId: (n, h) => `0${n}-${h}` }), 'profile', {
  note: '§did:webvh Profile, Encoding: no leading zeros in the version number',
});
reject('null-parameter', bobV1.update({ time: T(11), params: { ttl: null }, devices: ['bob-d1'], signer: key('bob-u1') }), 'profile', {
  note: '§did:webvh Profile, Parameters: a null parameter MUST be rejected',
});
reject(
  'proof-not-array',
  bobV1.update({ time: T(11), devices: ['bob-d1'], signer: key('bob-u1'), proofs: (e) => proof(key('bob-u1'), e, T(11)) }),
  'profile',
  { note: '§did:webvh Profile, Proofs: an array containing exactly one proof' },
);
reject(
  'two-proofs',
  bobV1.update({ time: T(11), devices: ['bob-d1'], signer: key('bob-u1'), proofs: (e) => [proof(key('bob-u1'), e, T(11)), proof(key('bob-u1'), e, T(12))] }),
  'profile',
  { note: '§did:webvh Profile, Proofs: exactly one proof' },
);
{
  // The document carries "x":1; the line repeats the member. JCS of the
  // parsed object (last value wins) is what was signed.
  const dup = Log.create({ path: 'dup', time: T(50), params: { updateKeys: [key('dup-u1').mk] }, devices: ['dup-d1'], docExtra: { x: 1 }, signer: key('dup-u1') });
  reject('duplicate-member', dup, 'profile', { text: dup.text().replace('"x":1', '"x":1,"x":1'), note: '§did:webvh Profile, Encoding: duplicate member names are rejected' });
}
reject('noncharacter', Log.create({ path: 'nonchar', time: T(51), params: { updateKeys: [key('nc-u1').mk] }, devices: ['nc-d1'], docExtra: { name: 'a￿b' }, signer: key('nc-u1') }), 'profile', {
  note: 'RFC 7493 §2.1: no noncharacters',
});
reject('percent-encoded-idn', Log.create({ path: 'idn', domain: 'b%C3%BCcher.example', time: T(52), params: { updateKeys: [key('idn-u1').mk] }, devices: ['idn-d1'], signer: key('idn-u1') }), 'profile', {
  note: '§did:webvh Profile, Domain: only ASCII letters, digits, hyphens and dots',
});
reject('port-in-domain', Log.create({ path: 'port', domain: 'example.com%3A8443', time: T(53), params: { updateKeys: [key('port-u1').mk] }, devices: ['port-d1'], signer: key('port-u1') }), 'profile', {
  note: '§did:webvh Profile, Domain (mimid reading, decision mimid-1wgh.4.81.12): %3A is not a letter, digit, hyphen or dot',
});
reject('unexpected-witness-file', bobV1, 'profile', {
  witness: witnessFile([{ versionId: bobV1.head.versionId, by: ['carol-w1'] }]),
  note: '§The did:webvh Credential: witness_file MUST be empty if no carried entry has active witnesses',
});
reject('empty-log', bobV1, 'profile', { text: '', note: '§The did:webvh Credential: did_log runs from the first entry through the head' });

// ---------------------------------------------------------------- group-rule vectors
const head = (log, devices) => ({ scid: log.scid, version_id: log.head.versionId, authorized_keys: devices.map((d) => hex(key(d).pub)).sort() });
const leaf = (logName, device) => ({ log: logName, signature_key: hex(key(device).pub) });
const record = (heads) => ({ heads, tls: hex(headsTls(heads)) });

const binding = [
  { leaf: leaf('alice-v2', 'alice-d2'), valid: true, note: '§Binding to the LeafNode' },
  { leaf: leaf('alice-v3', 'alice-d2'), valid: false, note: 'd2 is revoked in alice-v3' },
  { leaf: leaf('bob-v1', 'alice-d1'), valid: false, note: 'another user\'s key' },
  { leaf: leaf('dave-authorized-keys', 'dave-x3'), valid: false, note: 'in the document but not in authentication' },
];

const successor = [
  { old: 'alice-v1', new: 'alice-v2', valid: true, note: '§Successor Credentials: earlier log is a prefix' },
  { old: 'alice-v1', new: 'alice-v1', valid: true, note: 'the same log' },
  { old: 'alice-v2', new: 'alice-v1', valid: false, note: 'moving backwards' },
  { old: 'alice-v3', new: 'alice-v3b', valid: false, note: 'a fork' },
  { old: 'alice-v1', new: 'bob-v1', valid: false, note: 'a different SCID' },
];

const commits = [
  {
    name: 'first-device',
    previous: record([]),
    leaves: [leaf('alice-v1', 'alice-d1')],
    resulting: record([head(aliceV1, ['alice-d1'])]),
    valid: true,
    note: '§Expected Heads: no reference entry, so L\'s head',
  },
  {
    name: 'missing-extension',
    previous: record([]),
    leaves: [leaf('alice-v1', 'alice-d1')],
    resulting: record([]),
    valid: false,
    reason: 'extension-mismatch',
    note: '§Rules, Extension matches',
  },
  {
    name: 'add-device-raises-head',
    previous: record([head(aliceV1, ['alice-d1'])]),
    leaves: [leaf('alice-v1', 'alice-d1'), leaf('alice-v2', 'alice-d2')],
    resulting: record([head(aliceV2, ['alice-d1', 'alice-d2'])]),
    valid: true,
    note: 'd1 keeps its older credential (§Successor Credentials, second paragraph)',
  },
  {
    name: 'add-device-without-raising',
    previous: record([head(aliceV1, ['alice-d1'])]),
    leaves: [leaf('alice-v1', 'alice-d1'), leaf('alice-v2', 'alice-d2')],
    resulting: record([head(aliceV1, ['alice-d1'])]),
    valid: false,
    reason: 'extension-mismatch',
    note: 'a Commit that changes the expected value must set it',
  },
  {
    name: 'revocation-removes-device',
    previous: record([head(aliceV2, ['alice-d1', 'alice-d2'])]),
    leaves: [leaf('alice-v3', 'alice-d1')],
    resulting: record([head(aliceV3, ['alice-d1'])]),
    valid: true,
    note: '§Revoking a Device: the Commit carries alice-v3 and removes d2',
  },
  {
    name: 'revocation-keeps-device',
    previous: record([head(aliceV2, ['alice-d1', 'alice-d2'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('alice-v2', 'alice-d2')],
    resulting: record([head(aliceV3, ['alice-d1'])]),
    valid: false,
    reason: 'unauthorized',
    note: '§Rules, Authorization: the Commit that raises the head must remove d2',
  },
  {
    name: 'stale-key-package',
    previous: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('alice-v2', 'alice-d2')],
    resulting: record([head(aliceV3, ['alice-d1'])]),
    valid: false,
    reason: 'unauthorized',
    note: '§Withheld or Stale Logs: an old KeyPackage of the revoked d2',
  },
  {
    name: 'record-outlives-devices',
    previous: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v2', 'alice-d2')],
    resulting: record([head(aliceV3, ['alice-d1'])]),
    valid: false,
    reason: 'unauthorized',
    note: '§The Heads Extension: the record remembers the revocation after every device of the user has left',
  },
  {
    name: 'never-backwards',
    previous: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v2', 'alice-d1')],
    resulting: record([head(aliceV2, ['alice-d1', 'alice-d2'])]),
    valid: false,
    reason: 'extension-mismatch',
    note: 'the record never moves backwards',
  },
  {
    name: 'older-credential-still-authorized',
    previous: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v1', 'alice-d1')],
    resulting: record([head(aliceV3, ['alice-d1'])]),
    valid: true,
    note: '§Successor Credentials: an older head stays valid while its key is recorded',
  },
  {
    name: 'entry-never-removed',
    previous: record([head(aliceV3, ['alice-d1']), head(bobV1, ['bob-d1'])]),
    leaves: [leaf('bob-v1', 'bob-d1')],
    resulting: record([head(bobV1, ['bob-d1'])]),
    valid: false,
    reason: 'extension-mismatch',
    note: '§The Heads Extension: "an entry is never removed"',
  },
  {
    name: 'entry-kept-without-leaves',
    previous: record([head(aliceV3, ['alice-d1']), head(bobV1, ['bob-d1'])]),
    leaves: [leaf('bob-v1', 'bob-d1')],
    resulting: record([head(aliceV3, ['alice-d1']), head(bobV1, ['bob-d1'])]),
    valid: true,
    note: '§Expected Heads: an SCID with no leaf keeps its entry unchanged',
  },
  {
    name: 'fork-at-same-height',
    previous: record([head(aliceV2, ['alice-d1', 'alice-d2'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('alice-v3b', 'alice-d3')],
    resulting: record([head(aliceV3b, ['alice-d1', 'alice-d2', 'alice-d3'])]),
    valid: false,
    reason: 'fork',
    note: '§Rules, Consistency: a credential newer than R must be a prefix of L',
  },
  {
    name: 'fork-against-record',
    previous: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('alice-v3b', 'alice-d3')],
    resulting: record([head(aliceV3, ['alice-d1'])]),
    valid: false,
    reason: 'missing-reference',
    note: '§Rules, Consistency: a credential at the recorded version must contain it',
  },
  {
    name: 'newer-fork-lacks-reference',
    previous: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('alice-v4b', 'alice-d3')],
    resulting: record([head(aliceV4b, ['alice-d3'])]),
    valid: false,
    reason: 'newest-lacks-reference',
    note: '§Expected Heads: L MUST contain R\'s versionId',
  },
  {
    name: 'new-scid-two-forks',
    previous: record([]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('alice-v3b', 'alice-d3')],
    resulting: record([head(aliceV3b, ['alice-d1', 'alice-d2', 'alice-d3'])]),
    valid: false,
    reason: 'fork',
    note: 'no reference entry: every credential must be a prefix of L (mimid reading, decision mimid-1wgh.4.81.14)',
  },
  {
    name: 'two-users',
    previous: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('bob-v2', 'bob-d2'), leaf('bob-v1', 'bob-d1')],
    resulting: record([head(aliceV3, ['alice-d1']), head(bobV2, ['bob-d1', 'bob-d2'])]),
    valid: true,
    note: 'entries sorted by scid bytes',
  },
];

const joins = [
  {
    name: 'welcome-valid',
    heads: record([head(aliceV3, ['alice-d1']), head(bobV1, ['bob-d1'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('bob-v1', 'bob-d1')],
    valid: true,
  },
  {
    name: 'welcome-older-credential',
    heads: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v1', 'alice-d1')],
    valid: true,
    note: 'the joiner relies on the GroupContext for heads no leaf carries',
  },
  {
    name: 'welcome-entry-without-leaves',
    heads: record([head(aliceV3, ['alice-d1']), head(carolV1, ['carol-d1'])]),
    leaves: [leaf('alice-v3', 'alice-d1')],
    valid: true,
  },
  {
    name: 'welcome-leaf-newer-than-record',
    heads: record([head(aliceV2, ['alice-d1', 'alice-d2'])]),
    leaves: [leaf('alice-v3', 'alice-d1')],
    valid: false,
    reason: 'newer-than-recorded',
  },
  {
    name: 'welcome-keys-mismatch',
    heads: record([head(aliceV3, ['alice-d1', 'alice-d2'])]),
    leaves: [leaf('alice-v3', 'alice-d1')],
    valid: false,
    reason: 'keys-mismatch',
    note: 'a recorded head a leaf carries must list that document\'s keys',
  },
  {
    name: 'welcome-missing-entry',
    heads: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('bob-v1', 'bob-d1')],
    valid: false,
    reason: 'missing-entry',
  },
  {
    name: 'welcome-revoked-device',
    heads: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('alice-v2', 'alice-d2')],
    valid: false,
    reason: 'unauthorized',
  },
  {
    name: 'welcome-fork',
    heads: record([head(aliceV3, ['alice-d1'])]),
    leaves: [leaf('alice-v3', 'alice-d1'), leaf('alice-v3b', 'alice-d3')],
    valid: false,
    reason: 'missing-reference',
  },
];

// Known-answer check of this generator's JCS and multihash: the entry hash
// example in did:webvh v1.0 §Generate Entry Hash.
{
  const example = JSON.parse(
    '{"versionId": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE", "versionTime": "2025-04-01T17:39:50Z", "parameters": {"witness": {"threshold": 2, "witnesses": [{"id": "did:key:z6Mkkc51mg2vpQzKWAbWQZupeGYhowaBjYkmvcKMTqteqHB4", "weight": 1}, {"id": "did:key:z6MkuDdJdKLCgwZuQuEi9xG6LVgJJ9Tebr74CXPYPSumqgJs", "weight": 1}, {"id": "did:key:z6MkoSWmQyp4fTk4ZQy4KUsss9dFX51XfEUzKKKj1J1JUsrF", "weight": 1}]}, "updateKeys": ["z6MkgzBDcBFV3sk4ypPE5YXMZHmS213A3HpYY2LmcVKV15jr"], "nextKeyHashes": ["QmZreDcjvWEpyRFznQeExWNCsvMLk5i59AcRJJuQC8UodJ"], "method": "did:webvh:0.5", "scid": "QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE"}, "state": {"@context": ["https://www.w3.org/ns/did/v1"], "id": "did:webvh:QmdmPkUdYzbr9txmx8gM2rsHPgr5L6m3gHjJGAf4vUFoGE:domain.example"}}',
  );
  const got = multihash(jcs(example));
  if (got !== 'QmQ6FJ4fk2xheSSQoEjVpTgx9AQPKhJgtR9hn1nr4EeCrZ') throw new Error(`entry hash known answer failed: ${got}`);
}

const devices = Object.values(keys)
  .filter((k) => /-d\d$/.test(k.name))
  .sort((a, b) => a.name.localeCompare(b.name))
  .map((k) => ({ name: k.name, seed: hex(k.seed), public_key: hex(k.pub), multikey: k.mk }));

const out = {
  description:
    'Interop vectors for draft-atwood-mls-didwebvh-credential-00, generated by generate.mjs (Node built-in crypto only). ' +
    'did:webvh v1.0 is spec-v1.0 at decentralized-identity/didwebvh 91f3cba. Device keys are Ed25519; seed is the RFC 8032 private key.',
  reasons: {
    webvh: 'fails a did:webvh v1.0 Read (Resolve) check',
    profile: 'fails a check of the draft\'s §did:webvh Profile or §The did:webvh Credential, though a plain did:webvh v1.0 resolver accepts it',
    deactivated: '§Log Verification item 5',
  },
  devices,
  logs,
  binding,
  successor,
  commits,
  joins,
};
fs.writeFileSync(path.join(OUT, 'vectors.json'), JSON.stringify(out, null, 1) + '\n');
console.log(`wrote ${logs.length} logs, ${binding.length} binding, ${successor.length} successor, ${commits.length} commit and ${joins.length} join vectors`);
