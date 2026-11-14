import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createHash, randomUUID } from 'node:crypto';
import { promisify } from 'node:util';
import { zstdDecompress } from 'node:zlib';

const decompress = promisify(zstdDecompress);
export const DETECTOR_DATA_SOURCE = 'https://lm.ikale.io/data/';
export const DETECTOR_DATA_PROJECT = 'https://github.com/Ikaleio/lm-detector';
const DAY = 24 * 60 * 60 * 1000;
const CHUNK = 4 * 1024 * 1024;
const LIMIT = { metadata: 1024 * 1024, compressed: 128 * 1024 * 1024, expanded: 256 * 1024 * 1024, total: 256 * 1024 * 1024 };
const NAMES = ['unified_reference.jsonl', 'unified_bank.json', 'shared_detector.bin', 'tokenizer_bank.json'];
const instances = new Map();
const sha = bytes => createHash('sha256').update(bytes).digest('hex');
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const iso = () => new Date().toISOString();
const validTime = v => typeof v === 'string' && v.length <= 64 && Number.isFinite(Date.parse(v));
const validId = v => typeof v === 'string' && v.length > 0 && v.length <= 256;
function check(condition, code) { if (!condition) throw new UpdateError(code); }
const MESSAGES = {
  network: 'Fingerprint source could not be reached.', timeout: 'Fingerprint download timed out.',
  http: 'Fingerprint source returned an unsuccessful response.', size: 'Fingerprint data exceeds the supported size limit.',
  manifest: 'Fingerprint manifest format is not supported.', bundle: 'Fingerprint bundle format is not supported.',
  schema: 'Fingerprint data is incompatible with this detector engine.', hash: 'Fingerprint checksum verification failed.',
  changed: 'Upstream changed during download; the previous snapshot was kept. Retry the update.',
  collision: 'An immutable local fingerprint chunk differs from upstream; the previous snapshot was kept.',
  locked: 'Another updater holds the disk lock. A lock left by a stopped process requires operator removal.',
  storage: 'Fingerprint data could not be read or written locally.',
};
class UpdateError extends Error { constructor(code) { super(MESSAGES[code]); this.code = code; } }
function safeError(error) {
  const code = error instanceof UpdateError ? error.code : 'storage';
  return { code, message: MESSAGES[code], at: iso() };
}
function json(bytes, code) { try { return JSON.parse(bytes.toString('utf8')); } catch { throw new UpdateError(code); } }

function manifestInfo(bytes) {
  const manifest = json(bytes, 'manifest');
  check(object(manifest) && Object.keys(manifest).length === NAMES.length && NAMES.every(n => Object.hasOwn(manifest, n)), 'manifest');
  let total = 0;
  for (const name of NAMES) {
    const entry = manifest[name];
    check(object(entry) && Number.isSafeInteger(entry.bytes) && entry.bytes > 0 && entry.bytes <= LIMIT.compressed, 'manifest');
    check(Array.isArray(entry.parts) && entry.parts.length === Math.ceil(entry.bytes / CHUNK), 'manifest');
    let digest;
    entry.parts.forEach((part, i) => {
      check(typeof part === 'string' && part.startsWith(name + '.'), 'manifest');
      const match = /^([a-f0-9]{16})\.(0|[1-9][0-9]*)\.zst$/.exec(part.slice(name.length + 1));
      check(match && Number(match[2]) === i && (!digest || digest === match[1]), 'manifest');
      digest = match[1];
    });
    total += entry.bytes;
  }
  check(total <= LIMIT.total, 'size');
  return manifest;
}
function bundleInfo(bytes, manifest) {
  const bundle = json(bytes, 'bundle');
  check(object(bundle) && bundle.schema === 'lmfpd-data-v1' && bundle.detector_schema === 'shared-detector-v2' && validTime(bundle.built_at), 'bundle');
  check(Array.isArray(bundle.models) && bundle.models.length > 0 && bundle.models.length <= 10000, 'bundle');
  const ids = new Set();
  for (const m of bundle.models) {
    check(object(m) && validId(m.id) && !ids.has(m.id) && Number.isSafeInteger(m.response_count) && m.response_count > 0, 'bundle');
    ids.add(m.id);
  }
  const file = bundle.files?.['shared_detector.bin'];
  check(object(file) && /^[a-f0-9]{64}$/.test(file.sha256) && file.bytes === manifest['shared_detector.bin'].bytes && JSON.stringify(file.parts) === JSON.stringify(manifest['shared_detector.bin'].parts), 'bundle');
  return bundle;
}

async function readLimited(file, max) {
  const handle = await fs.open(file, 'r');
  try {
    const stat = await handle.stat();
    check(stat.isFile() && stat.size <= max, 'size');
    return await handle.readFile();
  } finally { await handle.close(); }
}
async function fetchPublic(relative, max, signal) {
  // Only internal, validated manifest filenames reach this function. Never accept request URLs/headers.
  const requestSignal = AbortSignal.any([signal, AbortSignal.timeout(30000)]);
  let response;
  try {
    response = await fetch(new URL(relative, DETECTOR_DATA_SOURCE), {
      redirect: 'error', signal: requestSignal, cache: 'no-store',
      headers: { Accept: 'application/octet-stream, application/json', 'Cache-Control': 'no-cache' },
    });
    check(response.ok && response.body, 'http');
    const length = response.headers.get('content-length');
    check(!length || (Number.isSafeInteger(Number(length)) && Number(length) >= 0 && Number(length) <= max), 'size');
    const pieces = []; let size = 0;
    for await (const piece of response.body) {
      size += piece.length; check(size <= max, 'size'); pieces.push(piece);
    }
    return Buffer.concat(pieces, size);
  } catch (error) {
    if (response?.body && !response.body.locked) await response.body.cancel().catch(() => {});
    if (error instanceof UpdateError) throw error;
    throw new UpdateError(requestSignal.aborted ? 'timeout' : 'network');
  }
}
async function atomicWrite(file, bytes) {
  const temporary = `${file}.${randomUUID()}.tmp`;
  try {
    const handle = await fs.open(temporary, 'wx', 0o600);
    try { await handle.writeFile(bytes); await handle.sync(); } finally { await handle.close(); }
    await fs.rename(temporary, file);
  } finally { await fs.rm(temporary, { force: true }).catch(() => {}); }
}

function validateDetector(bytes, bundle) {
  check(bytes.length >= 4, 'schema');
  const length = bytes.readUInt32LE(0), start = Math.ceil((4 + length) / 4) * 4;
  check(length > 0 && length <= 16 * 1024 * 1024 && start <= bytes.length && (bytes.length - start) % 4 === 0, 'schema');
  const header = json(bytes.subarray(4, 4 + length), 'schema');
  const count = (bytes.length - start) / 4;
  check(header.schema === 'shared-detector-v2' && header.bank_built_at === bundle.built_at && JSON.stringify(header.model_ids) === JSON.stringify(bundle.models.map(m => m.id)), 'schema');
  const responseCounts = header.response_counts;
  check(object(responseCounts) && Number.isSafeInteger(responseCounts.$f32) && responseCounts.$f32 >= 0 && responseCounts.n === bundle.models.length && responseCounts.$f32 + responseCounts.n <= count, 'schema');
  const floatBytes = Buffer.allocUnsafe(4);
  const readFloat = i => {
    for (let b = 0; b < 4; b++) floatBytes[b] = bytes[start + b * count + i];
    return floatBytes.readFloatLE(0);
  };
  check(bundle.models.every((m, i) => readFloat(responseCounts.$f32 + i) === m.response_count), 'schema');
  const r = header.ranker;
  check(object(r) && Array.isArray(r.head_params) && r.head_params.length === 2 && Array.isArray(r.full_params) && r.full_params.length === 2 &&
    Array.isArray(r.lda_weights) && object(r.lda_bias) && Array.isArray(r.references) && r.references.length === bundle.models.length &&
    object(r.bank?.hellinger) && object(r.bank?.ordered_blocks) && object(r.blend) && object(r.positional), 'schema');
  for (let i = 0; i < count; i++) check(Number.isFinite(readFloat(i)), 'schema');
  // Validate every binary vector reference before clients decode the column-packed float32 payload.
  const stack = [header]; let visited = 0;
  while (stack.length) {
    const value = stack.pop(); check(++visited < 2000000, 'size');
    if (object(value) && Object.hasOwn(value, '$f32')) {
      check(Number.isSafeInteger(value.$f32) && value.$f32 >= 0 && Number.isSafeInteger(value.n) && value.n > 0 && value.$f32 + value.n <= count, 'schema');
    } else if (value && typeof value === 'object') { for (const child of Object.values(value)) stack.push(child); }
  }
  return header;
}
function validateTokenizer(bank) {
  check(bank.schema === 'tokenizer-bank-v1' && Array.isArray(bank.probes) && bank.probes.length > 0 && bank.probes.length <= 10000 && Array.isArray(bank.classes) && bank.classes.length >= 2 && bank.classes.length <= 10000, 'schema');
  check(typeof bank.wrapper?.prefix === 'string' && typeof bank.wrapper?.suffix === 'string' && Array.isArray(bank.api_models), 'schema');
  check(bank.probes.every(p => object(p) && validId(p.id) && typeof p.text === 'string'), 'schema');
  const ids = new Set();
  for (const item of bank.classes) {
    check(object(item) && validId(item.id) && !ids.has(item.id) && Array.isArray(item.counts) && item.counts.length === bank.probes.length && item.counts.every(Number.isSafeInteger) && Array.isArray(item.aliases), 'schema');
    ids.add(item.id);
  }
  check(bank.api_models.every(m => object(m) && (m.class === null || ids.has(m.class))), 'schema');
  for (const pattern of [...bank.api_models.map(m => m.pattern), ...bank.classes.flatMap(m => m.aliases)]) {
    check(typeof pattern === 'string' && pattern.length <= 4096, 'schema');
    try { new RegExp(pattern, 'i'); } catch { throw new UpdateError('schema'); }
  }
}
async function validateSnapshot(stage, manifest, bundle) {
  let bank, detector, referenceHash; const counts = new Map();
  for (const name of NAMES) {
    const entry = manifest[name];
    const compressed = Buffer.concat(await Promise.all(entry.parts.map(p => readLimited(path.join(stage, 'chunks', p), CHUNK))));
    check(compressed.length === entry.bytes && sha(compressed).slice(0, 16) === entry.parts[0].slice(name.length + 1, name.length + 17), 'hash');
    let bytes;
    try { bytes = await decompress(compressed, { maxOutputLength: LIMIT.expanded }); }
    catch { throw new UpdateError('schema'); }
    if (name === 'shared_detector.bin') {
      check(sha(bytes) === bundle.files[name].sha256, 'hash'); detector = validateDetector(bytes, bundle);
    } else if (name === 'unified_bank.json') {
      bank = json(bytes, 'schema');
      check(bank.schema === 'robust-number-fingerprint-bank' && bank.built_at === bundle.built_at && Array.isArray(bank.models) && bank.models.length === bundle.models.length && object(bank.robust) && object(bank.calibration), 'schema');
      check(bank.models.every((m, i) => m.id === bundle.models[i].id && m.response_count === bundle.models[i].response_count), 'schema');
    } else if (name === 'tokenizer_bank.json') { validateTokenizer(json(bytes, 'schema')); }
    else {
      referenceHash = sha(bytes);
      for (const line of bytes.toString('utf8').split('\n')) {
        if (!line.trim()) continue;
        const batch = json(Buffer.from(line), 'schema');
        check(batch.schema_version === 1 && batch.purpose === 'reference' && validId(batch.model?.id) && Array.isArray(batch.samples) && batch.samples.length > 0 && batch.samples.every(s => object(s) && typeof s.text === 'string'), 'schema');
        counts.set(batch.model.id, (counts.get(batch.model.id) || 0) + batch.samples.length);
      }
    }
  }
  check(bank.reference_sha256 === referenceHash && counts.size === bank.models.length && bank.models.every(m => counts.get(m.id) === m.response_count), 'hash');
  check(JSON.stringify(detector.model_ids) === JSON.stringify(bank.models.map(m => m.id)), 'schema');
}

/** No import-time I/O or timers. Call start() once after constructing the authenticated gateway. */
export function createDetectorUpdater({
  dataDir = fileURLToPath(new URL('./lm-detector-dist/data/', import.meta.url)),
  stateDir = fileURLToPath(new URL('./.lm-detector-updates/', import.meta.url)),
} = {}) {
  dataDir = path.resolve(dataDir); stateDir = path.resolve(stateDir);
  if (instances.has(dataDir)) return instances.get(dataDir);
  const stateFile = path.join(stateDir, 'status.json'), lockFile = path.join(stateDir, 'update.lock');
  let pending, timer, initialTimer, activeController, started = false, initialized;
  let state = { version: null, builtAt: null, modelCount: null, lastChecked: null, lastSuccess: null, lastError: null, changed: false, updateCount: 0 };
  let nextCheck = null;
  function snapshot() { return { ...state, lastError: state.lastError ? { ...state.lastError } : null, source: DETECTOR_DATA_SOURCE, project: DETECTOR_DATA_PROJECT, running: Boolean(pending), automatic: started, intervalMs: DAY, nextCheck }; }
  async function initialize() {
    try {
      const saved = json(await readLimited(stateFile, LIMIT.metadata), 'schema');
      for (const key of ['lastChecked', 'lastSuccess']) if (saved[key] === null || validTime(saved[key])) state[key] = saved[key];
      if (Number.isSafeInteger(saved.updateCount) && saved.updateCount >= 0) state.updateCount = saved.updateCount;
      if (saved.lastError && Object.hasOwn(MESSAGES, saved.lastError.code)) state.lastError = { code: saved.lastError.code, message: MESSAGES[saved.lastError.code], at: validTime(saved.lastError.at) ? saved.lastError.at : null };
    } catch (error) { if (error.code !== 'ENOENT') state.lastError = safeError(error); }
    try {
      const bytes = await readLimited(path.join(dataDir, 'manifest.json'), LIMIT.metadata);
      const manifest = manifestInfo(bytes);
      state.version = sha(bytes);
      const bundle = bundleInfo(await readLimited(path.join(dataDir, 'bundle.json'), LIMIT.metadata), manifest);
      state.builtAt = bundle.built_at; state.modelCount = bundle.models.length;
    } catch (error) { state.lastError = safeError(error); }
  }
  const ready = () => initialized ??= initialize();
  async function persist() { await atomicWrite(stateFile, JSON.stringify(state)); }
  async function perform() {
    activeController = new AbortController();
    await ready();
    state.lastChecked = iso(); state.changed = false; state.lastError = null;
    let stage, lock, bundleBefore, bundleWritten = false, activated = false;
    try {
      await fs.mkdir(stateDir, { recursive: true, mode: 0o700 });
      try { lock = await fs.open(lockFile, 'wx', 0o600); }
      catch (error) {
        if (error.code !== 'EEXIST') throw error;
        const previous = json(await readLimited(lockFile, 4096), 'locked');
        check(Number.isSafeInteger(previous.pid) && previous.pid > 0, 'locked');
        let dead = false;
        try { process.kill(previous.pid, 0); } catch (e) { dead = e.code === 'ESRCH'; }
        check(dead, 'locked');
        await fs.unlink(lockFile);
        try { lock = await fs.open(lockFile, 'wx', 0o600); }
        catch (e) { if (e.code === 'EEXIST') throw new UpdateError('locked'); throw e; }
      }
      await lock.writeFile(JSON.stringify({ pid: process.pid, startedAt: state.lastChecked }));
      await fs.mkdir(path.join(dataDir, 'chunks'), { recursive: true });
      // Stage beside data so hard links and the manifest rename stay on the same filesystem.
      stage = await fs.mkdtemp(path.join(path.dirname(dataDir), '.detector-stage-'));
      await fs.mkdir(path.join(stage, 'chunks'));
      const signal = AbortSignal.any([activeController.signal, AbortSignal.timeout(10 * 60 * 1000)]);
      const manifestBytes = await fetchPublic('manifest.json', LIMIT.metadata, signal);
      const manifest = manifestInfo(manifestBytes);
      const bundleBytes = await fetchPublic('bundle.json', LIMIT.metadata, signal);
      const bundle = bundleInfo(bundleBytes, manifest);
      for (const name of NAMES) {
        const entry = manifest[name];
        for (const [i, part] of entry.parts.entries()) {
          const target = path.join(stage, 'chunks', part);
          const expected = Math.min(CHUNK, entry.bytes - i * CHUNK);
          let bytes;
          try { bytes = await readLimited(path.join(dataDir, 'chunks', part), CHUNK); }
          catch (error) { if (error.code !== 'ENOENT') throw error; }
          if (!bytes) bytes = await fetchPublic('chunks/' + part, expected, signal);
          check(bytes.length === expected, 'hash');
          await fs.writeFile(target, bytes, { flag: 'wx', mode: 0o644 });
        }
      }
      await validateSnapshot(stage, manifest, bundle);
      // Detect non-atomic upstream deployments instead of mixing two published datasets.
      const manifestAgain = await fetchPublic('manifest.json', LIMIT.metadata, signal);
      const bundleAgain = await fetchPublic('bundle.json', LIMIT.metadata, signal);
      check(manifestAgain.equals(manifestBytes) && bundleAgain.equals(bundleBytes), 'changed');
      const version = sha(manifestBytes);
      for (const name of NAMES) for (const part of manifest[name].parts) {
        const source = path.join(stage, 'chunks', part), destination = path.join(dataDir, 'chunks', part);
        try { await fs.link(source, destination); }
        catch (error) {
          if (error.code !== 'EEXIST') throw error;
          check((await readLimited(source, CHUNK)).equals(await readLimited(destination, CHUNK)), 'collision');
        }
      }
      // Browser loaders cache manifest.json for the whole run: never replace/delete old chunks.
      // bundle.json is SDK metadata, not used by that loader. Roll it back if the manifest commit fails.
      try { bundleBefore = await readLimited(path.join(dataDir, 'bundle.json'), LIMIT.metadata); }
      catch (error) { if (error.code !== 'ENOENT') throw error; }
      await atomicWrite(path.join(dataDir, 'bundle.json'), bundleBytes); bundleWritten = true;
      await atomicWrite(path.join(dataDir, 'manifest.json'), manifestBytes); activated = true;
      state.changed = version !== state.version;
      if (state.changed) state.updateCount++;
      state.version = version; state.builtAt = bundle.built_at; state.modelCount = bundle.models.length;
      state.lastSuccess = iso();
      await persist();
    } catch (error) {
      state.lastError = safeError(error);
      if (bundleWritten && !activated) {
        try {
          if (bundleBefore) await atomicWrite(path.join(dataDir, 'bundle.json'), bundleBefore);
          else await fs.rm(path.join(dataDir, 'bundle.json'), { force: true });
        } catch { state.lastError = safeError(new UpdateError('storage')); }
      }
      // A contending process must not overwrite the active updater's persisted status.
      if (lock) await persist().catch(() => { state.lastError = safeError(new UpdateError('storage')); });
    } finally {
      if (stage) await fs.rm(stage, { recursive: true, force: true }).catch(() => {});
      if (lock) { await lock.close().catch(() => {}); await fs.rm(lockFile, { force: true }).catch(() => {}); }
    }
  }
  function sync() {
    if (pending) return pending;
    pending = perform().finally(() => { pending = undefined; activeController = undefined; }).then(snapshot);
    return pending;
  }
  function start() {
    if (started) return;
    started = true; nextCheck = iso();
    initialTimer = setTimeout(() => {
      initialTimer = undefined; nextCheck = new Date(Date.now() + DAY).toISOString();
      void sync();
      timer = setInterval(() => { nextCheck = new Date(Date.now() + DAY).toISOString(); void sync(); }, DAY);
      timer.unref();
    }, 0);
    initialTimer.unref();
  }
  function stop() {
    started = false; nextCheck = null;
    clearTimeout(initialTimer); clearInterval(timer); initialTimer = timer = undefined;
    activeController?.abort();
    // Let transaction cleanup release the disk lock before graceful process exit.
    return pending ?? Promise.resolve();
  }
  const updater = { start, stop, sync, getStatus: async () => { await ready(); return snapshot(); } };
  instances.set(dataDir, updater);
  return updater;
}
