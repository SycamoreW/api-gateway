import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { DatabaseSync } from 'node:sqlite';
import {
  stats, LOG_DIR, LOG_MAX_BODY_CHARS, HIDDEN_UI_LOG_EVENTS, STATS_FILE,
} from './state.mjs';

const LOG_INDEX_FILE = path.join(LOG_DIR, 'gateway-log-index.sqlite');
let logDb = null;

function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function currentLogFile() {
  const date = new Date().toISOString().split('T')[0];
  return path.join(LOG_DIR, `gateway-${date}.log`);
}

function logSourceName(file) {
  return path.basename(file);
}

function insertIndexedLog(sourceFile, byteOffset, entry, payload) {
  if (!logDb) return;
  logDb.prepare(`
    INSERT OR IGNORE INTO gateway_logs
      (source_file, byte_offset, timestamp, event, client_ip, payload)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    sourceFile,
    byteOffset,
    entry?.timestamp || null,
    entry?.event || 'parse_error',
    String(entry?.clientIp || entry?.ip || ''),
    payload,
  );
}

function syncLogFileToIndex(file) {
  if (!logDb || !fs.existsSync(file)) return;
  const sourceFile = logSourceName(file);
  const fileSize = fs.statSync(file).size;
  const meta = logDb.prepare('SELECT indexed_size FROM gateway_log_files WHERE source_file = ?').get(sourceFile);
  let indexedSize = Number(meta?.indexed_size) || 0;

  if (indexedSize > fileSize) {
    logDb.prepare('DELETE FROM gateway_logs WHERE source_file = ?').run(sourceFile);
    indexedSize = 0;
  }
  if (indexedSize === fileSize) return;

  const fd = fs.openSync(file, 'r');
  try {
    const length = fileSize - indexedSize;
    const buffer = Buffer.allocUnsafe(length);
    fs.readSync(fd, buffer, 0, length, indexedSize);
    logDb.exec('BEGIN');
    try {
      let start = 0;
      while (start < buffer.length) {
        const newline = buffer.indexOf(0x0a, start);
        if (newline < 0) break;
        const raw = buffer.subarray(start, newline).toString('utf8');
        if (raw) {
          let entry;
          try {
            entry = JSON.parse(raw);
          } catch {
            entry = { timestamp: null, event: 'parse_error', raw: truncateText(raw) };
          }
          insertIndexedLog(sourceFile, indexedSize + start, entry, JSON.stringify(entry));
        }
        start = newline + 1;
      }
      logDb.prepare(`
        INSERT INTO gateway_log_files (source_file, indexed_size)
        VALUES (?, ?)
        ON CONFLICT(source_file) DO UPDATE SET indexed_size = excluded.indexed_size
      `).run(sourceFile, indexedSize + start);
      logDb.exec('COMMIT');
    } catch (err) {
      logDb.exec('ROLLBACK');
      throw err;
    }
  } finally {
    fs.closeSync(fd);
  }
}

function initializeLogIndex() {
  try {
    ensureLogDir();
    logDb = new DatabaseSync(LOG_INDEX_FILE);
    logDb.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA synchronous = NORMAL;
      PRAGMA temp_store = MEMORY;
      CREATE TABLE IF NOT EXISTS gateway_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        source_file TEXT NOT NULL,
        byte_offset INTEGER NOT NULL,
        timestamp TEXT,
        event TEXT,
        client_ip TEXT,
        payload TEXT NOT NULL,
        UNIQUE(source_file, byte_offset)
      );
      CREATE INDEX IF NOT EXISTS idx_gateway_logs_event ON gateway_logs(event);
      CREATE INDEX IF NOT EXISTS idx_gateway_logs_client_ip ON gateway_logs(client_ip);
      CREATE TABLE IF NOT EXISTS gateway_log_files (
        source_file TEXT PRIMARY KEY,
        indexed_size INTEGER NOT NULL DEFAULT 0
      );
    `);
    const files = fs.readdirSync(LOG_DIR)
      .filter(name => /^gateway-\d{4}-\d{2}-\d{2}\.log$/.test(name))
      .sort()
      .map(name => path.join(LOG_DIR, name));
    for (const file of files) syncLogFileToIndex(file);
    logDb.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  } catch (err) {
    console.error('[log-index] initialization failed, falling back to file scan:', err.message);
    try { logDb?.close(); } catch {}
    logDb = null;
  }
}

function sanitizeHeaders(headers = {}) {
  const result = {};
  for (const [key, value] of Object.entries(headers)) {
    const lower = key.toLowerCase();
    if (lower === 'authorization' || lower.includes('key') || lower.includes('token')) {
      result[key] = '[redacted]';
    } else {
      result[key] = value;
    }
  }
  return result;
}

function truncateText(value, maxChars = LOG_MAX_BODY_CHARS) {
  const text = typeof value === 'string' ? value : JSON.stringify(value);
  if (!text || text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}... [truncated ${text.length - maxChars} chars]`;
}

function writeGatewayLog(event, fields = {}) {
  try {
    ensureLogDir();
    const entry = {
      timestamp: new Date().toISOString(),
      event,
      ...fields,
    };
    const file = currentLogFile();
    const payload = JSON.stringify(entry);
    const byteOffset = fs.existsSync(file) ? fs.statSync(file).size : 0;
    fs.appendFileSync(file, `${payload}\n`);
    if (logDb) {
      insertIndexedLog(logSourceName(file), byteOffset, entry, payload);
      logDb.prepare(`
        INSERT INTO gateway_log_files (source_file, indexed_size)
        VALUES (?, ?)
        ON CONFLICT(source_file) DO UPDATE SET indexed_size = excluded.indexed_size
      `).run(logSourceName(file), byteOffset + Buffer.byteLength(payload) + 1);
    }
  } catch (err) {
    console.error('[log] failed to write gateway log:', err.message);
  }
}

function readVisibleGatewayLogs(options = 100) {
  if (logDb) {
    try {
      const settings = typeof options === 'number' ? { limit: options } : (options || {});
      const limit = Number(settings.limit) > 0 ? Math.floor(Number(settings.limit)) : 100;
      const offset = Math.max(0, Math.floor(Number(settings.offset) || 0));
      const eventFilter = String(settings.event || '').trim();
      const search = String(settings.search || '').trim();
      const ipFilter = String(settings.ip || '').trim();
      const returnMeta = Boolean(settings.returnMeta);
      const hiddenEvents = [...HIDDEN_UI_LOG_EVENTS];
      const hiddenSql = hiddenEvents.map(() => '?').join(', ');
      const where = [`event NOT IN (${hiddenSql})`];
      const params = [...hiddenEvents];
      if (eventFilter) {
        where.push('event = ?');
        params.push(eventFilter);
      }
      if (ipFilter) {
        where.push('client_ip LIKE ?');
        params.push(`%${ipFilter}%`);
      }
      if (search) {
        where.push('payload LIKE ?');
        params.push(`%${search}%`);
      }
      const whereSql = `WHERE ${where.join(' AND ')}`;
      const total = Number(logDb.prepare(`SELECT COUNT(*) AS count FROM gateway_logs ${whereSql}`).get(...params)?.count) || 0;
      const rows = logDb.prepare(`
        SELECT payload FROM gateway_logs
        ${whereSql}
        ORDER BY id DESC
        LIMIT ? OFFSET ?
      `).all(...params, limit, offset);
      const logs = rows.map(row => {
        try { return JSON.parse(row.payload); } catch { return { event: 'parse_error', raw: truncateText(row.payload) }; }
      });
      if (!returnMeta) return logs;
      const events = logDb.prepare(`
        SELECT DISTINCT event FROM gateway_logs
        WHERE event NOT IN (${hiddenSql})
        ORDER BY event
      `).all(...hiddenEvents).map(row => row.event).filter(Boolean);
      return { logs, total, events };
    } catch (err) {
      console.error('[log-index] query failed, falling back to file scan:', err.message);
    }
  }
  try {
    const settings = typeof options === 'number' ? { limit: options } : (options || {});
    const limit = Number(settings.limit) > 0 ? Math.floor(Number(settings.limit)) : Infinity;
    const offset = Math.max(0, Math.floor(Number(settings.offset) || 0));
    const eventFilter = String(settings.event || '').trim();
    const search = String(settings.search || '').trim().toLowerCase();
    const ipFilter = String(settings.ip || '').trim().toLowerCase();
    const returnMeta = Boolean(settings.returnMeta);
    const files = fs.existsSync(LOG_DIR)
      ? fs.readdirSync(LOG_DIR)
        .filter(name => /^gateway-\d{4}-\d{2}-\d{2}\.log$/.test(name))
        .sort()
        .reverse()
        .map(name => path.join(LOG_DIR, name))
      : [];
    const logs = [];
    const events = new Set();
    let total = 0;
    for (const file of files) {
      const content = fs.readFileSync(file, 'utf-8').trim();
      if (!content) continue;
      const lines = content.split('\n').filter(Boolean);
      for (let i = lines.length - 1; i >= 0; i--) {
        let entry;
        try {
          entry = JSON.parse(lines[i]);
        } catch {
          entry = { timestamp: null, event: 'parse_error', raw: truncateText(lines[i]) };
        }
        if (HIDDEN_UI_LOG_EVENTS.has(entry.event)) continue;
        if (entry.event) events.add(entry.event);
        if (eventFilter && entry.event !== eventFilter) continue;
        if (ipFilter) {
          const entryIp = String(entry.clientIp || entry.ip || '').trim().toLowerCase();
          if (!entryIp.includes(ipFilter)) continue;
        }
        if (search && !JSON.stringify(entry).toLowerCase().includes(search)) continue;
        if (total >= offset && logs.length < limit) logs.push(entry);
        total += 1;
      }
    }
    return returnMeta ? { logs, total, events: [...events].sort() } : logs;
  } catch (err) {
    const logs = [{ timestamp: new Date().toISOString(), event: 'read_error', error: err.message }];
    return typeof options === 'object' && options?.returnMeta
      ? { logs, total: 1, events: ['read_error'] }
      : logs;
  }
}

function clearCurrentGatewayLog() {
  ensureLogDir();
  const file = currentLogFile();
  const sourceFile = logSourceName(file);
  fs.writeFileSync(file, '');
  if (logDb) {
    logDb.prepare('DELETE FROM gateway_logs WHERE source_file = ?').run(sourceFile);
    logDb.prepare(`
      INSERT INTO gateway_log_files (source_file, indexed_size)
      VALUES (?, 0)
      ON CONFLICT(source_file) DO UPDATE SET indexed_size = 0
    `).run(sourceFile);
  }
}

function newRequestId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

initializeLogIndex();

function fingerprintKey(key = '', scope = '') {
  if (!key) return '';
  // scope（一般为渠道 key）参与哈希，避免不同渠道使用相同上游 Key 时统计混算
  const material = scope ? `${scope}\n${key}` : key;
  return crypto.createHash('sha256').update(material).digest('hex').slice(0, 12);
}

function toTokenNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : 0;
}

function extractTokenUsageDetails(data) {
  if (!data || typeof data !== 'object') {
    return { inputTokens: 0, outputTokens: 0, totalTokens: 0, cacheCreationInputTokens: 0, cacheReadInputTokens: 0 };
  }

  const usage = data.usage && typeof data.usage === 'object' ? data.usage : {};
  const tokenUsage = data.token_usage && typeof data.token_usage === 'object' ? data.token_usage : {};
  const promptTokenDetails = usage.prompt_tokens_details && typeof usage.prompt_tokens_details === 'object'
    ? usage.prompt_tokens_details
    : {};
  const cacheCreationInputTokens =
    toTokenNumber(usage.cache_creation_input_tokens) +
    toTokenNumber(tokenUsage.cache_creation_input_tokens) +
    toTokenNumber(promptTokenDetails.cache_write_tokens);
  const cacheReadInputTokens =
    toTokenNumber(usage.cache_read_input_tokens) +
    toTokenNumber(tokenUsage.cache_read_input_tokens) +
    toTokenNumber(promptTokenDetails.cached_tokens);
  const promptTokens =
    toTokenNumber(usage.prompt_tokens) +
    toTokenNumber(tokenUsage.prompt_tokens);
  const uncachedInputTokens =
    toTokenNumber(usage.input_tokens) +
    toTokenNumber(tokenUsage.input_tokens);
  const inputTokens =
    promptTokens +
    uncachedInputTokens +
    (promptTokens > 0 ? 0 : cacheCreationInputTokens + cacheReadInputTokens);
  const outputTokens =
    toTokenNumber(usage.completion_tokens) +
    toTokenNumber(usage.output_tokens) +
    toTokenNumber(usage.reasoning_tokens) +
    toTokenNumber(tokenUsage.completion_tokens) +
    toTokenNumber(tokenUsage.output_tokens);

  const directTotal =
    toTokenNumber(usage.total_tokens) ||
    toTokenNumber(usage.totalTokens) ||
    toTokenNumber(data.total_tokens) ||
    toTokenNumber(data.totalTokens) ||
    toTokenNumber(typeof data.token_usage === 'number' ? data.token_usage : 0) ||
    toTokenNumber(tokenUsage.total_tokens) ||
    toTokenNumber(tokenUsage.totalTokens);
  const totalTokens = directTotal || inputTokens + outputTokens;
  return { inputTokens, outputTokens, totalTokens, cacheCreationInputTokens, cacheReadInputTokens };
}

function extractOutputContent(data) {
  if (!data || typeof data !== 'object') return '';
  if (typeof data.output_text === 'string') return data.output_text;
  if (typeof data.content === 'string') return data.content;
  if (Array.isArray(data.content)) {
    return data.content.map((part) => part?.text || part?.content || '').filter(Boolean).join('');
  }
  if (Array.isArray(data.choices)) {
    return data.choices.map((choice) => {
      const messageContent = choice?.message?.content;
      if (typeof messageContent === 'string') return messageContent;
      if (Array.isArray(messageContent)) {
        return messageContent.map((part) => part?.text || part?.content || '').filter(Boolean).join('');
      }
      return choice?.delta?.content || choice?.text || '';
    }).filter(Boolean).join('');
  }
  return '';
}

function extractErrorMessage(data) {
  if (!data || typeof data !== 'object') return '';
  if (typeof data.error === 'string') return data.error;
  if (data.error && typeof data.error === 'object') {
    return data.error.message || data.error.type || JSON.stringify(data.error);
  }
  if (typeof data.message === 'string') return data.message;
  return '';
}

function extractResponseLogDetails(responseData) {
  if (!responseData) return { inputTokens: 0, outputTokens: 0, totalTokens: 0, outputContent: '', errorMessage: '' };

  try {
    const data = JSON.parse(responseData);
    return {
      ...extractTokenUsageDetails(data),
      outputContent: truncateText(extractOutputContent(data)),
      errorMessage: truncateText(extractErrorMessage(data)),
    };
  } catch {
    // Some compatible APIs return usage/content inside SSE data chunks.
  }

  let inputTokens = 0;
  let outputTokens = 0;
  let totalTokens = 0;
  let cacheCreationInputTokens = 0;
  let cacheReadInputTokens = 0;
  let outputContent = '';
  let errorMessage = '';
  for (const line of responseData.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('data: ')) continue;
    const payload = trimmed.slice(6);
    if (!payload || payload === '[DONE]') continue;
    try {
      const data = JSON.parse(payload);
      const usage = extractTokenUsageDetails(data);
      inputTokens = Math.max(inputTokens, usage.inputTokens);
      outputTokens = Math.max(outputTokens, usage.outputTokens);
      totalTokens = Math.max(totalTokens, usage.totalTokens);
      cacheCreationInputTokens = Math.max(cacheCreationInputTokens, usage.cacheCreationInputTokens);
      cacheReadInputTokens = Math.max(cacheReadInputTokens, usage.cacheReadInputTokens);
      outputContent += extractOutputContent(data);
      errorMessage ||= extractErrorMessage(data);
      if (data.type === 'content_block_delta' && data.delta?.text) outputContent += data.delta.text;
      if (data.type === 'message_start') {
        const messageUsage = extractTokenUsageDetails(data.message);
        inputTokens = Math.max(inputTokens, messageUsage.inputTokens);
        cacheCreationInputTokens = Math.max(cacheCreationInputTokens, messageUsage.cacheCreationInputTokens);
        cacheReadInputTokens = Math.max(cacheReadInputTokens, messageUsage.cacheReadInputTokens);
      }
      if (data.type === 'message_delta') outputTokens = Math.max(outputTokens, toTokenNumber(data.usage?.output_tokens));
    } catch {
      // Ignore non-JSON stream lines.
    }
  }
  return {
    inputTokens,
    outputTokens,
    totalTokens: totalTokens || inputTokens + outputTokens,
    cacheCreationInputTokens,
    cacheReadInputTokens,
    outputContent: truncateText(outputContent),
    errorMessage: truncateText(errorMessage),
  };
}

function getClientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.socket.remoteAddress || '';
}

function extractInputContent(data) {
  if (!data || typeof data !== 'object') return '';
  if (Array.isArray(data.messages)) return truncateText(data.messages);
  if (typeof data.prompt === 'string') return truncateText(data.prompt);
  if (typeof data.input === 'string') return truncateText(data.input);
  if (Array.isArray(data.input)) return truncateText(data.input);
  return '';
}

function buildLogContext(req, data = {}) {
  return {
    clientIp: getClientIp(req),
    requestedModel: data.model || '',
    inputContent: extractInputContent(data),
    stream: Boolean(data.stream),
    clientKey: req.clientApiKey || '',
    clientKeyFingerprint: req.clientApiKeyFingerprint || '',
    clientKeyType: req.clientApiKeyType || '',
  };
}

function responseLogFields(context = {}, extra = {}) {
  const fields = { ...extra };
  if (context.clientIp) fields.clientIp = context.clientIp;
  if (context.requestedModel && context.requestedModel !== extra.model) fields.requestedModel = context.requestedModel;
  if (context.inputContent) fields.inputContent = context.inputContent;
  if (context.stream != null) fields.stream = context.stream;
  if (context.clientKeyFingerprint) fields.clientKeyFingerprint = context.clientKeyFingerprint;
  if (context.clientKeyType) fields.clientKeyType = context.clientKeyType;
  if (fields.totalTokens == null && fields.tokens != null) fields.totalTokens = fields.tokens;
  return fields;
}

function requestLogOptions(context = {}, requestId = '', error = null, extra = {}) {
  return {
    error,
    requestId,
    clientIp: context.clientIp || '',
    clientKey: context.clientKey || '',
    clientKeyFingerprint: context.clientKeyFingerprint || '',
    clientKeyType: context.clientKeyType || '',
    ...(context.upstreamKeyFingerprint ? { upstreamKeyFingerprint: context.upstreamKeyFingerprint } : {}),
    ...(context.upstreamKeyIndex != null ? { upstreamKeyIndex: context.upstreamKeyIndex } : {}),
    ...extra,
  };
}

function recordUpstreamKeyUsage(fingerprint = '', details = {}) {
  const key = String(fingerprint || '');
  if (!key) return;
  if (!stats.upstreamKeyUsage) stats.upstreamKeyUsage = {};
  if (!stats.upstreamKeyUsage[key]) {
    stats.upstreamKeyUsage[key] = {
      totalRequests: 0,
      totalErrors: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      lastUsedAt: null,
      lastError: '',
      lastErrorAt: null,
    };
  }
  const usage = stats.upstreamKeyUsage[key];
  const now = new Date().toISOString();
  const success = details.success !== false;
  usage.totalRequests++;
  if (!success) usage.totalErrors++;
  usage.totalInputTokens += toTokenNumber(details.inputTokens);
  usage.totalOutputTokens += toTokenNumber(details.outputTokens);
  usage.lastUsedAt = now;
  usage.lastStatus = Number(details.statusCode) || null;
  if (success) {
    usage.lastError = '';
    usage.lastErrorAt = null;
  } else {
    usage.lastError = String(details.error || 'upstream_error').slice(0, 1000);
    usage.lastErrorAt = now;
  }
}

function saveStats() {
  fs.writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2));
}

function makeUsageBucket() {
  return { count: 0, tokens: 0, cacheHitCount: 0, cacheReadInputTokens: 0, cacheCreationInputTokens: 0 };
}

function addUsageRequest(bucket, tokens, options = {}) {
  bucket.count = (bucket.count || 0) + 1;
  bucket.tokens = (bucket.tokens || 0) + tokens;
  bucket.cacheHitCount = bucket.cacheHitCount || 0;
  bucket.cacheReadInputTokens = bucket.cacheReadInputTokens || 0;
  bucket.cacheCreationInputTokens = bucket.cacheCreationInputTokens || 0;
  const cacheReadInputTokens = toTokenNumber(options.cacheReadInputTokens);
  const cacheCreationInputTokens = toTokenNumber(options.cacheCreationInputTokens);
  if (cacheReadInputTokens > 0) bucket.cacheHitCount++;
  bucket.cacheReadInputTokens += cacheReadInputTokens;
  bucket.cacheCreationInputTokens += cacheCreationInputTokens;
}

function ensureUsageScope(parent, key) {
  if (!parent[key]) parent[key] = { requests: 0, tokens: 0, models: {}, channels: {}, ips: {} };
  if (!parent[key].models) parent[key].models = {};
  if (!parent[key].channels) parent[key].channels = {};
  if (!parent[key].ips) parent[key].ips = {};
  return parent[key];
}

function addUsageToMap(map, key, tokens, options = {}) {
  if (!map[key]) map[key] = makeUsageBucket();
  addUsageRequest(map[key], tokens, options);
}

function addUsageToScope(scope, model, channel, clientIp, tokens, options = {}) {
  scope.requests++;
  scope.tokens += tokens;
  addUsageToMap(scope.models, model, tokens, options);
  addUsageToMap(scope.channels, channel, tokens, options);
  addUsageToMap(scope.ips, clientIp, tokens, options);
}

function applyUsageCacheFromLogs(bucket, logs) {
  if (!bucket || !Array.isArray(logs)) return false;
  if (bucket.cacheReadInputTokens != null && bucket.cacheCreationInputTokens != null && bucket.cacheHitCount != null) return false;
  if (logs.length !== (bucket.count || 0)) return false;
  bucket.cacheReadInputTokens = logs.reduce((sum, entry) => sum + toTokenNumber(entry.cacheReadInputTokens), 0);
  bucket.cacheCreationInputTokens = logs.reduce((sum, entry) => sum + toTokenNumber(entry.cacheCreationInputTokens), 0);
  bucket.cacheHitCount = logs.filter(entry => toTokenNumber(entry.cacheReadInputTokens) > 0).length;
  return true;
}

function backfillUsageGroupCache(group = {}, logs = [], field) {
  let changed = false;
  for (const [key, bucket] of Object.entries(group || {})) {
    changed = applyUsageCacheFromLogs(bucket, logs.filter(entry => entry[field] === key)) || changed;
  }
  return changed;
}

function backfillUsageScopeCache(scope = {}, logs = []) {
  return [
    backfillUsageGroupCache(scope.models, logs, 'model'),
    backfillUsageGroupCache(scope.channels, logs, 'channel'),
    backfillUsageGroupCache(scope.ips, logs, 'clientIp'),
  ].some(Boolean);
}

function backfillUsageCacheFromRecentLogs() {
  const recentLogs = Array.isArray(stats.recentLogs) ? stats.recentLogs : [];
  let changed = false;

  changed = backfillUsageGroupCache(stats.modelUsage, recentLogs, 'model') || changed;
  changed = backfillUsageGroupCache(stats.channelUsage, recentLogs, 'channel') || changed;
  changed = backfillUsageGroupCache(stats.ipUsage, recentLogs, 'clientIp') || changed;
  for (const [date, day] of Object.entries(stats.dailyStats || {})) {
    const dayLogs = recentLogs.filter(entry => {
      if (!entry.timestamp) return false;
      return new Date(entry.timestamp).toISOString().slice(0, 10) === date;
    });
    changed = backfillUsageScopeCache(day, dayLogs) || changed;
  }

  for (const [hour, bucket] of Object.entries(stats.hourlyStats || {})) {
    const hourLogs = recentLogs.filter(entry => {
      if (!entry.timestamp) return false;
      return new Date(entry.timestamp).toISOString().slice(0, 13) === hour;
    });
    changed = backfillUsageScopeCache(bucket, hourLogs) || changed;
  }

  if (changed) saveStats();
}

function backfillHourlyStatsFromRecentLogs() {
  if (Object.keys(stats.hourlyStats || {}).length > 0) return;
  const recentLogs = Array.isArray(stats.recentLogs) ? stats.recentLogs : [];
  for (const entry of recentLogs) {
    if (!entry.timestamp) continue;
    const hour = new Date(entry.timestamp).toISOString().slice(0, 13);
    const model = entry.model || 'unknown';
    const channel = entry.channel || 'unknown';
    const clientIp = entry.clientIp || 'unknown';
    const tokens = toTokenNumber(entry.tokens);
    addUsageToScope(ensureUsageScope(stats.hourlyStats, hour), model, channel, clientIp, tokens, {
      cacheReadInputTokens: entry.cacheReadInputTokens,
      cacheCreationInputTokens: entry.cacheCreationInputTokens,
    });
  }
  if (recentLogs.length) saveStats();
}

function backfillUpstreamKeyUsageFromRecentLogs() {
  if (Object.keys(stats.upstreamKeyUsage || {}).length > 0) return;
  stats.upstreamKeyUsage = {};
  for (const entry of stats.recentLogs || []) {
    const fingerprint = String(entry.upstreamKeyFingerprint || '');
    if (!fingerprint) continue;
    if (!stats.upstreamKeyUsage[fingerprint]) {
      stats.upstreamKeyUsage[fingerprint] = {
        totalRequests: 0,
        totalErrors: 0,
        totalInputTokens: 0,
        totalOutputTokens: 0,
        lastUsedAt: null,
        lastError: '',
        lastErrorAt: null,
      };
    }
    const keyUsage = stats.upstreamKeyUsage[fingerprint];
    keyUsage.totalRequests++;
    if (entry.success === false) keyUsage.totalErrors++;
    keyUsage.totalInputTokens += toTokenNumber(entry.inputTokens);
    keyUsage.totalOutputTokens += toTokenNumber(entry.outputTokens);
    if (!keyUsage.lastUsedAt || String(entry.timestamp || '') > keyUsage.lastUsedAt) {
      keyUsage.lastUsedAt = entry.timestamp || null;
      keyUsage.lastError = entry.success === false ? String(entry.error || '') : '';
      keyUsage.lastErrorAt = entry.success === false ? entry.timestamp || null : null;
    }
  }
  if ((stats.recentLogs || []).length) saveStats();
}

function recordUpstreamKeyTest(fingerprint = '', details = {}) {
  const key = String(fingerprint || '');
  if (!key) return;
  if (!stats.upstreamKeyUsage) stats.upstreamKeyUsage = {};
  if (!stats.upstreamKeyUsage[key]) {
    stats.upstreamKeyUsage[key] = {
      totalRequests: 0,
      totalErrors: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      lastUsedAt: null,
      lastError: '',
      lastErrorAt: null,
    };
  }
  const usage = stats.upstreamKeyUsage[key];
  const now = new Date().toISOString();
  const success = details.success === true;
  usage.lastTestAt = now;
  usage.lastTestStatus = Number(details.statusCode) || null;
  usage.lastTestPassed = success;
  if (success) {
    usage.lastError = '';
    usage.lastErrorAt = null;
  } else {
    usage.lastError = String(details.error || 'test_failed').slice(0, 1000);
    usage.lastErrorAt = now;
  }
  saveStats();
}

function recordClientKeyUsage(fingerprint = '', details = {}) {
  const key = String(fingerprint || '');
  if (!key) return;
  if (!stats.clientKeyUsage) stats.clientKeyUsage = {};
  if (!stats.clientKeyUsage[key]) {
    stats.clientKeyUsage[key] = {
      totalRequests: 0,
      totalErrors: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      lastUsedAt: null,
      lastStatus: null,
      byChannel: {},
    };
  }
  const usage = stats.clientKeyUsage[key];
  if (!usage.byChannel || typeof usage.byChannel !== 'object') usage.byChannel = {};
  const now = new Date().toISOString();
  usage.totalRequests++;
  if (!details.success) usage.totalErrors++;
  usage.totalInputTokens += toTokenNumber(details.inputTokens);
  usage.totalOutputTokens += toTokenNumber(details.outputTokens);
  usage.lastUsedAt = now;
  usage.lastStatus = Number(details.statusCode) || null;

  // 同一调用 Key 按渠道拆分统计，便于区分不同项目/渠道的用量
  const channel = String(details.channel || 'unknown');
  if (!usage.byChannel[channel]) {
    usage.byChannel[channel] = {
      totalRequests: 0,
      totalErrors: 0,
      totalInputTokens: 0,
      totalOutputTokens: 0,
      lastUsedAt: null,
      lastStatus: null,
    };
  }
  const chUsage = usage.byChannel[channel];
  chUsage.totalRequests++;
  if (!details.success) chUsage.totalErrors++;
  chUsage.totalInputTokens += toTokenNumber(details.inputTokens);
  chUsage.totalOutputTokens += toTokenNumber(details.outputTokens);
  chUsage.lastUsedAt = now;
  chUsage.lastStatus = Number(details.statusCode) || null;
}

function logRequest(model, channel, tokens = 0, success = true, error = null) {
  const options = error && typeof error === 'object' && !Array.isArray(error)
    ? error
    : { error };
  error = options.error ?? null;
  tokens = toTokenNumber(tokens);
  const cacheReadInputTokens = toTokenNumber(options.cacheReadInputTokens);
  const cacheCreationInputTokens = toTokenNumber(options.cacheCreationInputTokens);
  const cacheHit = cacheReadInputTokens > 0;
  const inputTokens = toTokenNumber(options.inputTokens);
  const outputTokens = toTokenNumber(options.outputTokens);
  const now = new Date();
  const isoTime = now.toISOString();
  const date = isoTime.slice(0, 10);
  const hour = isoTime.slice(0, 13);
  const time = now.toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai' });

  // 更新总计数
  stats.totalRequests++;

  // 更新模型使用统计
  if (!stats.modelUsage[model]) {
    stats.modelUsage[model] = makeUsageBucket();
  }
  addUsageRequest(stats.modelUsage[model], tokens, { cacheReadInputTokens, cacheCreationInputTokens });

  // 更新渠道使用统计
  if (!stats.channelUsage[channel]) {
    stats.channelUsage[channel] = makeUsageBucket();
  }
  addUsageRequest(stats.channelUsage[channel], tokens, { cacheReadInputTokens, cacheCreationInputTokens });

  // 更新 IP 使用统计
  const clientIp = options.clientIp || 'unknown';
  if (!stats.ipUsage) stats.ipUsage = {};
  if (!stats.ipUsage[clientIp]) {
    stats.ipUsage[clientIp] = makeUsageBucket();
  }
  addUsageRequest(stats.ipUsage[clientIp], tokens, { cacheReadInputTokens, cacheCreationInputTokens });

  // 更新每日和每小时统计
  addUsageToScope(ensureUsageScope(stats.dailyStats, date), model, channel, clientIp, tokens, { cacheReadInputTokens, cacheCreationInputTokens });
  addUsageToScope(ensureUsageScope(stats.hourlyStats, hour), model, channel, clientIp, tokens, { cacheReadInputTokens, cacheCreationInputTokens });

  recordUpstreamKeyUsage(options.upstreamKeyFingerprint, {
    success,
    error,
    statusCode: options.statusCode,
    inputTokens,
    outputTokens,
  });
  recordClientKeyUsage(options.clientKeyFingerprint, {
    success,
    statusCode: options.statusCode,
    inputTokens,
    outputTokens,
    channel,
  });

  // 添加到最近日志（保留最近100条）
  const logEntry = {
    timestamp: now.toISOString(),
    time: time,
    model: model,
    channel: channel,
    tokens: tokens,
    success: success,
    error: error,
    clientIp,
    cacheHit,
    cacheReadInputTokens,
    cacheCreationInputTokens,
    inputTokens,
    outputTokens,
    ...(options.clientKeyFingerprint ? { clientKeyFingerprint: options.clientKeyFingerprint } : {}),
    ...(options.clientKeyType ? { clientKeyType: options.clientKeyType } : {}),
    ...(options.upstreamKeyFingerprint ? { upstreamKeyFingerprint: options.upstreamKeyFingerprint } : {}),
    ...(options.upstreamKeyIndex != null ? { upstreamKeyIndex: options.upstreamKeyIndex } : {}),
  };

  stats.recentLogs.unshift(logEntry);
  if (stats.recentLogs.length > 100) {
    stats.recentLogs = stats.recentLogs.slice(0, 100);
  }

  // 控制台输出
  console.log(`[${time}] ${success ? '✓' : '✗'} ${model} (${channel}) - ${tokens} tokens${error ? ` - ${error}` : ''}`);

  // 定期保存（每10次请求保存一次）
  if (stats.totalRequests % 10 === 0) {
    saveStats();
  }
}


export {
  ensureLogDir,
  currentLogFile,
  sanitizeHeaders,
  truncateText,
  writeGatewayLog,
  readVisibleGatewayLogs,
  clearCurrentGatewayLog,
  newRequestId,
  fingerprintKey,
  toTokenNumber,
  extractTokenUsageDetails,
  extractOutputContent,
  extractErrorMessage,
  extractResponseLogDetails,
  getClientIp,
  extractInputContent,
  buildLogContext,
  responseLogFields,
  requestLogOptions,
  recordUpstreamKeyUsage,
  saveStats,
  makeUsageBucket,
  addUsageRequest,
  ensureUsageScope,
  addUsageToMap,
  addUsageToScope,
  applyUsageCacheFromLogs,
  backfillUsageGroupCache,
  backfillUsageScopeCache,
  backfillUsageCacheFromRecentLogs,
  backfillHourlyStatsFromRecentLogs,
  backfillUpstreamKeyUsageFromRecentLogs,
  recordUpstreamKeyTest,
  logRequest,
};
