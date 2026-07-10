import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import {
  stats, LOG_DIR, LOG_MAX_BODY_CHARS, HIDDEN_UI_LOG_EVENTS, STATS_FILE,
} from './state.mjs';

function ensureLogDir() {
  if (!fs.existsSync(LOG_DIR)) {
    fs.mkdirSync(LOG_DIR, { recursive: true });
  }
}

function currentLogFile() {
  const date = new Date().toISOString().split('T')[0];
  return path.join(LOG_DIR, `gateway-${date}.log`);
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
    fs.appendFileSync(currentLogFile(), `${JSON.stringify(entry)}\n`);
  } catch (err) {
    console.error('[log] failed to write gateway log:', err.message);
  }
}

function readVisibleGatewayLogs(limit = 100) {
  try {
    const file = currentLogFile();
    if (!fs.existsSync(file)) return [];
    const lines = fs.readFileSync(file, 'utf-8').trim().split('\n').filter(Boolean);
    const logs = [];
    for (let i = lines.length - 1; i >= 0 && logs.length < limit; i--) {
      let entry;
      try {
        entry = JSON.parse(lines[i]);
      } catch {
        entry = { timestamp: null, event: 'parse_error', raw: truncateText(lines[i]) };
      }
      if (!HIDDEN_UI_LOG_EVENTS.has(entry.event)) {
        logs.push(entry);
      }
    }
    return logs;
  } catch (err) {
    return [{ timestamp: new Date().toISOString(), event: 'read_error', error: err.message }];
  }
}

function clearCurrentGatewayLog() {
  ensureLogDir();
  fs.writeFileSync(currentLogFile(), '');
}

function newRequestId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function fingerprintKey(key = '') {
  if (!key) return '';
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 12);
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
