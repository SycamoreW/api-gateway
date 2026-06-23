import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';

const CONFIG_FILE = path.resolve(process.argv[2] || 'config.json');
const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
if (!Array.isArray(config.api_keys)) config.api_keys = [];
const LOG_DIR = path.resolve('logs');
const LOG_MAX_BODY_CHARS = 2000;
const HIDDEN_UI_LOG_EVENTS = new Set(['http_request', 'model_params', 'model_routed']);
const channelKeyCursors = new Map();

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

function extractTokenUsageFromResponse(responseData) {
  return extractResponseLogDetails(responseData).totalTokens;
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
    ...extra,
  };
}

function normalizeKeyList(keys = []) {
  const seen = new Set();
  const result = [];
  for (const key of keys) {
    const normalized = String(key || '').trim();
    if (!normalized || seen.has(normalized)) continue;
    seen.add(normalized);
    result.push(normalized);
  }
  return result;
}

function getChannelKeys(channel = {}) {
  return normalizeKeyList([
    channel.key,
    ...(Array.isArray(channel.keys) ? channel.keys : []),
  ]);
}

function getChannelKeyCount(channel = {}) {
  return getChannelKeys(channel).length;
}

function selectChannelKey(channel = {}, channelKey = '') {
  const keys = getChannelKeys(channel);
  if (keys.length === 0) return { key: '', index: -1, count: 0, fingerprint: '' };
  const cursorKey = channelKey || channel.name || channel.base_url || 'default';
  const cursor = channelKeyCursors.get(cursorKey) || 0;
  const index = cursor % keys.length;
  channelKeyCursors.set(cursorKey, (index + 1) % keys.length);
  return {
    key: keys[index],
    index,
    count: keys.length,
    fingerprint: fingerprintKey(keys[index]),
  };
}

async function fetchPioneerBilling(key) {
  return new Promise((resolve, reject) => {
    const billingReq = https.request('https://api.pioneer.ai/billing/billing-status', {
      method: 'GET',
      headers: { 'X-API-Key': key },
    }, (r) => {
      let data = '';
      r.on('data', c => data += c);
      r.on('end', () => {
        if (r.statusCode >= 200 && r.statusCode < 300) {
          try { resolve(JSON.parse(data)); } catch (e) { reject(new Error('Pioneer API 返回非 JSON')); }
        } else {
          reject(new Error(`Pioneer API error: ${r.statusCode} ${data}`));
        }
      });
    });
    billingReq.on('error', reject);
    billingReq.setTimeout(10000, () => {
      billingReq.destroy();
      reject(new Error('Pioneer API timeout'));
    });
    billingReq.end();
  });
}

function toMoneyNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) ? number : 0;
}

function summarizePioneerBilling(items = []) {
  const successful = items.filter(item => item.ok && item.billing);
  const totalUsage = successful.reduce((sum, item) => sum + toMoneyNumber(item.billing.total_usage), 0);
  const freeTierRemaining = successful.reduce((sum, item) => sum + toMoneyNumber(item.billing.free_tier_remaining), 0);
  const exceedsFreeTier = successful.some(item => Boolean(item.billing.exceeds_free_tier));
  return {
    total_usage: totalUsage,
    free_tier_remaining: freeTierRemaining,
    exceeds_free_tier: exceedsFreeTier,
    key_count: items.length,
    successful_key_count: successful.length,
    failed_key_count: items.length - successful.length,
    items,
  };
}

function normalizeChannelForSave(channel = {}) {
  const keys = getChannelKeys(channel);
  const next = { ...channel };
  if (next.prompt_cache_enabled) {
    next.prompt_cache_ttl = normalizePromptCacheTtl(next.prompt_cache_ttl);
  } else {
    delete next.prompt_cache_ttl;
  }
  if (keys.length > 0) {
    next.key = keys[0];
    if (keys.length > 1) next.keys = keys;
    else delete next.keys;
  } else {
    next.key = '';
    delete next.keys;
  }
  return next;
}

function normalizePromptCacheTtl(ttl = '') {
  return String(ttl || '').trim() === '1h' ? '1h' : '5m';
}

function writeAccessLog(req, res, event, fields = {}) {
  writeGatewayLog(event, {
    requestId: fields.requestId,
    method: req.method,
    url: req.url,
    clientIp: getClientIp(req),
    statusCode: fields.statusCode,
    ...fields,
  });
}

// 初始化统计文件
const STATS_FILE = path.resolve('stats.json');
let stats = {};
if (fs.existsSync(STATS_FILE)) {
  stats = JSON.parse(fs.readFileSync(STATS_FILE, 'utf-8'));
} else {
  stats = {
    totalRequests: 0,
    modelUsage: {},
    channelUsage: {},
    ipUsage: {},
    dailyStats: {},
    recentLogs: []
  };
}

// 保存统计数据
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

function applyUsageCacheFromLogs(bucket, logs) {
  if (!bucket || !Array.isArray(logs)) return false;
  if (bucket.cacheReadInputTokens != null && bucket.cacheCreationInputTokens != null && bucket.cacheHitCount != null) return false;
  if (logs.length !== (bucket.count || 0)) return false;
  bucket.cacheReadInputTokens = logs.reduce((sum, entry) => sum + toTokenNumber(entry.cacheReadInputTokens), 0);
  bucket.cacheCreationInputTokens = logs.reduce((sum, entry) => sum + toTokenNumber(entry.cacheCreationInputTokens), 0);
  bucket.cacheHitCount = logs.filter(entry => toTokenNumber(entry.cacheReadInputTokens) > 0).length;
  return true;
}

function backfillUsageCacheFromRecentLogs() {
  const recentLogs = Array.isArray(stats.recentLogs) ? stats.recentLogs : [];
  let changed = false;

  for (const [model, bucket] of Object.entries(stats.modelUsage || {})) {
    changed = applyUsageCacheFromLogs(bucket, recentLogs.filter(entry => entry.model === model)) || changed;
  }
  for (const [channel, bucket] of Object.entries(stats.channelUsage || {})) {
    changed = applyUsageCacheFromLogs(bucket, recentLogs.filter(entry => entry.channel === channel)) || changed;
  }
  for (const [ip, bucket] of Object.entries(stats.ipUsage || {})) {
    changed = applyUsageCacheFromLogs(bucket, recentLogs.filter(entry => entry.clientIp === ip)) || changed;
  }
  for (const [date, day] of Object.entries(stats.dailyStats || {})) {
    const dayLogs = recentLogs.filter(entry => {
      if (!entry.timestamp) return false;
      return new Date(entry.timestamp).toISOString().slice(0, 10) === date;
    });
    for (const [model, bucket] of Object.entries(day.models || {})) {
      changed = applyUsageCacheFromLogs(bucket, dayLogs.filter(entry => entry.model === model)) || changed;
    }
    for (const [channel, bucket] of Object.entries(day.channels || {})) {
      changed = applyUsageCacheFromLogs(bucket, dayLogs.filter(entry => entry.channel === channel)) || changed;
    }
    for (const [ip, bucket] of Object.entries(day.ips || {})) {
      changed = applyUsageCacheFromLogs(bucket, dayLogs.filter(entry => entry.clientIp === ip)) || changed;
    }
  }

  if (changed) saveStats();
}

backfillUsageCacheFromRecentLogs();

// 记录访问日志
function logRequest(model, channel, tokens = 0, success = true, error = null) {
  const options = error && typeof error === 'object' && !Array.isArray(error)
    ? error
    : { error };
  error = options.error ?? null;
  tokens = toTokenNumber(tokens);
  const cacheReadInputTokens = toTokenNumber(options.cacheReadInputTokens);
  const cacheCreationInputTokens = toTokenNumber(options.cacheCreationInputTokens);
  const cacheHit = cacheReadInputTokens > 0;
  const now = new Date();
  const date = now.toISOString().split('T')[0];
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
  
  // 更新每日统计
  if (!stats.dailyStats[date]) {
    stats.dailyStats[date] = { requests: 0, tokens: 0, models: {}, channels: {}, ips: {} };
  }
  if (!stats.dailyStats[date].models) stats.dailyStats[date].models = {};
  if (!stats.dailyStats[date].channels) stats.dailyStats[date].channels = {};
  if (!stats.dailyStats[date].ips) stats.dailyStats[date].ips = {};
  stats.dailyStats[date].requests++;
  stats.dailyStats[date].tokens += tokens;
  if (!stats.dailyStats[date].models[model]) {
    stats.dailyStats[date].models[model] = makeUsageBucket();
  }
  addUsageRequest(stats.dailyStats[date].models[model], tokens, { cacheReadInputTokens, cacheCreationInputTokens });
  if (!stats.dailyStats[date].channels[channel]) {
    stats.dailyStats[date].channels[channel] = makeUsageBucket();
  }
  addUsageRequest(stats.dailyStats[date].channels[channel], tokens, { cacheReadInputTokens, cacheCreationInputTokens });
  if (!stats.dailyStats[date].ips[clientIp]) {
    stats.dailyStats[date].ips[clientIp] = makeUsageBucket();
  }
  addUsageRequest(stats.dailyStats[date].ips[clientIp], tokens, { cacheReadInputTokens, cacheCreationInputTokens });
  
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
    ...(options.clientKeyFingerprint ? { clientKeyFingerprint: options.clientKeyFingerprint } : {}),
    ...(options.clientKeyType ? { clientKeyType: options.clientKeyType } : {}),
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

const SERVE_UI = fs.existsSync(path.resolve('ui.html'));

// Build model -> channel mapping
const modelMap = new Map(); // modelName -> { channelKey, upstreamModel }
function rebuildModelMap() {
  modelMap.clear();
  for (const [ckey, ch] of Object.entries(config.channels)) {
    const overrides = (ch && typeof ch.model_overrides === 'object' && ch.model_overrides) || {};
    for (const m of ch.models) {
      // Allow per-channel model_overrides to rewrite the upstream model id.
      // Example: { "pioneer/auto": "pio/claude-opus-4-7" } makes inbound
      // `pioneer/auto` resolve to the same channel but forward `claude-opus-4-7`
      // (after stripModelPrefix) to the upstream provider.
      const override = Object.prototype.hasOwnProperty.call(overrides, m) ? overrides[m] : null;
      const upstreamModel = (typeof override === 'string' && override.trim()) ? override.trim() : m;
      modelMap.set(m, { channelKey: ckey, upstreamModel });
    }
  }

}
rebuildModelMap();

function normalizeStringArray(value) {
  const items = Array.isArray(value) ? value : [];
  return [...new Set(items.map(item => String(item || '').trim()).filter(Boolean))];
}

function normalizeExpiresAt(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  const time = Date.parse(raw);
  if (!Number.isFinite(time)) return '';
  return new Date(time).toISOString();
}

function normalizeClientKeyEntry(entry) {
  if (typeof entry === 'string') {
    const key = entry.trim();
    return key ? {
      key,
      name: '',
      allowed_channels: [],
      allowed_models: [],
      quota_limit: 0,
      quota_used: 0,
      expires_at: '',
      enabled: true,
    } : null;
  }
  if (!entry || typeof entry !== 'object' || Array.isArray(entry)) return null;
  const key = String(entry.key || '').trim();
  if (!key) return null;
  const quotaLimit = Math.max(0, Math.floor(Number(entry.quota_limit) || 0));
  const quotaUsed = Math.max(0, Math.floor(Number(entry.quota_used) || 0));
  return {
    key,
    name: String(entry.name || '').trim(),
    allowed_channels: normalizeStringArray(entry.allowed_channels),
    allowed_models: normalizeStringArray(entry.allowed_models),
    quota_limit: quotaLimit,
    quota_used: quotaUsed,
    expires_at: normalizeExpiresAt(entry.expires_at),
    enabled: entry.enabled !== false,
  };
}

function getClientKeyEntries() {
  return (Array.isArray(config.api_keys) ? config.api_keys : [])
    .map(normalizeClientKeyEntry)
    .filter(Boolean);
}

function saveClientKeyEntries(entries) {
  config.api_keys = entries.map(entry => ({
    key: entry.key,
    ...(entry.name ? { name: entry.name } : {}),
    ...(entry.allowed_channels?.length ? { allowed_channels: entry.allowed_channels } : {}),
    ...(entry.allowed_models?.length ? { allowed_models: entry.allowed_models } : {}),
    ...(entry.quota_limit > 0 ? { quota_limit: entry.quota_limit } : {}),
    ...(entry.quota_used > 0 ? { quota_used: entry.quota_used } : {}),
    ...(entry.expires_at ? { expires_at: entry.expires_at } : {}),
    ...(entry.enabled === false ? { enabled: false } : {}),
  }));
}

function findClientKeyEntry(token) {
  return getClientKeyEntries().find(entry => entry.key === token) || null;
}

function isClientKeyExpired(entry = {}) {
  if (!entry.expires_at) return false;
  const time = Date.parse(entry.expires_at);
  return Number.isFinite(time) && time <= Date.now();
}

function clientCanUseChannel(req, channelKey = '') {
  if (req.clientApiKeyType === 'admin') return true;
  const allowedChannels = req.clientAllowedChannels || [];
  if (allowedChannels.length === 0) return true;
  return allowedChannels.includes(channelKey);
}

function clientCanUseModel(req, modelName = '', channelKey = '') {
  if (!clientCanUseChannel(req, channelKey)) return false;
  if (req.clientApiKeyType === 'admin') return true;
  const allowedModels = req.clientAllowedModels || [];
  if (allowedModels.length === 0) return true;
  return allowedModels.includes(modelName);
}

function getAccessibleModelEntries(req) {
  return [...modelMap.entries()].filter(([model, entry]) => clientCanUseModel(req, model, entry.channelKey));
}

function getModelQuotaCost(modelName = '') {
  return 1;
}

function consumeClientQuota(req, modelName = '') {
  if (req.clientApiKeyType === 'admin') return { ok: true, cost: 0, remaining: Infinity };
  const entries = getClientKeyEntries();
  const index = entries.findIndex(entry => entry.key === req.clientApiKey);
  if (index < 0) return { ok: false, statusCode: 401, message: 'Invalid API key' };

  const entry = entries[index];
  const cost = getModelQuotaCost(modelName);
  const limit = Math.max(0, Math.floor(Number(entry.quota_limit) || 0));
  const used = Math.max(0, Math.floor(Number(entry.quota_used) || 0));
  if (limit > 0 && used + cost > limit) {
    return {
      ok: false,
      statusCode: 429,
      message: `Quota exceeded: need ${cost}, remaining ${Math.max(0, limit - used)}`,
      cost,
      limit,
      used,
      remaining: Math.max(0, limit - used),
    };
  }

  if (limit > 0) {
    entries[index] = { ...entry, quota_used: used + cost };
    saveClientKeyEntries(entries);
    saveConfig();
  }
  return {
    ok: true,
    cost,
    limit,
    used: limit > 0 ? used + cost : used,
    remaining: limit > 0 ? Math.max(0, limit - used - cost) : Infinity,
  };
}

function getBearerToken(req) {
  const authHeader = String(req.headers['authorization'] || '');
  return authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
}

function rejectAuth(req, res, message = 'Invalid API key', type = 'auth_error') {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message, type } }));
    writeGatewayLog('request_complete', {
      requestId: res.getHeader('X-Request-Id') || '',
      method: req.method,
      url: req.url,
      clientIp: getClientIp(req),
      statusCode: 401,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      errorMessage: message,
    });
    return false;
}

function adminAuth(req, res) {
  if (getBearerToken(req) !== config.api_key) {
    return rejectAuth(req, res);
  }
  req.clientApiKey = config.api_key;
  req.clientApiKeyFingerprint = fingerprintKey(config.api_key);
  req.clientApiKeyType = 'admin';
  req.clientAllowedChannels = [];
  req.clientAllowedModels = [];
  return true;
}

function clientAuth(req, res) {
  const token = getBearerToken(req);
  if (token === config.api_key) {
    req.clientApiKey = token;
    req.clientApiKeyFingerprint = fingerprintKey(token);
    req.clientApiKeyType = 'admin';
    req.clientAllowedChannels = [];
    req.clientAllowedModels = [];
    return true;
  }
  const clientKeyEntry = findClientKeyEntry(token);
  if (!clientKeyEntry) {
    return rejectAuth(req, res);
  }
  if (clientKeyEntry.enabled === false) {
    return rejectAuth(req, res, 'API key disabled', 'auth_error');
  }
  if (isClientKeyExpired(clientKeyEntry)) {
    return rejectAuth(req, res, 'API key expired', 'auth_error');
  }
  req.clientApiKey = token;
  req.clientApiKeyFingerprint = fingerprintKey(token);
  req.clientApiKeyType = 'generated';
  req.clientKeyName = clientKeyEntry.name;
  req.clientAllowedChannels = clientKeyEntry.allowed_channels || [];
  req.clientAllowedModels = clientKeyEntry.allowed_models || [];
  return true;
}

function escapeRegExp(value = '') {
  return String(value).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function stripModelPrefix(modelName = '', channelKey = '') {
  const model = String(modelName || '');
  const prefix = String(channelKey || '').trim();
  if (!prefix) return model;
  const escapedPrefix = escapeRegExp(prefix);
  // Only remove this gateway's own wrapper. Upstream model names may already
  // start with provider tags such as [云愿] or [max], and those must be kept.
  return model
    .replace(new RegExp(`^\\[${escapedPrefix}\\]`), '')
    .replace(new RegExp(`^${escapedPrefix}/`, 'i'), '');
}

function convertOpenAIContentToAnthropic(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return content;
  return content.map((part) => {
    if (typeof part === 'string') return { type: 'text', text: part };
    if (part?.type === 'text') return { ...part, text: part.text || '' };
    return part;
  });
}

function normalizeOpenAIFinishReason(reason) {
  if (!reason) return 'stop';
  const value = String(reason);
  if (value === 'end_turn' || value === 'stop_sequence') return 'stop';
  if (value === 'max_tokens') return 'length';
  if (value === 'tool_use') return 'tool_calls';
  return value;
}

function convertOpenAIToolsToAnthropic(tools) {
  if (!Array.isArray(tools)) return undefined;
  const converted = [];
  for (const tool of tools) {
    const fn = tool?.type === 'function' ? tool.function : tool;
    const name = fn?.name;
    if (!name) continue;
    converted.push({
      name,
      description: fn.description || '',
      input_schema: fn.parameters && typeof fn.parameters === 'object'
        ? fn.parameters
        : { type: 'object', properties: {} },
    });
  }
  return converted.length > 0 ? converted : undefined;
}

function convertOpenAIToolChoiceToAnthropic(toolChoice) {
  if (!toolChoice || toolChoice === 'auto') return { type: 'auto' };
  if (toolChoice === 'none') return { type: 'none' };
  if (toolChoice === 'required') return { type: 'any' };
  const name = toolChoice?.function?.name || toolChoice?.name;
  if (name) return { type: 'tool', name };
  return undefined;
}

function stringifyToolResultContent(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  return JSON.stringify(content);
}

function convertOpenAIMessageToAnthropicContent(message) {
  const content = [];
  const convertedContent = convertOpenAIContentToAnthropic(message.content);
  if (Array.isArray(convertedContent)) {
    content.push(...convertedContent);
  } else if (convertedContent) {
    content.push({ type: 'text', text: String(convertedContent) });
  }

  if (Array.isArray(message.tool_calls)) {
    for (const call of message.tool_calls) {
      if (call?.type && call.type !== 'function') continue;
      const name = call?.function?.name || call?.name;
      if (!name) continue;
      let input = {};
      const rawArgs = call?.function?.arguments ?? call?.input;
      if (typeof rawArgs === 'string' && rawArgs.trim()) {
        try { input = JSON.parse(rawArgs); } catch { input = { _raw: rawArgs }; }
      } else if (rawArgs && typeof rawArgs === 'object') {
        input = rawArgs;
      }
      content.push({
        type: 'tool_use',
        id: call.id || `toolu_${newRequestId()}`,
        name,
        input,
      });
    }
  }

  return content.length > 0 ? content : '';
}

function buildPromptCacheControl(ttl = '') {
  const cacheControl = { type: 'ephemeral' };
  if (ttl === '1h') cacheControl.ttl = '1h';
  return cacheControl;
}

function getPromptCacheControl(data = {}, channel = {}) {
  return data.cache_control && typeof data.cache_control === 'object'
    ? data.cache_control
    : buildPromptCacheControl(channel.prompt_cache_ttl);
}

function getAnthropicBetaHeader(channel = {}) {
  if (channel.anthropic_beta) return String(channel.anthropic_beta);
  if (channel.prompt_cache_enabled && channel.prompt_cache_ttl === '1h') {
    return 'extended-cache-ttl-2025-04-11';
  }
  return '';
}

function contentPartHasPromptCache(part) {
  return part && typeof part === 'object' && part.cache_control && typeof part.cache_control === 'object';
}

function messageHasPromptCache(message) {
  if (!message || typeof message !== 'object') return false;
  if (message.cache_control && typeof message.cache_control === 'object') return true;
  const content = message.content;
  if (Array.isArray(content)) return content.some(contentPartHasPromptCache);
  return false;
}

function withPromptCacheOnContent(content, cacheControl) {
  if (Array.isArray(content)) {
    for (let i = content.length - 1; i >= 0; i--) {
      const part = content[i];
      if (typeof part === 'string') {
        const next = [...content];
        next[i] = { type: 'text', text: part, cache_control: cacheControl };
        return next;
      }
      if (part && typeof part === 'object' && (part.type === 'text' || typeof part.text === 'string')) {
        const next = [...content];
        next[i] = { ...part, cache_control: cacheControl };
        return next;
      }
    }
    return [...content, { type: 'text', text: '', cache_control: cacheControl }];
  }
  if (typeof content === 'string') return [{ type: 'text', text: content, cache_control: cacheControl }];
  return content;
}

function systemHasPromptCache(system) {
  if (Array.isArray(system)) return system.some(contentPartHasPromptCache);
  return false;
}

function withPromptCacheOnSystem(system, cacheControl) {
  if (Array.isArray(system)) return withPromptCacheOnContent(system, cacheControl);
  if (typeof system === 'string') return [{ type: 'text', text: system, cache_control: cacheControl }];
  return system;
}

function applyOpenAICompatiblePromptCache(data, channel = {}) {
  if (!data || typeof data !== 'object') return data;
  if (!channel.prompt_cache_enabled || !Array.isArray(data.messages)) return data;
  if (data.messages.some(messageHasPromptCache)) return data;
  const cacheControl = getPromptCacheControl(data, channel);
  const messages = [...data.messages];
  let targetIndex = -1;
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i];
    if (!message || typeof message !== 'object') continue;
    if (message.role === 'user' && i === messages.length - 1) continue;
    if (typeof message.content === 'string' || Array.isArray(message.content)) {
      targetIndex = i;
      break;
    }
  }
  if (targetIndex < 0) return data;
  messages[targetIndex] = {
    ...messages[targetIndex],
    content: withPromptCacheOnContent(messages[targetIndex].content, cacheControl),
  };
  const { cache_control, ...rest } = data;
  return {
    ...rest,
    messages,
  };
}

function applyAnthropicPromptCache(payload, data, channel = {}) {
  if (!channel.prompt_cache_enabled) return payload;
  if (systemHasPromptCache(payload.system) || payload.messages?.some(messageHasPromptCache)) return payload;

  const cacheControl = getPromptCacheControl(data, channel);
  let next = { ...payload };

  // 断点1：system 是最稳定的前缀，永远优先缓存（修复：之前大 system 场景常常完全不缓存）
  if (next.system) {
    next = { ...next, system: withPromptCacheOnSystem(next.system, cacheControl) };
  }

  // 断点2：在最后一条消息上再打一个，让滚动的对话历史也能命中
  // （Anthropic 允许最多 4 个 cache breakpoint，system + 末条消息合规）
  const messages = Array.isArray(next.messages) ? [...next.messages] : [];
  let targetIndex = -1;
  for (let i = messages.length - 1; i >= 0; i--) {
    const message = messages[i];
    if (!message || typeof message !== 'object') continue;
    if (typeof message.content === 'string' || Array.isArray(message.content)) {
      targetIndex = i;
      break;
    }
  }
  if (targetIndex >= 0) {
    messages[targetIndex] = {
      ...messages[targetIndex],
      content: withPromptCacheOnContent(messages[targetIndex].content, cacheControl),
    };
    next = { ...next, messages };
  }

  return next;
}

function toPositiveInteger(value, fallback = 0) {
  const number = Number(value);
  return Number.isInteger(number) && number > 0 ? number : fallback;
}

function applyAnthropicThinking(payload, data, channel = {}) {
  if (data.output_config && typeof data.output_config === 'object') {
    payload.output_config = data.output_config;
  }

  if (data.thinking && typeof data.thinking === 'object') {
    payload.thinking = data.thinking;
  } else if (channel.anthropic_thinking_type === 'enabled') {
    const budgetTokens = toPositiveInteger(channel.anthropic_thinking_budget_tokens, 32000);
    payload.thinking = { type: 'enabled', budget_tokens: budgetTokens };
    if (payload.max_tokens <= budgetTokens) {
      payload.max_tokens = budgetTokens + 1024;
    }
  } else if (channel.anthropic_thinking_type === 'adaptive') {
    payload.thinking = { type: 'adaptive' };
    if (channel.anthropic_thinking_display) {
      payload.thinking.display = channel.anthropic_thinking_display;
    }
  }

  if (!payload.output_config && channel.anthropic_output_effort) {
    payload.output_config = { effort: channel.anthropic_output_effort };
  }
}

function convertOpenAIChatToAnthropic(data, realModel, channel = {}) {
  const messages = [];
  const system = [];

  for (const message of data.messages || []) {
    if (message.role === 'system') {
      if (typeof message.content === 'string') {
        system.push(message.content);
      }
      continue;
    }

    if (message.role === 'tool') {
      messages.push({
        role: 'user',
        content: [{
          type: 'tool_result',
          tool_use_id: message.tool_call_id || message.id || '',
          content: stringifyToolResultContent(message.content),
        }],
      });
      continue;
    }

    messages.push({
      role: message.role === 'assistant' ? 'assistant' : 'user',
      content: message.role === 'assistant'
        ? convertOpenAIMessageToAnthropicContent(message)
        : convertOpenAIContentToAnthropic(message.content),
    });
  }

  const payload = {
    model: realModel,
    messages,
    max_tokens: data.max_tokens || data.max_completion_tokens || 4096,
  };
  if (channel.name === 'pio' || String(channel.base_url || '').includes('api.pioneer.ai')) {
    payload.max_tokens = Math.max(Number(payload.max_tokens) || 0, 32768);
  }

  if (channel.prompt_cache_enabled) {
    payload.cache_control = getPromptCacheControl(data, channel);
  }

  if (system.length > 0) payload.system = system.join('\n\n');
  if (typeof data.temperature === 'number') payload.temperature = data.temperature;
  if (typeof data.top_p === 'number') payload.top_p = data.top_p;
  if (typeof data.stop === 'string' || Array.isArray(data.stop)) payload.stop_sequences = Array.isArray(data.stop) ? data.stop : [data.stop];
  const tools = convertOpenAIToolsToAnthropic(data.tools);
  if (tools) payload.tools = tools;
  const toolChoice = convertOpenAIToolChoiceToAnthropic(data.tool_choice);
  if (toolChoice) payload.tool_choice = toolChoice;
  applyAnthropicThinking(payload, data, channel);

  return applyAnthropicPromptCache(payload, data, channel);
}

function convertAnthropicResponseToOpenAI(data, requestedModel) {
  const content = Array.isArray(data.content) ? data.content : [];
  const text = content.map((part) => part?.type === 'text' ? (part.text || '') : '').join('');
  const toolCalls = content
    .filter((part) => part?.type === 'tool_use' && part.name)
    .map((part) => ({
      id: part.id || `call_${newRequestId()}`,
      type: 'function',
      function: {
        name: part.name,
        arguments: JSON.stringify(part.input || {}),
      },
    }));
  const usage = data.usage || {};
  const inputTokens = usage.input_tokens || 0;
  const outputTokens = usage.output_tokens || 0;
  const cacheCreationTokens = usage.cache_creation_input_tokens || 0;
  const cacheReadTokens = usage.cache_read_input_tokens || 0;

  return {
    id: data.id || `chatcmpl-${newRequestId()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: requestedModel,
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content: text || null,
          ...(toolCalls.length ? { tool_calls: toolCalls } : {}),
        },
        finish_reason: normalizeOpenAIFinishReason(data.stop_reason),
      },
    ],
    usage: {
      prompt_tokens: inputTokens,
      completion_tokens: outputTokens,
      cache_creation_input_tokens: cacheCreationTokens,
      cache_read_input_tokens: cacheReadTokens,
      total_tokens: inputTokens + cacheCreationTokens + cacheReadTokens + outputTokens,
    },
  };
}

function flattenTextContent(content) {
  if (content == null) return '';
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return JSON.stringify(content);
  return content.map((part) => {
    if (typeof part === 'string') return part;
    if (part?.type === 'text') return part.text || '';
    if (typeof part?.text === 'string') return part.text;
    if (typeof part?.content === 'string') return part.content;
    return JSON.stringify(part);
  }).filter(Boolean).join('\n');
}

function convertOpenAIChatToPrompt(data = {}) {
  if (typeof data.prompt === 'string') return data.prompt;
  if (!Array.isArray(data.messages)) return '';
  return data.messages.map((message) => {
    const role = message?.role || 'user';
    const content = flattenTextContent(message?.content);
    if (!content) return '';
    if (role === 'system') return `System:\n${content}`;
    if (role === 'assistant') return `Assistant:\n${content}`;
    if (role === 'tool') return `Tool result:\n${content}`;
    return `User:\n${content}`;
  }).filter(Boolean).join('\n\n');
}

function buildUnlimitedChatPayload(data, realModel) {
  const payload = {
    model: realModel,
    prompt: convertOpenAIChatToPrompt(data),
  };
  for (const key of ['temperature', 'top_p', 'max_tokens', 'max_completion_tokens', 'stop']) {
    if (Object.prototype.hasOwnProperty.call(data, key)) payload[key] = data[key];
  }
  if (payload.max_completion_tokens != null && payload.max_tokens == null) {
    payload.max_tokens = payload.max_completion_tokens;
  }
  delete payload.max_completion_tokens;
  return payload;
}

function buildOpenAIChatCompletion(content, requestedModel, finishReason = 'stop') {
  return {
    id: `chatcmpl-${newRequestId()}`,
    object: 'chat.completion',
    created: Math.floor(Date.now() / 1000),
    model: requestedModel,
    choices: [
      {
        index: 0,
        message: {
          role: 'assistant',
          content,
        },
        finish_reason: normalizeOpenAIFinishReason(finishReason),
      },
    ],
    usage: {
      prompt_tokens: 0,
      completion_tokens: 0,
      total_tokens: 0,
    },
  };
}

async function proxyUnlimitedChatRequest(channel, req, res, data, upstreamModel = '', requestedModel = '', requestId = '', logContext = {}, channelKey = '') {
  const fullUrl = `${channel.base_url.replace(/\/$/, '')}/api/chat`;
  const parsed = new URL(fullUrl);
  const realModel = stripModelPrefix(upstreamModel, channelKey);
  const unlimitedPayload = buildUnlimitedChatPayload(data, realModel);
  const body = JSON.stringify(unlimitedPayload);
  const wantsStream = data.stream === true;
  const startedAt = Date.now();
  const selectedKey = selectChannelKey(channel, channelKey);
  const streamId = `chatcmpl-${requestId || newRequestId()}`;
  const streamCreated = Math.floor(Date.now() / 1000);

  const headers = {
    'content-type': 'application/json',
    'accept': 'text/event-stream, application/json',
    'authorization': `Bearer ${selectedKey.key}`,
    'content-length': Buffer.byteLength(body),
  };

  function writeOpenAIStreamChunk(content = '', finishReason = null) {
    const chunk = {
      id: streamId,
      object: 'chat.completion.chunk',
      created: streamCreated,
      model: requestedModel || upstreamModel,
      choices: [
        {
          index: 0,
          delta: content ? { content } : {},
          finish_reason: finishReason ? normalizeOpenAIFinishReason(finishReason) : null,
        },
      ],
    };
    res.write(`data: ${JSON.stringify(chunk)}\n\n`);
  }

  writeGatewayLog('upstream_request', {
    requestId,
    model: upstreamModel || 'unknown',
    channel: channel.name,
    clientIp: logContext.clientIp,
    requestedModel: logContext.requestedModel || requestedModel,
    upstreamHost: parsed.host,
    upstreamPath: parsed.pathname,
    method: 'POST',
    requestBytes: Buffer.byteLength(body),
    inputContent: logContext.inputContent,
    format: 'unlimited_api_chat',
    upstreamKeyIndex: selectedKey.index,
    upstreamKeyCount: selectedKey.count,
    upstreamKeyFingerprint: selectedKey.fingerprint,
  });

  return new Promise((resolve, reject) => {
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers,
      timeout: 120000,
    };
    const transport = parsed.protocol === 'https:' ? https : http;
    let rawResponse = '';
    let lineBuffer = '';
    let outputContent = '';
    let finishReason = 'stop';
    let upstreamError = '';
    let streamStarted = false;
    let completed = false;

    function inferUnlimitedErrorStatus(errorMessage = '', fallback = 424) {
      const match = String(errorMessage).match(/\bstatus code\s+(\d{3})\b/i)
        || String(errorMessage).match(/\bHTTP\s+(\d{3})\b/i);
      if (match) {
        const status = Number(match[1]);
        if (status >= 400 && status < 600) return status;
      }
      return fallback;
    }

    function finishWithUpstreamError(statusCode, errorMessage, extra = {}) {
      if (completed) return;
      completed = true;
      const safeStatusCode = statusCode || inferUnlimitedErrorStatus(errorMessage);
      logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, errorMessage));
      writeGatewayLog('request_complete', responseLogFields(logContext, {
        requestId,
        model: upstreamModel || 'unknown',
        channel: channel.name,
        requestedModel,
        statusCode: safeStatusCode,
        durationMs: Date.now() - startedAt,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        upstreamKeyIndex: selectedKey.index,
        upstreamKeyCount: selectedKey.count,
        upstreamKeyFingerprint: selectedKey.fingerprint,
        outputContent: truncateText(outputContent),
        errorMessage,
        responseBody: truncateText(rawResponse),
        format: 'unlimited_api_chat',
        ...extra,
      }));
      if (res.writableEnded) return;
      if (wantsStream) {
        if (!res.headersSent) {
          res.writeHead(safeStatusCode, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: errorMessage, type: 'upstream_error' } }));
          return;
        }
        if (streamStarted) {
          writeOpenAIStreamChunk('', 'stop');
          res.write('data: [DONE]\n\n');
          res.end();
        }
        return;
      }
      if (!res.headersSent) {
        res.writeHead(safeStatusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: errorMessage, type: 'upstream_error' } }));
      }
    }

    function handleEvent(payload) {
      let eventData;
      try {
        eventData = JSON.parse(payload);
      } catch {
        return;
      }
      if (typeof eventData.delta === 'string') {
        outputContent += eventData.delta;
        if (wantsStream) {
          if (!streamStarted) {
            res.writeHead(200, {
              'Content-Type': 'text/event-stream; charset=utf-8',
              'Cache-Control': 'no-cache',
              'Connection': 'keep-alive',
            });
            streamStarted = true;
          }
          writeOpenAIStreamChunk(eventData.delta);
        }
      }
      if (eventData.finish) finishReason = eventData.reason || finishReason;
      if (eventData.error) upstreamError = String(eventData.error);
    }

    const proxy = transport.request(options, (proxyRes) => {
      proxyRes.on('data', (chunk) => {
        const chunkStr = chunk.toString();
        rawResponse += chunkStr;
        lineBuffer += chunkStr;
        const lines = lineBuffer.split('\n');
        lineBuffer = lines.pop() || '';
        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith('data: ')) continue;
          const payload = line.slice(6);
          if (!payload || payload === '[DONE]') continue;
          handleEvent(payload);
        }
      });

      proxyRes.on('end', () => {
        if (completed) return;
        const trailing = lineBuffer.trim();
        if (trailing.startsWith('data: ')) {
          const payload = trailing.slice(6);
          if (payload && payload !== '[DONE]') handleEvent(payload);
        }

        if (proxyRes.statusCode >= 400 || upstreamError) {
          const errorMessage = upstreamError || `HTTP ${proxyRes.statusCode}`;
          finishWithUpstreamError(proxyRes.statusCode >= 400 ? proxyRes.statusCode : inferUnlimitedErrorStatus(errorMessage), errorMessage);
          resolve();
          return;
        }

        completed = true;
        logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, true, requestLogOptions(logContext, requestId, null));
        writeGatewayLog('request_complete', responseLogFields(logContext, {
          requestId,
          model: upstreamModel || 'unknown',
          channel: channel.name,
          requestedModel,
          statusCode: proxyRes.statusCode,
          durationMs: Date.now() - startedAt,
          inputTokens: 0,
          outputTokens: 0,
          totalTokens: 0,
          upstreamKeyIndex: selectedKey.index,
          upstreamKeyCount: selectedKey.count,
          upstreamKeyFingerprint: selectedKey.fingerprint,
          outputContent: truncateText(outputContent),
          format: wantsStream ? 'unlimited_api_chat_stream' : 'unlimited_api_chat',
        }));

        if (wantsStream) {
          if (!streamStarted) {
            res.writeHead(200, {
              'Content-Type': 'text/event-stream; charset=utf-8',
              'Cache-Control': 'no-cache',
              'Connection': 'keep-alive',
            });
          }
          writeOpenAIStreamChunk('', finishReason);
          res.write('data: [DONE]\n\n');
          res.end();
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(buildOpenAIChatCompletion(outputContent, requestedModel || upstreamModel, finishReason)));
        }
        resolve();
      });

      proxyRes.on('error', (err) => {
        finishWithUpstreamError(424, err.message || 'upstream aborted', { upstreamEvent: 'response_error' });
        resolve();
      });
      proxyRes.on('aborted', () => {
        finishWithUpstreamError(424, 'upstream aborted', { upstreamEvent: 'response_aborted' });
        resolve();
      });
    });

    proxy.on('error', (err) => {
      finishWithUpstreamError(inferUnlimitedErrorStatus(err.message), err.message || 'upstream error', { upstreamEvent: 'request_error' });
      resolve();
    });

    proxy.on('timeout', () => {
      finishWithUpstreamError(408, 'timeout', { upstreamEvent: 'request_timeout' });
      proxy.destroy();
      resolve();
    });

    proxy.write(body);
    proxy.end();
  });
}

function sanitizePayloadForUpstream(data, upstreamModel) {
  if (!data || typeof data !== 'object') return { data, removedParams: [] };
  const next = { ...data };
  const removedParams = [];
  const model = String(upstreamModel || next.model || '').toLowerCase();

  if (model.includes('gemini')) {
    for (const key of ['presence_penalty', 'frequency_penalty']) {
      if (Object.prototype.hasOwnProperty.call(next, key)) {
        delete next[key];
        removedParams.push(key);
      }
    }
  }

  return { data: next, removedParams };
}

async function proxyRequest(channel, req, res, body, modelName = '', requestId = '', logContext = {}, channelKey = '') {
  const targetUrl = new URL(channel.base_url);
  // Append the request path (strip /v1 prefix if base_url already has it)
  const reqPath = req.url.startsWith('/v1/') ? req.url.slice(3) : req.url;
  const fullUrl = `${channel.base_url}${reqPath}`;
  
  const headers = {};
  // Forward only necessary headers
  if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  if (req.headers['accept']) headers['accept'] = req.headers['accept'];
  const selectedKey = selectChannelKey(channel, channelKey);
  headers['authorization'] = `Bearer ${selectedKey.key}`;
  headers['content-length'] = body ? Buffer.byteLength(body) : 0;
  
  return new Promise((resolve, reject) => {
    const parsed = new URL(fullUrl);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: req.method,
      headers,
      timeout: 120000,
    };
    
    const transport = parsed.protocol === 'https:' ? https : http;
    let responseData = '';
    const startedAt = Date.now();
    writeGatewayLog('upstream_request', {
      requestId,
      model: modelName || 'unknown',
      channel: channel.name,
      clientIp: logContext.clientIp,
      requestedModel: logContext.requestedModel,
      upstreamHost: parsed.host,
      upstreamPath: parsed.pathname,
      method: req.method,
      requestBytes: Buffer.byteLength(body || ''),
      inputContent: logContext.inputContent,
      upstreamKeyIndex: selectedKey.index,
      upstreamKeyCount: selectedKey.count,
      upstreamKeyFingerprint: selectedKey.fingerprint,
    });
    
    const proxy = transport.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      // 收集响应数据以提取 token 使用量
      proxyRes.on('data', chunk => {
        responseData += chunk.toString();
        res.write(chunk);
      });
      
      proxyRes.on('end', () => {
        if (!res.writableEnded) {
          res.end();
        }
        
        // 尝试解析 token 使用量和输出内容
        const responseDetails = extractResponseLogDetails(responseData);
        const errorMessage = responseDetails.errorMessage;
        const tokens = responseDetails.totalTokens;
        
        // 记录成功的请求
        if (proxyRes.statusCode < 400 && !errorMessage) {
          logRequest(modelName || 'unknown', channel.name, tokens, true, requestLogOptions(logContext, requestId, null, responseDetails));
          writeGatewayLog('request_complete', responseLogFields(logContext, {
            requestId,
            model: modelName || 'unknown',
            channel: channel.name,
            statusCode: proxyRes.statusCode,
            durationMs: Date.now() - startedAt,
            tokens,
            inputTokens: responseDetails.inputTokens,
            outputTokens: responseDetails.outputTokens,
            totalTokens: responseDetails.totalTokens,
            cacheCreationInputTokens: responseDetails.cacheCreationInputTokens,
            cacheReadInputTokens: responseDetails.cacheReadInputTokens,
            upstreamKeyIndex: selectedKey.index,
            upstreamKeyCount: selectedKey.count,
            upstreamKeyFingerprint: selectedKey.fingerprint,
            outputContent: responseDetails.outputContent,
          }));
        } else {
          const finalErrorMessage = errorMessage || `HTTP ${proxyRes.statusCode}`;
          logRequest(modelName || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, finalErrorMessage));
          writeGatewayLog('request_complete', responseLogFields(logContext, {
            requestId,
            model: modelName || 'unknown',
            channel: channel.name,
            statusCode: proxyRes.statusCode,
            durationMs: Date.now() - startedAt,
            tokens: responseDetails.totalTokens,
            inputTokens: responseDetails.inputTokens,
            outputTokens: responseDetails.outputTokens,
            totalTokens: responseDetails.totalTokens,
            cacheCreationInputTokens: responseDetails.cacheCreationInputTokens,
            cacheReadInputTokens: responseDetails.cacheReadInputTokens,
            upstreamKeyIndex: selectedKey.index,
            upstreamKeyCount: selectedKey.count,
            upstreamKeyFingerprint: selectedKey.fingerprint,
            outputContent: responseDetails.outputContent,
            errorMessage: finalErrorMessage,
            responseBody: truncateText(responseData),
          }));
        }
        
        resolve();
      });
      
      proxyRes.on('error', reject);
    });
    
    proxy.on('error', (err) => {
      logRequest(modelName || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message));
      writeGatewayLog('request_complete', responseLogFields(logContext, {
        requestId,
        model: modelName || 'unknown',
        channel: channel.name,
        statusCode: 502,
        durationMs: Date.now() - startedAt,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        errorMessage: err.message,
      }));
      reject(err);
    });
    
    proxy.on('timeout', () => {
      logRequest(modelName || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, 'timeout'));
      writeGatewayLog('request_complete', responseLogFields(logContext, {
        requestId,
        model: modelName || 'unknown',
        channel: channel.name,
        statusCode: 504,
        durationMs: Date.now() - startedAt,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        errorMessage: 'timeout',
      }));
      proxy.destroy(); 
      reject(new Error('timeout')); 
    });
    
    if (body) proxy.write(body);
    proxy.end();
  });
}

async function proxyAnthropicChatRequest(channel, req, res, data, upstreamModel = '', requestedModel = '', requestId = '', logContext = {}, channelKey = '') {
  const parsedBase = new URL(channel.base_url);
  const fullUrl = `${channel.base_url.replace(/\/$/, '')}/messages`;
  const parsed = new URL(fullUrl);
  const anthropicPayload = convertOpenAIChatToAnthropic(data, stripModelPrefix(upstreamModel, channelKey), channel);
  const wantsStream = data.stream === true;
  if (wantsStream) anthropicPayload.stream = true;
  const body = JSON.stringify(anthropicPayload);
  const startedAt = Date.now();
  const selectedKey = selectChannelKey(channel, channelKey);

  const headers = {
    'content-type': 'application/json',
    'accept': 'application/json',
    'x-api-key': selectedKey.key,
    'anthropic-version': channel.anthropic_version || '2023-06-01',
    'content-length': Buffer.byteLength(body),
  };
  const anthropicBeta = getAnthropicBetaHeader(channel);
  if (anthropicBeta) headers['anthropic-beta'] = anthropicBeta;

  return new Promise((resolve, reject) => {
    const options = {
      hostname: parsed.hostname || parsedBase.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: 'POST',
      headers,
      timeout: 120000,
    };

    const transport = parsed.protocol === 'https:' ? https : http;
    let responseData = '';
    let streamBuffer = '';
    let streamFinishReason = 'stop';
    let streamInputTokens = 0;
    let streamOutputTokens = 0;
    let streamCacheCreationInputTokens = 0;
    let streamCacheReadInputTokens = 0;
    let streamOutputContent = '';
    const streamToolBlocks = new Map();
    const streamId = `chatcmpl-${requestId || newRequestId()}`;
    const streamCreated = Math.floor(Date.now() / 1000);

    function writeOpenAIStreamChunk(content = '', finishReason = null, extraDelta = null) {
      const delta = extraDelta || (content ? { content } : {});
      const chunk = {
        id: streamId,
        object: 'chat.completion.chunk',
        created: streamCreated,
        model: requestedModel || upstreamModel,
        choices: [
          {
            index: 0,
            delta,
            finish_reason: finishReason ? normalizeOpenAIFinishReason(finishReason) : null,
          },
        ],
      };
      res.write(`data: ${JSON.stringify(chunk)}\n\n`);
    }

    writeGatewayLog('upstream_request', {
      requestId,
      model: upstreamModel || 'unknown',
      channel: channel.name,
      clientIp: logContext.clientIp,
      requestedModel: logContext.requestedModel || requestedModel,
      upstreamHost: parsed.host,
      upstreamPath: parsed.pathname,
      method: 'POST',
      requestBytes: Buffer.byteLength(body),
      inputContent: logContext.inputContent,
      format: 'anthropic',
      upstreamKeyIndex: selectedKey.index,
      upstreamKeyCount: selectedKey.count,
      upstreamKeyFingerprint: selectedKey.fingerprint,
    });

    const proxy = transport.request(options, (proxyRes) => {
      const contentType = String(proxyRes.headers['content-type'] || '').toLowerCase();
      const isEventStream = contentType.includes('text/event-stream');
      if (wantsStream && proxyRes.statusCode < 400) {
        res.writeHead(200, {
          'Content-Type': 'text/event-stream; charset=utf-8',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive',
        });
      }

      proxyRes.on('data', (chunk) => {
        const chunkStr = chunk.toString();
        if (!wantsStream || proxyRes.statusCode >= 400 || !isEventStream) {
          responseData += chunkStr;
          return;
        }

        streamBuffer += chunkStr;
        const lines = streamBuffer.split('\n');
        streamBuffer = lines.pop() || '';

        for (const rawLine of lines) {
          const line = rawLine.trim();
          if (!line.startsWith('data: ')) continue;
          const payload = line.slice(6);
          if (!payload || payload === '[DONE]') continue;
          try {
            const eventData = JSON.parse(payload);
            if (eventData.type === 'message_start') {
              const usage = extractTokenUsageDetails(eventData.message);
              streamInputTokens = usage.inputTokens || 0;
              streamCacheCreationInputTokens = usage.cacheCreationInputTokens || 0;
              streamCacheReadInputTokens = usage.cacheReadInputTokens || 0;
              writeOpenAIStreamChunk('');
            } else if (eventData.type === 'content_block_start') {
              const block = eventData.content_block || {};
              if (block.type === 'tool_use' && block.name) {
                const index = Number.isInteger(eventData.index) ? eventData.index : streamToolBlocks.size;
                streamToolBlocks.set(eventData.index, index);
                writeOpenAIStreamChunk('', null, {
                  tool_calls: [{
                    index,
                    id: block.id || `call_${newRequestId()}`,
                    type: 'function',
                    function: {
                      name: block.name,
                      arguments: '',
                    },
                  }],
                });
              }
            } else if (eventData.type === 'content_block_delta') {
              const text = eventData.delta?.text || '';
              if (text) {
                streamOutputContent += text;
                writeOpenAIStreamChunk(text);
              }
              const partialJson = eventData.delta?.partial_json || '';
              if (partialJson) {
                const index = streamToolBlocks.get(eventData.index) ?? (Number.isInteger(eventData.index) ? eventData.index : 0);
                writeOpenAIStreamChunk('', null, {
                  tool_calls: [{
                    index,
                    function: {
                      arguments: partialJson,
                    },
                  }],
                });
              }
            } else if (eventData.type === 'message_delta') {
              streamFinishReason = eventData.delta?.stop_reason || streamFinishReason;
              streamOutputTokens = eventData.usage?.output_tokens || streamOutputTokens;
            }
          } catch (err) {
            writeGatewayLog('anthropic_stream_parse_error', {
              requestId,
              model: upstreamModel || 'unknown',
              channel: channel.name,
              error: err.message,
              line: truncateText(line),
            });
          }
        }
      });

      proxyRes.on('end', () => {
        if (wantsStream && proxyRes.statusCode < 400) {
          if (!isEventStream) {
            try {
              const anthropicData = JSON.parse(responseData);
              const openAIData = convertAnthropicResponseToOpenAI(anthropicData, requestedModel || upstreamModel);
              const content = openAIData.choices?.[0]?.message?.content || '';
              if (content) writeOpenAIStreamChunk(content);
              writeOpenAIStreamChunk('', openAIData.choices?.[0]?.finish_reason || streamFinishReason);
              res.write('data: [DONE]\n\n');
              res.end();
              const usageDetails = extractTokenUsageDetails(openAIData);
              const tokens = usageDetails.totalTokens;
              logRequest(upstreamModel || requestedModel || 'unknown', channel.name, tokens, true, requestLogOptions(logContext, requestId, null, usageDetails));
              writeGatewayLog('request_complete', responseLogFields(logContext, {
                requestId,
                model: upstreamModel || 'unknown',
                channel: channel.name,
                requestedModel,
                statusCode: proxyRes.statusCode,
                durationMs: Date.now() - startedAt,
                tokens,
                ...usageDetails,
                upstreamKeyIndex: selectedKey.index,
                upstreamKeyCount: selectedKey.count,
                upstreamKeyFingerprint: selectedKey.fingerprint,
                outputContent: truncateText(content),
                format: 'anthropic_stream_json_fallback',
              }));
              resolve();
            } catch (err) {
              logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message));
              writeGatewayLog('request_complete', responseLogFields(logContext, {
                requestId,
                model: upstreamModel || 'unknown',
                channel: channel.name,
                requestedModel,
                statusCode: 502,
                durationMs: Date.now() - startedAt,
                inputTokens: 0,
                outputTokens: 0,
                totalTokens: 0,
                errorMessage: err.message,
                responseBody: truncateText(responseData),
              }));
              reject(err);
            }
            return;
          }

          writeOpenAIStreamChunk('', streamFinishReason);
          res.write('data: [DONE]\n\n');
          res.end();
          const tokens = streamInputTokens + streamOutputTokens;
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, tokens, true, requestLogOptions(logContext, requestId, null, {
            cacheCreationInputTokens: streamCacheCreationInputTokens,
            cacheReadInputTokens: streamCacheReadInputTokens,
          }));
          writeGatewayLog('request_complete', responseLogFields(logContext, {
            requestId,
            model: upstreamModel || 'unknown',
            channel: channel.name,
            requestedModel,
            statusCode: proxyRes.statusCode,
            durationMs: Date.now() - startedAt,
            tokens,
            inputTokens: streamInputTokens,
            outputTokens: streamOutputTokens,
            totalTokens: tokens,
            cacheCreationInputTokens: streamCacheCreationInputTokens,
            cacheReadInputTokens: streamCacheReadInputTokens,
            upstreamKeyIndex: selectedKey.index,
            upstreamKeyCount: selectedKey.count,
            upstreamKeyFingerprint: selectedKey.fingerprint,
            outputContent: truncateText(streamOutputContent),
            format: 'anthropic_stream',
          }));
          resolve();
          return;
        }

        if (proxyRes.statusCode >= 400) {
          const responseDetails = extractResponseLogDetails(responseData);
          const errorMessage = responseDetails.errorMessage || `HTTP ${proxyRes.statusCode}`;
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, errorMessage));
          writeGatewayLog('request_complete', responseLogFields(logContext, {
            requestId,
            model: upstreamModel || 'unknown',
            channel: channel.name,
            requestedModel,
            statusCode: proxyRes.statusCode,
            durationMs: Date.now() - startedAt,
            tokens: responseDetails.totalTokens,
            inputTokens: responseDetails.inputTokens,
            outputTokens: responseDetails.outputTokens,
            totalTokens: responseDetails.totalTokens,
            outputContent: responseDetails.outputContent,
            errorMessage,
            responseBody: truncateText(responseData),
          }));
          res.writeHead(proxyRes.statusCode, { 'Content-Type': 'application/json' });
          res.end(responseData);
          resolve();
          return;
        }

        try {
          const anthropicData = JSON.parse(responseData);
          const openAIData = convertAnthropicResponseToOpenAI(anthropicData, requestedModel || upstreamModel);
          const usageDetails = extractTokenUsageDetails(openAIData);
          const tokens = usageDetails.totalTokens;
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, tokens, true, requestLogOptions(logContext, requestId, null, usageDetails));
          writeGatewayLog('request_complete', responseLogFields(logContext, {
            requestId,
            model: upstreamModel || 'unknown',
            channel: channel.name,
            requestedModel,
            statusCode: proxyRes.statusCode,
            durationMs: Date.now() - startedAt,
            tokens,
            ...usageDetails,
            upstreamKeyIndex: selectedKey.index,
            upstreamKeyCount: selectedKey.count,
            upstreamKeyFingerprint: selectedKey.fingerprint,
            outputContent: truncateText(openAIData.choices?.[0]?.message?.content || ''),
            format: 'anthropic',
          }));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(openAIData));
          resolve();
        } catch (err) {
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message));
          writeGatewayLog('request_complete', responseLogFields(logContext, {
            requestId,
            model: upstreamModel || 'unknown',
            channel: channel.name,
            requestedModel,
            statusCode: 502,
            durationMs: Date.now() - startedAt,
            inputTokens: 0,
            outputTokens: 0,
            totalTokens: 0,
            errorMessage: err.message,
            responseBody: truncateText(responseData),
          }));
          reject(err);
        }
      });

      proxyRes.on('error', reject);
    });

    proxy.on('error', (err) => {
      logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message));
      writeGatewayLog('request_complete', responseLogFields(logContext, {
        requestId,
        model: upstreamModel || 'unknown',
        channel: channel.name,
        requestedModel,
        statusCode: 502,
        durationMs: Date.now() - startedAt,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        errorMessage: err.message,
      }));
      reject(err);
    });

    proxy.on('timeout', () => {
      logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, 'timeout'));
      writeGatewayLog('request_complete', responseLogFields(logContext, {
        requestId,
        model: upstreamModel || 'unknown',
        channel: channel.name,
        requestedModel,
        statusCode: 504,
        durationMs: Date.now() - startedAt,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        errorMessage: 'timeout',
      }));
      proxy.destroy();
      reject(new Error('timeout'));
    });

    proxy.write(body);
    proxy.end();
  });
}

async function handleChatCompletions(req, res, body, requestId) {
  let data;
  try {
    data = JSON.parse(body);
  } catch (err) {
    writeGatewayLog('request_complete', {
      requestId,
      clientIp: getClientIp(req),
      statusCode: 400,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      errorMessage: err.message,
      body: truncateText(body),
    });
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'Invalid JSON body', type: 'invalid_request' } }));
    return;
  }
  const logContext = buildLogContext(req, data);
  const modelName = data.model;
  const messageCount = Array.isArray(data.messages) ? data.messages.length : 0;
  const paramKeys = Object.keys(data).filter(k => !['model', 'messages', 'stream'].includes(k));
  writeGatewayLog('chat_request', {
    requestId,
    model: modelName || null,
    stream: Boolean(data.stream),
    messageCount,
    params: paramKeys,
    clientIp: logContext.clientIp,
    inputContent: logContext.inputContent,
    headers: sanitizeHeaders(req.headers),
  });
  
  if (!modelName) {
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'model is required', type: 'invalid_request' } }));
    writeGatewayLog('chat_rejected', {
      requestId,
      model: modelName || null,
      clientIp: logContext.clientIp,
      statusCode: 400,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      errorMessage: 'model is required',
      inputContent: logContext.inputContent,
    });
    return;
  }
  
  let entry = modelMap.get(modelName);
  if (entry && !clientCanUseModel(req, modelName, entry.channelKey)) {
    entry = null;
  }
  if (!entry) {
    // Try partial match: any channel model that ends with the requested name
    const candidates = getAccessibleModelEntries(req).filter(([k]) => k.endsWith(modelName));
    if (candidates.length === 0) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: `Model not found: ${modelName}`, type: 'model_not_found' } }));
      logRequest(modelName, 'none', 0, false, requestLogOptions(logContext, requestId, 'model_not_found'));
      writeGatewayLog('request_complete', responseLogFields(logContext, {
        requestId,
        model: modelName,
        channel: 'none',
        statusCode: 404,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        errorMessage: `Model not found: ${modelName}`,
        availableModelCount: modelMap.size,
        accessibleModelCount: getAccessibleModelEntries(req).length,
      }));
      return;
    }
    // Use first match
    const [matched, info] = candidates[0];
    entry = info;
    writeGatewayLog('model_partial_match', {
      requestId,
      requestedModel: modelName,
      matchedModel: matched,
      channelKey: entry.channelKey,
    });
  }
  
  const channel = config.channels[entry.channelKey];
  if (!clientCanUseChannel(req, entry.channelKey)) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: `Model not found: ${modelName}`, type: 'model_not_found' } }));
    logRequest(modelName, 'none', 0, false, requestLogOptions(logContext, requestId, 'channel_not_allowed'));
    writeGatewayLog('request_complete', responseLogFields(logContext, {
      requestId,
      model: modelName,
      channel: 'none',
      statusCode: 404,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      errorMessage: 'channel_not_allowed',
      channelKey: entry.channelKey,
    }));
    return;
  }
  if (!channel) {
    res.writeHead(500, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'Channel not found', type: 'config_error' } }));
    logRequest(modelName, 'none', 0, false, 'channel_not_found');
    writeGatewayLog('request_complete', responseLogFields(logContext, {
      requestId,
      model: modelName,
      channel: 'none',
      statusCode: 500,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      errorMessage: 'Channel not found',
      channelKey: entry.channelKey,
    }));
    return;
  }

  const quota = consumeClientQuota(req, modelName);
  if (!quota.ok) {
    const statusCode = quota.statusCode || 429;
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      error: {
        message: quota.message || 'Quota exceeded',
        type: statusCode === 401 ? 'auth_error' : 'quota_exceeded',
        quota_cost: quota.cost || getModelQuotaCost(modelName),
        quota_limit: quota.limit || 0,
        quota_used: quota.used || 0,
        quota_remaining: quota.remaining || 0,
      },
    }));
    logRequest(modelName, channel.name, 0, false, requestLogOptions(logContext, requestId, 'quota_exceeded'));
    writeGatewayLog('request_complete', responseLogFields(logContext, {
      requestId,
      model: modelName,
      channel: channel.name,
      channelKey: entry.channelKey,
      statusCode,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      errorMessage: quota.message || 'quota_exceeded',
      quotaCost: quota.cost || getModelQuotaCost(modelName),
      quotaLimit: quota.limit || 0,
      quotaUsed: quota.used || 0,
      quotaRemaining: quota.remaining || 0,
    }));
    return;
  }
  
  // Strip prefix from model name for upstream
  const upstreamModel = entry.upstreamModel;
  // Remove provider prefixes like "local/" before passing upstream.
  const realModel = stripModelPrefix(upstreamModel, entry.channelKey);
  const channelInput = channel.format === 'anthropic' || channel.format === 'unlimited_api_chat'
    ? { ...data, model: realModel }
    : applyOpenAICompatiblePromptCache({ ...data, model: realModel }, channel);
  const sanitized = sanitizePayloadForUpstream(channelInput, upstreamModel);
  data = sanitized.data;
  body = JSON.stringify(data);  // 已经过滤过参数的 data
  writeGatewayLog('model_routed', {
    requestId,
    requestedModel: modelName,
    upstreamModel,
    upstreamPayloadModel: realModel,
    channelKey: entry.channelKey,
    channel: channel.name,
    ...(quota.cost ? {
      quotaCost: quota.cost,
      quotaLimit: quota.limit || 0,
      quotaUsed: quota.used || 0,
      quotaRemaining: Number.isFinite(quota.remaining) ? quota.remaining : null,
    } : {}),
    finalParams: Object.keys(data).filter(k => !['model', 'messages', 'stream'].includes(k)),
    ...(sanitized.removedParams.length ? { removedParams: sanitized.removedParams } : {}),
  });
  
  try {
    if (channel.format === 'anthropic') {
      await proxyAnthropicChatRequest(channel, req, res, data, upstreamModel, modelName, requestId, logContext, entry.channelKey);
    } else if (channel.format === 'unlimited_api_chat') {
      await proxyUnlimitedChatRequest(channel, req, res, data, upstreamModel, modelName, requestId, logContext, entry.channelKey);
    } else {
      await proxyRequest(channel, req, res, body, upstreamModel, requestId, logContext, entry.channelKey);
    }
  } catch (err) {
    console.error(`[${entry.channelKey}] proxy error:`, err.message);
    writeGatewayLog('request_complete', responseLogFields(logContext, {
      requestId,
      model: upstreamModel,
      channelKey: entry.channelKey,
      channel: channel.name,
      statusCode: 502,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      errorMessage: err.message,
    }));
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: `Upstream error: ${err.message}`, type: 'proxy_error' } }));
    }
  }
}

async function handleModels(req, res) {
  // Build model list from all channels
  const models = [];
  for (const [ckey, ch] of Object.entries(config.channels)) {
    for (const m of ch.models) {
      if (!clientCanUseModel(req, m, ckey)) continue;
      models.push({
        id: m,
        object: 'model',
        created: 0,
        owned_by: ch.name,
      });
    }
  }

  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ object: 'list', data: models }));
}

// Config management helpers
function saveConfig() {
  fs.writeFileSync(CONFIG_FILE, JSON.stringify(config, null, 2));
}

function normalizeImportedConfig(input) {
  const nextConfig = input && typeof input === 'object' && input.config && typeof input.config === 'object'
    ? input.config
    : input;
  if (!nextConfig || typeof nextConfig !== 'object' || Array.isArray(nextConfig)) {
    throw new Error('备份文件格式不正确');
  }
  if (!nextConfig.channels || typeof nextConfig.channels !== 'object' || Array.isArray(nextConfig.channels)) {
    throw new Error('备份文件缺少 channels');
  }
  if (nextConfig.models && !Array.isArray(nextConfig.models)) {
    throw new Error('models 必须是数组');
  }
  const normalized = {
    ...nextConfig,
    port: Number(nextConfig.port) || config.port || 8300,
    api_key: String(nextConfig.api_key || config.api_key || '').trim(),
    api_keys: Array.isArray(nextConfig.api_keys)
      ? nextConfig.api_keys.map(normalizeClientKeyEntry).filter(Boolean)
      : [],
    channels: nextConfig.channels,
    models: Array.isArray(nextConfig.models) ? nextConfig.models : [],
  };
  for (const [key, channel] of Object.entries(normalized.channels || {})) {
    normalized.channels[key] = normalizeChannelForSave(channel);
  }
  if (normalized.api_key.length < 4) {
    throw new Error('管理 Key 至少 4 位');
  }
  return normalized;
}

async function handleConfigAPI(req, res, url, body) {
  if (url === '/api/config' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      channels: config.channels,
      api_keys: getClientKeyEntries(),
    }));
    return true;
  }

  if (url === '/api/config/export' && req.method === 'GET') {
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    res.writeHead(200, {
      'Content-Type': 'application/json; charset=utf-8',
      'Content-Disposition': `attachment; filename="api-gateway-backup-${stamp}.json"`,
    });
    res.end(JSON.stringify(config, null, 2));
    return true;
  }

  if (url === '/api/config/api-key' && req.method === 'POST') {
    const d = JSON.parse(body);
    const nextKey = String(d.api_key || '').trim();
    if (nextKey.length < 4) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '管理 Key 至少 4 位' }));
      return true;
    }
    config.api_key = nextKey;
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }

  if (url === '/api/config/client-keys/generate' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const count = Math.min(Math.max(parseInt(d.count || '1', 10) || 1, 1), 100);
    const prefix = String(d.prefix || 'key').trim().replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 24) || 'key';
    const allowedChannels = normalizeStringArray(d.allowed_channels);
    const quotaLimit = Math.max(0, Math.floor(Number(d.quota_limit) || 0));
    const expiresAt = normalizeExpiresAt(d.expires_at);
    const existingEntries = getClientKeyEntries();
    const existing = new Set(existingEntries.map(entry => entry.key));
    const created = [];
    while (created.length < count) {
      const key = `${prefix}-${crypto.randomBytes(18).toString('base64url')}`;
      if (!existing.has(key)) {
        existing.add(key);
        created.push({
          key,
          name: count === 1 ? prefix : `${prefix}-${created.length + 1}`,
          allowed_channels: allowedChannels,
          allowed_models: [],
          quota_limit: quotaLimit,
          quota_used: 0,
          expires_at: expiresAt,
          enabled: true,
        });
      }
    }
    saveClientKeyEntries([...existingEntries, ...created]);
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      keys: created.map(entry => entry.key),
      api_keys: getClientKeyEntries(),
    }));
    return true;
  }

  if (url === '/api/config/client-keys/save' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const key = String(d.key || '').trim();
    if (!key) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '调用 Key 不能为空' }));
      return true;
    }
    if (key === config.api_key) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '调用 Key 不能和管理 Key 相同' }));
      return true;
    }
    const entries = getClientKeyEntries();
    const index = entries.findIndex(entry => entry.key === key);
    const nextEntry = {
      key,
      name: String(d.name || '').trim(),
      allowed_channels: normalizeStringArray(d.allowed_channels).filter(channelKey => Boolean(config.channels[channelKey])),
      allowed_models: normalizeStringArray(d.allowed_models),
      quota_limit: Math.max(0, Math.floor(Number(d.quota_limit) || 0)),
      quota_used: Math.max(0, Math.floor(Number(d.quota_used) || 0)),
      expires_at: normalizeExpiresAt(d.expires_at),
      enabled: d.enabled !== false,
    };
    if (index >= 0) entries[index] = nextEntry;
    else entries.push(nextEntry);
    saveClientKeyEntries(entries);
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, api_keys: getClientKeyEntries() }));
    return true;
  }

  if (url === '/api/config/client-keys/delete' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const key = String(d.key || '').trim();
    const entries = getClientKeyEntries();
    if (!key || !entries.some(entry => entry.key === key)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '调用 Key 不存在' }));
      return true;
    }
    saveClientKeyEntries(entries.filter(entry => entry.key !== key));
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, api_keys: getClientKeyEntries() }));
    return true;
  }

  if (url === '/api/config/import' && req.method === 'POST') {
    try {
      const imported = normalizeImportedConfig(JSON.parse(body));
      for (const key of Object.keys(config)) {
        delete config[key];
      }
      Object.assign(config, imported);
      saveConfig();
      rebuildModelMap();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: true,
        channels: Object.keys(config.channels || {}).length,
        models: [...modelMap.keys()].length,
      }));
      return true;
    } catch (err) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: err.message || '导入失败' }));
      return true;
    }
  }

  if (url.startsWith('/api/logs') && req.method === 'GET') {
    const parsed = new URL(url, 'http://localhost');
    const limit = Math.min(Math.max(parseInt(parsed.searchParams.get('limit') || '100', 10) || 100, 1), 500);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      file: currentLogFile(),
      logs: readVisibleGatewayLogs(limit),
    }));
    return true;
  }
  
  // 统计数据 API
  // Pioneer 额度查询 API
  if (url === '/api/billing' && req.method === 'GET') {
    // 查找 base_url 为 Pioneer 官方的渠道
    let pioneerChannel = null;
    for (const ch of Object.values(config.channels)) {
      if (ch.base_url && ch.base_url.includes('api.pioneer.ai')) {
        pioneerChannel = ch;
        break;
      }
    }
    const pioneerKeys = getChannelKeys(pioneerChannel || {});
    if (!pioneerChannel || pioneerKeys.length === 0) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '未配置 Pioneer 渠道' }));
      return true;
    }
    try {
      const items = await Promise.all(pioneerKeys.map(async (key, index) => {
        const item = {
          index,
          fingerprint: fingerprintKey(key),
          ok: false,
          billing: null,
          error: '',
        };
        try {
          item.billing = await fetchPioneerBilling(key);
          item.ok = true;
        } catch (err) {
          item.error = err.message || '查询失败';
        }
        return item;
      }));
      const billingRes = summarizePioneerBilling(items);
      if (billingRes.successful_key_count === 0) {
        throw new Error(items.map(item => `#${item.index + 1}: ${item.error}`).join('; ') || 'Pioneer 额度查询失败');
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, billing: billingRes }));
      return true;
    } catch (err) {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: err.message }));
      return true;
    }
  }

  if (url === '/api/stats' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats));
    return true;
  }
  
  if (url === '/api/stats/reset' && req.method === 'POST') {
    stats = {
      totalRequests: 0,
      modelUsage: {},
      channelUsage: {},
      ipUsage: {},
      dailyStats: {},
      recentLogs: []
    };
    saveStats();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }
  
  if (url === '/api/config/save' && req.method === 'POST') {
    const d = JSON.parse(body);
    const {
      channelKey,
      name,
      base_url,
      key,
      keys,
      models,
      format,
      anthropic_version,
      prompt_cache_enabled,
      prompt_cache_ttl,
      anthropic_thinking_type,
      anthropic_thinking_budget_tokens,
      anthropic_output_effort,
      anthropic_thinking_display,
      isNew,
      previousChannelKey,
    } = d;
    
    if (!channelKey) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'channelKey required' }));
      return true;
    }
    
    if (isNew && config.channels[channelKey]) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道 key 已存在' }));
      return true;
    }
    
    const oldChannelKey = !isNew && previousChannelKey ? String(previousChannelKey) : channelKey;
    const isRename = !isNew && oldChannelKey !== channelKey;

    if (!isNew && oldChannelKey && !config.channels[oldChannelKey]) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '原渠道不存在' }));
      return true;
    }

    if (isRename && config.channels[channelKey]) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '新前缀已存在' }));
      return true;
    }

    const existingChannel = config.channels[oldChannelKey] || config.channels[channelKey] || {};
    const configuredKeys = normalizeKeyList([
      key || existingChannel.key || '',
      ...(Array.isArray(keys) ? keys : []),
    ]);
    config.channels[channelKey] = normalizeChannelForSave({
      name: name || existingChannel.name || channelKey,
      base_url: base_url || existingChannel.base_url || '',
      key: configuredKeys[0] || '',
      keys: configuredKeys,
      ...(format || existingChannel.format ? { format: format || existingChannel.format } : {}),
      ...(anthropic_version || existingChannel.anthropic_version ? { anthropic_version: anthropic_version || existingChannel.anthropic_version } : {}),
      ...(prompt_cache_enabled ? { prompt_cache_enabled: true, prompt_cache_ttl } : {}),
      ...(anthropic_thinking_type && anthropic_thinking_type !== 'off' ? { anthropic_thinking_type } : {}),
      ...(anthropic_thinking_type === 'enabled' ? { anthropic_thinking_budget_tokens: toPositiveInteger(anthropic_thinking_budget_tokens, 32000) } : {}),
      ...(anthropic_thinking_type === 'adaptive' && anthropic_output_effort ? { anthropic_output_effort } : {}),
      ...(anthropic_thinking_type === 'adaptive' && anthropic_thinking_display ? { anthropic_thinking_display } : {}),
      models: models || [],
    });
    
    if (isRename) {
      delete config.channels[oldChannelKey];
      channelKeyCursors.delete(oldChannelKey);
      saveClientKeyEntries(getClientKeyEntries().map(entry => ({
        ...entry,
        allowed_channels: normalizeStringArray(entry.allowed_channels.map(key => key === oldChannelKey ? channelKey : key)),
      })));
    }

    rebuildModelMap();
    
    saveConfig();
    console.log(`[config] saved channel: ${channelKey}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }
  
  if (url === '/api/config/delete' && req.method === 'POST') {
    const d = JSON.parse(body);
    const { channelKey } = d;
    if (!channelKey || !config.channels[channelKey]) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    delete config.channels[channelKey];
    rebuildModelMap();
    saveConfig();
    console.log(`[config] deleted channel: ${channelKey}`);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }
  
  if (url === '/api/config/add-model' && req.method === 'POST') {
    const d = JSON.parse(body);
    const { channelKey, model } = d;
    if (!channelKey || !config.channels[channelKey]) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    if (!config.channels[channelKey].models.includes(model)) {
      config.channels[channelKey].models.push(model);
      rebuildModelMap();
      saveConfig();
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }
  
  if (url === '/api/config/remove-model' && req.method === 'POST') {
    const d = JSON.parse(body);
    const { channelKey, model } = d;
    if (!channelKey || !config.channels[channelKey]) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    config.channels[channelKey].models = config.channels[channelKey].models.filter(m => m !== model);
    rebuildModelMap();
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }
  
  // Backend proxy: probe upstream models (avoids browser CORS)
  if (url === '/api/probe-models' && req.method === 'POST') {
    try {
      const d = JSON.parse(body);
      const { base_url, key, channelKey } = d;
      const format = d.format || (channelKey && config.channels[channelKey]?.format) || '';
      if (!base_url || !key) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: '缺少 base_url 或 key' }));
        return true;
      }
      const rootUrl = base_url.replace(/\/+$/, '');
      const modelsPath = format === 'unlimited_api_chat' || /(^|\.)unlimited\.surf$/i.test(new URL(rootUrl).hostname)
        ? '/api/models'
        : '/models';
      const modelsUrl = rootUrl + modelsPath;
      const upstream = await fetch(modelsUrl, {
        headers: { 'Authorization': `Bearer ${key}`, 'Content-Type': 'application/json' },
        signal: AbortSignal.timeout(10000),
      });
      const text = await upstream.text();
      let json;
      try {
        json = JSON.parse(text);
      } catch {
        throw new Error(`上游返回非 JSON (${upstream.status})，URL: ${modelsPath}`);
      }
      if (!upstream.ok) {
        throw new Error(json?.error?.message || json?.message || `上游 HTTP ${upstream.status}`);
      }
      const models = (json.data || []).map(m => m.id || m).filter(Boolean);
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, models }));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: e.message }));
    }
    return true;
  }

  // Backend proxy: test channel by sending a minimal chat request
  if (url === '/api/test-channel' && req.method === 'POST') {
    try {
      const d = JSON.parse(body);
      const { channelKey } = d;
      const ch = config.channels[channelKey];
      if (!ch) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
        return true;
      }
      const model = ch.models[0];
      if (!model) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: '渠道没有模型' }));
        return true;
      }
      const keys = getChannelKeys(ch);
      const upstreamKey = keys[0] || '';
      const chatUrl = ch.base_url.replace(/\/+$/, '') + '/chat/completions';
      const realModel = stripModelPrefix(model, channelKey);
      const upResp = await fetch(chatUrl, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${upstreamKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: realModel, messages: [{ role: 'user', content: 'hi' }], max_tokens: 5 }),
        signal: AbortSignal.timeout(15000),
      });
      const upJson = await upResp.json();
      if (upJson.choices && upJson.choices[0]) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: true, reply: upJson.choices[0].message?.content || '(ok)' }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: upJson.error?.message || JSON.stringify(upJson) }));
      }
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: e.message }));
    }
    return true;
  }

  return false;
}

const server = http.createServer(async (req, res) => {
  const requestId = newRequestId();
  res.setHeader('X-Request-Id', requestId);
  writeGatewayLog('http_request', {
    requestId,
    method: req.method,
    url: req.url,
    client: req.socket.remoteAddress,
  });

  // CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', '*');
  
  if (req.method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }
  
  const url = req.url;
  
  // Web UI
  if (SERVE_UI && (url === '/' || url === '/ui')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync('ui.html', 'utf-8'));
    return;
  }
  
  // Health check
  if (url === '/health') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ 
      status: 'ok', 
      name: '聚合渠道',
      channels: Object.keys(config.channels).length,
      models: [...modelMap.keys()].length,
      totalRequests: stats.totalRequests
    }));
    return;
  }
  
  // Collect body for POST
  let body = '';
  if (req.method === 'POST') {
    body = await new Promise((resolve) => {
      const chunks = [];
      req.on('data', c => chunks.push(c));
      req.on('end', () => resolve(Buffer.concat(chunks).toString()));
    });
  }
  
  // Route
  if (url.startsWith('/api/')) {
    if (!adminAuth(req, res)) return;
    const handled = await handleConfigAPI(req, res, url, req.method === 'POST' ? body : '');
    if (!handled) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'API not found' } }));
    }
    return;
  }

  if (url.startsWith('/v1/')) {
    if (!clientAuth(req, res)) return;
  }
  
  if (url === '/v1/models' && req.method === 'GET') {
    await handleModels(req, res);
  } else if (url === '/v1/chat/completions' && req.method === 'POST') {
    await handleChatCompletions(req, res, body, requestId);
  } else if (url.startsWith('/v1/')) {
    // Generic proxy: try to find channel by model in body or just proxy first matching
    // For non-chat endpoints, proxy to first channel (used for embeddings etc)
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: `Not supported: ${url}`, type: 'not_implemented' } }));
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'Not found' } }));
  }
});

// 保存统计数据（程序退出时）
process.on('SIGINT', () => {
  console.log('\n保存统计数据...');
  saveStats();
  process.exit();
});

process.on('SIGTERM', () => {
  saveStats();
  process.exit();
});

server.listen(config.port, '0.0.0.0', () => {
  console.log(`========================================`);
  console.log(`聚合渠道 (API Gateway) v2.0`);
  console.log(`========================================`);
  console.log(`端口: ${config.port}`);
  console.log(`渠道数: ${Object.keys(config.channels).length}`);
  console.log(`模型总数: ${[...modelMap.keys()].length}`);
  console.log(`统计功能: 已启用`);
  console.log(`========================================`);
  
  // 显示已有统计
  if (stats.totalRequests > 0) {
    console.log(`历史请求数: ${stats.totalRequests}`);
    const topModels = Object.entries(stats.modelUsage)
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 3);
    if (topModels.length > 0) {
      console.log(`热门模型:`);
      topModels.forEach(([model, data]) => {
        console.log(`  - ${model}: ${data.count} 次`);
      });
    }
    console.log(`========================================`);
  }
});
