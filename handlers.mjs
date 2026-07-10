import crypto from 'node:crypto';
import {
  config, modelMap, stats, channelKeyCursors, resetStats, LEGACY_MODEL_ALIASES,
} from './state.mjs';
import {
  writeGatewayLog, logRequest, responseLogFields, requestLogOptions,
  getClientIp, sanitizeHeaders, buildLogContext, truncateText,
  currentLogFile, readVisibleGatewayLogs, clearCurrentGatewayLog,
  saveStats, newRequestId, fingerprintKey, recordUpstreamKeyTest,
} from './logger.mjs';
import {
  isChannelEnabled, getChannelKeys, getActiveChannelKeys, isKeyDisabled,
  normalizeKeyList, normalizeStringArray,
  normalizeExpiresAt, normalizeClientKeyEntry, normalizeChannelForSave,
  normalizeImportedConfig, rebuildModelMap, saveConfig,
  classifyUpstreamKeyFailure, disableUpstreamChannelKey, enableUpstreamChannelKey,
} from './config.mjs';
import {
  stripModelPrefix, applyOpenAICompatiblePromptCache,
  isForcedNonStreamModel, sanitizePayloadForUpstream, getConfiguredModelParams,
  reorderYepApiMessages, normalizeOpenAIFinishReason,
  convertResponsesInputToMessages, convertResponsesToolsToOpenAI,
  convertChatCompletionToResponsesFormat,
  convertAnthropicMessagesToOpenAIChat, convertOpenAIChatResultToAnthropicMessages,
  toPositiveInteger,
} from './format-converters.mjs';
import {
  getClientKeyEntries, saveClientKeyEntries, findClientKeyEntry,
  isClientKeyExpired, clientCanUseChannel, clientCanUseModel,
  getAccessibleModelEntries, getModelQuotaCost, consumeClientQuota,
  adminAuth, clientAuth,
} from './auth.mjs';
import {
  selectChannelKey, isYepApiChannel,
  proxyRequest, proxyAnthropicChatRequest, proxyUnlimitedChatRequest,
} from './proxy.mjs';

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
  let modelName = data.model;
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

  const aliasedModelName = LEGACY_MODEL_ALIASES.get(modelName);
  if (aliasedModelName) {
    writeGatewayLog('model_legacy_alias', {
      requestId,
      requestedModel: modelName,
      matchedModel: aliasedModelName,
    });
    data.model = aliasedModelName;
    modelName = aliasedModelName;
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
  const modelParams = getConfiguredModelParams(channel, modelName);
  const channelInput = channel.format === 'anthropic' || channel.format === 'unlimited_api_chat'
    ? { ...data, ...modelParams, model: realModel }
    : applyOpenAICompatiblePromptCache({ ...data, ...modelParams, model: realModel }, channel);
  const sanitized = sanitizePayloadForUpstream(channelInput, upstreamModel);
  data = sanitized.data;
  // YepAPI: reorder messages to avoid assistant-before-user pattern that triggers broken Google routing
  if (isYepApiChannel(channel) && Array.isArray(data.messages)) {
    data = reorderYepApiMessages(data);
  }
  if (isForcedNonStreamModel(entry.channelKey, upstreamModel)) {
    data.stream = false;
  }
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
    ...(Object.keys(modelParams).length ? { modelParams: Object.keys(modelParams) } : {}),
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

function getChannelKeyDashboard(channelKey, ch = {}) {
  const keys = getChannelKeys(ch);
  const disabledSet = new Set(Array.isArray(ch.disabled_keys) ? ch.disabled_keys : []);
  const disabledMeta = ch.disabled_key_meta && typeof ch.disabled_key_meta === 'object'
    ? ch.disabled_key_meta
    : {};
  const rows = keys.map((key, index) => {
    const fingerprint = fingerprintKey(key);
    const usage = stats.upstreamKeyUsage?.[fingerprint] || {};
    const meta = disabledMeta[key] || {};
    return {
      id: fingerprint,
      index,
      key,
      maskedKey: key.length <= 8 ? `${key.slice(0, 1)}***${key.slice(-1)}` : `${key.slice(0, 6)}…${key.slice(-4)}`,
      enabled: !disabledSet.has(key),
      disabledReason: meta.reason || '',
      disabledStatus: meta.status || null,
      disabledAt: meta.disabled_at || '',
      lastError: usage.lastError || meta.last_error || '',
      lastErrorAt: usage.lastErrorAt || meta.last_error_at || '',
      lastUsedAt: usage.lastUsedAt || null,
      lastStatus: usage.lastStatus || null,
      lastTestAt: usage.lastTestAt || null,
      lastTestStatus: usage.lastTestStatus || null,
      lastTestPassed: typeof usage.lastTestPassed === 'boolean' ? usage.lastTestPassed : null,
      totalRequests: Number(usage.totalRequests) || 0,
      totalErrors: Number(usage.totalErrors) || 0,
      totalInputTokens: Number(usage.totalInputTokens) || 0,
      totalOutputTokens: Number(usage.totalOutputTokens) || 0,
    };
  });
  return {
    channelKey,
    name: ch.name || channelKey,
    keys: rows,
    totals: rows.reduce((total, row) => ({
      total: total.total + 1,
      enabled: total.enabled + (row.enabled ? 1 : 0),
      disabled: total.disabled + (row.enabled ? 0 : 1),
      requests: total.requests + row.totalRequests,
      errors: total.errors + row.totalErrors,
      inputTokens: total.inputTokens + row.totalInputTokens,
      outputTokens: total.outputTokens + row.totalOutputTokens,
    }), { total: 0, enabled: 0, disabled: 0, requests: 0, errors: 0, inputTokens: 0, outputTokens: 0 }),
  };
}

function parseUpstreamTestPayload(text = '') {
  try {
    return JSON.parse(text);
  } catch {
    for (const line of String(text).split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('data: ')) continue;
      const payload = trimmed.slice(6);
      if (!payload || payload === '[DONE]') continue;
      try { return JSON.parse(payload); } catch { /* continue */ }
    }
  }
  return null;
}

async function testUpstreamChannelKey(channelKey, key, options = {}) {
  const ch = config.channels[channelKey];
  if (!ch) return { ok: false, pass: false, error: '渠道不存在', status: null };
  const trimmedKey = String(key || '').trim();
  if (!trimmedKey || !getChannelKeys(ch).includes(trimmedKey)) {
    return { ok: false, pass: false, error: 'Key 不存在', status: null };
  }
  const model = ch.models?.[0];
  if (!model) return { ok: false, pass: false, error: '渠道没有模型', status: null };

  const realModel = stripModelPrefix(model, channelKey);
  const format = ch.format || '';
  const baseUrl = ch.base_url.replace(/\/+$/, '');
  let chatUrl;
  let headers;
  let requestBody;
  if (format === 'anthropic') {
    chatUrl = `${baseUrl}/messages`;
    headers = {
      'Content-Type': 'application/json',
      'x-api-key': trimmedKey,
      'anthropic-version': ch.anthropic_version || '2023-06-01',
    };
    requestBody = { model: realModel, max_tokens: 5, messages: [{ role: 'user', content: 'ping' }] };
  } else if (format === 'unlimited_api_chat') {
    chatUrl = `${baseUrl}/api/chat`;
    headers = { 'Content-Type': 'application/json', 'Authorization': `Bearer ${trimmedKey}` };
    requestBody = { model: realModel, prompt: 'ping' };
  } else {
    chatUrl = `${baseUrl}/chat/completions`;
    headers = isYepApiChannel(ch)
      ? { 'Content-Type': 'application/json', 'x-api-key': trimmedKey }
      : { 'Content-Type': 'application/json', 'Authorization': `Bearer ${trimmedKey}` };
    requestBody = { model: realModel, messages: [{ role: 'user', content: 'ping' }], max_tokens: 5, stream: false };
  }

  try {
    const upstream = await fetch(chatUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(requestBody),
      signal: AbortSignal.timeout(15000),
    });
    const text = await upstream.text();
    const data = parseUpstreamTestPayload(text);
    const errorMessage = data?.error?.message
      || (typeof data?.error === 'string' ? data.error : '')
      || data?.message
      || (upstream.ok ? '' : truncateText(text, 500))
      || (upstream.ok ? '' : `HTTP ${upstream.status}`);
    const pass = upstream.ok && !errorMessage;
    const verdict = pass
      ? { disable: false, retry: false, reason: '' }
      : classifyUpstreamKeyFailure(upstream.status, errorMessage);
    let autoDisabled = false;
    let reenabled = false;
    if (!pass && verdict.disable && options.autoDisable !== false) {
      autoDisabled = disableUpstreamChannelKey(channelKey, trimmedKey, {
        status: upstream.status,
        reason: verdict.reason,
        error: errorMessage,
      });
    } else if (pass && options.reenable === true && isKeyDisabled(ch, trimmedKey)) {
      reenabled = enableUpstreamChannelKey(channelKey, trimmedKey);
    }
    const reply = data?.choices?.[0]?.message?.content
      || data?.content?.[0]?.text
      || data?.output_text
      || (pass ? '(ok)' : '');
    recordUpstreamKeyTest(fingerprintKey(trimmedKey), {
      success: pass,
      statusCode: upstream.status,
      error: errorMessage || verdict.reason,
    });
    return {
      ok: true,
      pass,
      status: upstream.status,
      id: fingerprintKey(trimmedKey),
      key: trimmedKey,
      reply: truncateText(reply, 200),
      error: pass ? '' : (errorMessage || verdict.reason || `HTTP ${upstream.status}`),
      reason: pass ? '' : (verdict.reason || `http_${upstream.status}`),
      excerpt: truncateText(text, 300),
      autoDisabled,
      reenabled,
    };
  } catch (err) {
    recordUpstreamKeyTest(fingerprintKey(trimmedKey), {
      success: false,
      statusCode: null,
      error: `network:${err.message}`,
    });
    return {
      ok: true,
      pass: false,
      status: null,
      id: fingerprintKey(trimmedKey),
      key: trimmedKey,
      error: `network:${err.message}`,
      reason: `network:${err.message}`,
      autoDisabled: false,
      reenabled: false,
    };
  }
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

  if (url.startsWith('/api/config/channel-keys?') && req.method === 'GET') {
    const parsed = new URL(url, 'http://localhost');
    const channelKey = String(parsed.searchParams.get('channelKey') || '');
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, ...getChannelKeyDashboard(channelKey, ch) }));
    return true;
  }

  if (url.startsWith('/api/config/channel-keys/export?') && req.method === 'GET') {
    const parsed = new URL(url, 'http://localhost');
    const channelKey = String(parsed.searchParams.get('channelKey') || '');
    const only = String(parsed.searchParams.get('only') || 'all');
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    const disabled = new Set(ch.disabled_keys || []);
    let keys = getChannelKeys(ch);
    if (only === 'enabled') keys = keys.filter(key => !disabled.has(key));
    if (only === 'disabled') keys = keys.filter(key => disabled.has(key));
    const stamp = new Date().toISOString().replace(/[:.]/g, '-');
    res.writeHead(200, {
      'Content-Type': 'text/plain; charset=utf-8',
      'Content-Disposition': `attachment; filename="${channelKey}-keys-${only}-${stamp}.txt"`,
    });
    res.end(keys.join('\n') + (keys.length ? '\n' : ''));
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

  if (url === '/api/logs/clear' && req.method === 'POST') {
    try {
      clearCurrentGatewayLog();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, file: currentLogFile() }));
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: err.message || '清空日志失败' }));
    }
    return true;
  }

  if (url === '/api/stats' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(stats));
    return true;
  }

  if (url === '/api/stats/reset' && req.method === 'POST') {
    resetStats();
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
      model_prefix,
      enabled,
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
      disabled_keys: existingChannel.disabled_keys,
      disabled_key_meta: existingChannel.disabled_key_meta,
      ...(format || existingChannel.format ? { format: format || existingChannel.format } : {}),
      ...(anthropic_version || existingChannel.anthropic_version ? { anthropic_version: anthropic_version || existingChannel.anthropic_version } : {}),
      ...(prompt_cache_enabled ? { prompt_cache_enabled: true, prompt_cache_ttl } : {}),
      ...(anthropic_thinking_type && anthropic_thinking_type !== 'off' ? { anthropic_thinking_type } : {}),
      ...(anthropic_thinking_type === 'enabled' ? { anthropic_thinking_budget_tokens: toPositiveInteger(anthropic_thinking_budget_tokens, 32000) } : {}),
      ...(anthropic_thinking_type === 'adaptive' && anthropic_output_effort ? { anthropic_output_effort } : {}),
      ...(anthropic_thinking_type === 'adaptive' && anthropic_thinking_display ? { anthropic_thinking_display } : {}),
      ...(Object.prototype.hasOwnProperty.call(d, 'model_prefix') ? { model_prefix } : {}),
      enabled: enabled !== false,
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

  if (url === '/api/config/channel-enabled' && req.method === 'POST') {
    const d = JSON.parse(body);
    const { channelKey, enabled } = d;
    if (!channelKey || !config.channels[channelKey]) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    config.channels[channelKey] = normalizeChannelForSave({
      ...config.channels[channelKey],
      enabled: enabled !== false,
    });
    if (enabled === false) channelKeyCursors.delete(channelKey);
    rebuildModelMap();
    saveConfig();
    console.log(`[config] ${enabled === false ? 'disabled' : 'enabled'} channel: ${channelKey}`);
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
      if (!isChannelEnabled(ch)) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: '渠道已禁用' }));
        return true;
      }
      const model = ch.models[0];
      if (!model) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: '渠道没有模型' }));
        return true;
      }
      const activeKeys = getActiveChannelKeys(ch);
      if (!activeKeys.length) {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ ok: false, error: '渠道没有可用 Key，请先恢复或导入 Key' }));
        return true;
      }
      const result = await testUpstreamChannelKey(channelKey, activeKeys[0], { autoDisable: true });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        ok: result.pass === true,
        reply: result.reply || '',
        error: result.pass ? '' : (result.error || result.reason || '测试失败'),
        status: result.status,
        autoDisabled: result.autoDisabled === true,
      }));
    } catch (e) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: e.message }));
    }
    return true;
  }

  // ==================== Channel Key 管理 ====================

  if (url === '/api/config/channel-keys/test' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const result = await testUpstreamChannelKey(d.channelKey, d.key, {
      reenable: d.reenable === true,
      autoDisable: d.autoDisable !== false,
    });
    res.writeHead(result.ok === false ? 400 : 200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(result));
    return true;
  }

  if (url === '/api/config/channel-keys/batch-test' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const channelKey = String(d.channelKey || '');
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    const allKeys = getChannelKeys(ch);
    const requestedKeys = normalizeKeyList(Array.isArray(d.keys) ? d.keys : []);
    const targets = (requestedKeys.length ? requestedKeys : allKeys)
      .filter(key => allKeys.includes(key));
    const concurrency = Math.min(Math.max(parseInt(d.concurrency || '5', 10) || 5, 1), 20);
    const results = new Array(targets.length);
    let cursor = 0;
    async function worker() {
      while (cursor < targets.length) {
        const index = cursor++;
        results[index] = await testUpstreamChannelKey(channelKey, targets[index], {
          reenable: d.reenable === true,
          autoDisable: d.autoDisable !== false,
        });
      }
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, targets.length || 1) }, () => worker()));
    const passed = results.filter(result => result.pass).length;
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      ok: true,
      results,
      summary: { total: results.length, pass: passed, fail: results.length - passed },
    }));
    return true;
  }

  if (url === '/api/config/channel-keys/disable' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const { channelKey, key } = d;
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    const trimmedKey = String(key || '').trim();
    if (!trimmedKey || !getChannelKeys(ch).includes(trimmedKey)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Key 不存在' }));
      return true;
    }
    disableUpstreamChannelKey(channelKey, trimmedKey, { reason: 'manual' });
    rebuildModelMap();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }

  if (url === '/api/config/channel-keys/enable' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const { channelKey, key } = d;
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    const trimmedKey = String(key || '').trim();
    if (!trimmedKey || !getChannelKeys(ch).includes(trimmedKey)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Key 不存在' }));
      return true;
    }
    enableUpstreamChannelKey(channelKey, trimmedKey);
    rebuildModelMap();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }

  if (url === '/api/config/channel-keys/enable-all' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const channelKey = String(d.channelKey || '');
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    let enabled = 0;
    for (const key of [...(ch.disabled_keys || [])]) {
      if (enableUpstreamChannelKey(channelKey, key)) enabled++;
    }
    rebuildModelMap();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, enabled }));
    return true;
  }

  if (url === '/api/config/channel-keys/edit' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const channelKey = String(d.channelKey || '');
    const oldKey = String(d.key || '').trim();
    const newKey = String(d.newKey || '').trim();
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    const allKeys = getChannelKeys(ch);
    const index = allKeys.indexOf(oldKey);
    if (index < 0) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Key 不存在' }));
      return true;
    }
    if (!newKey) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '新 Key 不能为空' }));
      return true;
    }
    if (allKeys.some((key, keyIndex) => key === newKey && keyIndex !== index)) {
      res.writeHead(409, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '新 Key 已存在' }));
      return true;
    }
    const nextKeys = [...allKeys];
    nextKeys[index] = newKey;
    const wasDisabled = isKeyDisabled(ch, oldKey);
    const disabledKeys = (ch.disabled_keys || []).filter(key => key !== oldKey);
    if (wasDisabled) disabledKeys.push(newKey);
    const disabledMeta = { ...(ch.disabled_key_meta || {}) };
    if (disabledMeta[oldKey]) {
      disabledMeta[newKey] = disabledMeta[oldKey];
      delete disabledMeta[oldKey];
    }
    config.channels[channelKey] = normalizeChannelForSave({
      ...ch,
      key: nextKeys[0],
      keys: nextKeys,
      disabled_keys: disabledKeys,
      disabled_key_meta: disabledMeta,
    });
    channelKeyCursors.delete(channelKey);
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, id: fingerprintKey(newKey) }));
    return true;
  }

  if (url === '/api/config/channel-keys/delete-batch' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const channelKey = String(d.channelKey || '');
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    const allKeys = getChannelKeys(ch);
    const deleteSet = new Set(normalizeKeyList(Array.isArray(d.keys) ? d.keys : []));
    const remainingKeys = allKeys.filter(key => !deleteSet.has(key));
    const deleted = allKeys.length - remainingKeys.length;
    if (!deleted) {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true, deleted: 0, total: allKeys.length }));
      return true;
    }
    if (!remainingKeys.length) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '至少保留一个 Key' }));
      return true;
    }
    config.channels[channelKey] = normalizeChannelForSave({ ...ch, key: remainingKeys[0], keys: remainingKeys });
    channelKeyCursors.delete(channelKey);
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, deleted, total: remainingKeys.length }));
    return true;
  }

  if (url === '/api/config/channel-keys/delete-disabled' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const channelKey = String(d.channelKey || '');
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    const allKeys = getChannelKeys(ch);
    const disabledSet = new Set(ch.disabled_keys || []);
    const remainingKeys = allKeys.filter(key => !disabledSet.has(key));
    if (!remainingKeys.length && allKeys.length) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '不能删除全部 Key，请先恢复至少一个' }));
      return true;
    }
    config.channels[channelKey] = normalizeChannelForSave({ ...ch, key: remainingKeys[0] || '', keys: remainingKeys });
    channelKeyCursors.delete(channelKey);
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, deleted: allKeys.length - remainingKeys.length, total: remainingKeys.length }));
    return true;
  }

  if (url === '/api/config/channel-keys/delete' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const { channelKey, key } = d;
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    const trimmedKey = String(key || '').trim();
    const allKeys = getChannelKeys(ch);
    if (!allKeys.includes(trimmedKey)) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: 'Key 不存在' }));
      return true;
    }
    if (allKeys.length <= 1) {
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '至少保留一个 Key' }));
      return true;
    }
    const remainingKeys = allKeys.filter(k => k !== trimmedKey);
    config.channels[channelKey] = normalizeChannelForSave({
      ...ch,
      key: remainingKeys[0],
      keys: remainingKeys,
    });
    rebuildModelMap();
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true }));
    return true;
  }

  if (url === '/api/config/channel-keys/import' && req.method === 'POST') {
    const d = JSON.parse(body || '{}');
    const { channelKey, keys: keysText } = d;
    const ch = config.channels[channelKey];
    if (!ch) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: false, error: '渠道不存在' }));
      return true;
    }
    const existingKeys = getChannelKeys(ch);
    const newKeys = normalizeKeyList([
      ...existingKeys,
      ...String(keysText || '').split(/[\r\n,]+/).map(k => k.trim()).filter(Boolean),
    ]);
    const addedCount = newKeys.length - existingKeys.length;
    config.channels[channelKey] = normalizeChannelForSave({
      ...ch,
      key: newKeys[0],
      keys: newKeys,
    });
    rebuildModelMap();
    saveConfig();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ ok: true, added: addedCount, total: newKeys.length }));
    return true;
  }

  return false;
}

async function handleResponses(req, res, body, requestId) {
  // Override req.url so downstream proxying calls use /v1/chat/completions
  const originalUrl = req.url;
  req.url = '/v1/chat/completions';

  let data;
  try {
    data = JSON.parse(body);
  } catch (err) {
    req.url = originalUrl;
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'Invalid JSON body', type: 'invalid_request' } }));
    return;
  }
  const wantsStream = data.stream === true;
  const messages = convertResponsesInputToMessages(data.input);
  if (data.instructions) {
    messages.unshift({ role: 'system', content: data.instructions });
  }
  const chatData = {
    model: data.model,
    messages,
    stream: wantsStream,
  };
  if (data.temperature != null) chatData.temperature = data.temperature;
  if (data.top_p != null) chatData.top_p = data.top_p;
  if (data.max_output_tokens != null) chatData.max_tokens = data.max_output_tokens;
  if (data.max_tokens != null) chatData.max_tokens = data.max_tokens;
  const tools = convertResponsesToolsToOpenAI(data.tools);
  if (tools?.length) chatData.tools = tools;
  if (data.tool_choice) chatData.tool_choice = data.tool_choice;

  if (wantsStream) {
    const chatBody = JSON.stringify(chatData);
    let headersSent = false;
    let isFirst = true;
    const responseId = 'resp_' + newRequestId();
    const msgId = 'msg_' + newRequestId();
    const fakeRes = {
      headersSent: false,
      writableEnded: false,
      writeHead(status, headers) {
        if (!headersSent) {
          if (status >= 400) {
            res.writeHead(status, { 'Content-Type': 'application/json' });
          } else {
            res.writeHead(200, {
              'Content-Type': 'text/event-stream; charset=utf-8',
              'Cache-Control': 'no-cache',
              'Connection': 'keep-alive',
            });
          }
          headersSent = true;
        }
        fakeRes.headersSent = true;
      },
      setHeader() { },
      getHeader(name) { return res.getHeader(name); },
      write(chunk) {
        const str = typeof chunk === 'string' ? chunk : chunk.toString();
        for (const line of str.split('\n')) {
          const trimmed = line.trim();
          if (!trimmed.startsWith('data: ')) continue;
          const payload = trimmed.slice(6);
          if (payload === '[DONE]') {
            res.write('data: ' + JSON.stringify({ type: 'response.output_text.done', output_index: 0, content_index: 0 }) + '\n\n');
            res.write('data: ' + JSON.stringify({ type: 'response.content_part.done', output_index: 0, content_index: 0 }) + '\n\n');
            res.write('data: ' + JSON.stringify({ type: 'response.output_item.done', output_index: 0 }) + '\n\n');
            res.write('data: ' + JSON.stringify({ type: 'response.completed' }) + '\n\n');
            return;
          }
          try {
            const chatChunk = JSON.parse(payload);
            if (isFirst) {
              isFirst = false;
              res.write('data: ' + JSON.stringify({
                type: 'response.created',
                response: { id: responseId, object: 'response', status: 'in_progress', model: data.model || chatChunk.model || '', output: [] },
              }) + '\n\n');
              res.write('data: ' + JSON.stringify({ type: 'response.in_progress' }) + '\n\n');
              res.write('data: ' + JSON.stringify({
                type: 'response.output_item.added', output_index: 0,
                item: { type: 'message', id: msgId, role: 'assistant', status: 'in_progress', content: [] },
              }) + '\n\n');
              res.write('data: ' + JSON.stringify({
                type: 'response.content_part.added', output_index: 0, content_index: 0,
                part: { type: 'output_text', text: '', annotations: [] },
              }) + '\n\n');
            }
            const delta = chatChunk.choices?.[0]?.delta;
            if (delta?.content) {
              res.write('data: ' + JSON.stringify({
                type: 'response.output_text.delta', output_index: 0, content_index: 0, delta: delta.content,
              }) + '\n\n');
            }
          } catch { }
        }
      },
      end(endData) {
        if (endData) fakeRes.write(endData);
        if (!res.writableEnded) res.end();
        fakeRes.writableEnded = true;
      },
    };
    await handleChatCompletions(req, fakeRes, chatBody, requestId);
    return;
  }

  // Non-streaming
  const chatBody = JSON.stringify(chatData);
  let capturedStatus = 200;
  let capturedBody = '';
  const fakeRes = {
    headersSent: false,
    writableEnded: false,
    writeHead(status) { capturedStatus = status; fakeRes.headersSent = true; },
    setHeader() { },
    getHeader(name) { return res.getHeader(name); },
    write(chunk) { capturedBody += (typeof chunk === 'string' ? chunk : chunk.toString()); },
    end(endData) {
      if (endData) capturedBody += (typeof endData === 'string' ? endData : endData.toString());
      fakeRes.writableEnded = true;
    },
  };
  await handleChatCompletions(req, fakeRes, chatBody, requestId);
  if (capturedStatus >= 400) {
    res.writeHead(capturedStatus, { 'Content-Type': 'application/json' });
    res.end(capturedBody);
    return;
  }
  try {
    const chatResult = JSON.parse(capturedBody);
    const responsesResult = convertChatCompletionToResponsesFormat(chatResult, data.model);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(responsesResult));
  } catch {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(capturedBody);
  }
}

async function handleAnthropicMessages(req, res, body, requestId) {
  // Override req.url so downstream proxying calls use /v1/chat/completions
  const originalUrl = req.url;
  req.url = '/v1/chat/completions';

  let data;
  try {
    data = JSON.parse(body);
  } catch (err) {
    req.url = originalUrl;
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ type: 'error', error: { type: 'invalid_request_error', message: 'Invalid JSON body' } }));
    return;
  }
  const wantsStream = data.stream === true;
  const messages = convertAnthropicMessagesToOpenAIChat(data);
  const chatData = {
    model: data.model,
    messages,
    stream: wantsStream,
  };
  if (data.max_tokens != null) chatData.max_tokens = data.max_tokens;
  if (data.temperature != null) chatData.temperature = data.temperature;
  if (data.top_p != null) chatData.top_p = data.top_p;
  if (data.stop_sequences) chatData.stop = data.stop_sequences;
  if (data.thinking) chatData.thinking = data.thinking;
  if (Array.isArray(data.tools)) {
    chatData.tools = data.tools.map(tool => ({
      type: 'function',
      function: {
        name: tool.name || '',
        description: tool.description || '',
        parameters: tool.input_schema || { type: 'object', properties: {} },
      },
    }));
  }
  if (data.tool_choice) {
    if (data.tool_choice.type === 'auto') chatData.tool_choice = 'auto';
    else if (data.tool_choice.type === 'none') chatData.tool_choice = 'none';
    else if (data.tool_choice.type === 'any') chatData.tool_choice = 'required';
    else if (data.tool_choice.type === 'tool' && data.tool_choice.name) {
      chatData.tool_choice = { type: 'function', function: { name: data.tool_choice.name } };
    }
  }

  if (wantsStream) {
    const chatBody = JSON.stringify(chatData);
    let headersSent = false;
    let isFirst = true;
    const msgId = (data.model || '').replace('chatcmpl-', 'msg_') || ('msg_' + newRequestId());
    const fakeRes = {
      headersSent: false,
      writableEnded: false,
      writeHead(status, headers) {
        if (!headersSent) {
          if (status >= 400) {
            res.writeHead(status, { 'Content-Type': 'application/json' });
          } else {
            res.writeHead(200, {
              'Content-Type': 'text/event-stream; charset=utf-8',
              'Cache-Control': 'no-cache',
              'Connection': 'keep-alive',
            });
          }
          headersSent = true;
        }
        fakeRes.headersSent = true;
      },
      setHeader() { },
      getHeader(name) { return res.getHeader(name); },
      write(chunk) {
        const str = typeof chunk === 'string' ? chunk : chunk.toString();
        for (const line of str.split('\n')) {
          const trimmed = line.trim();
          if (!trimmed.startsWith('data: ')) continue;
          const payload = trimmed.slice(6);
          if (payload === '[DONE]') {
            res.write('event: content_block_stop\ndata: ' + JSON.stringify({ type: 'content_block_stop', index: 0 }) + '\n\n');
            res.write('event: message_delta\ndata: ' + JSON.stringify({
              type: 'message_delta', delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: { output_tokens: 0 },
            }) + '\n\n');
            res.write('event: message_stop\ndata: ' + JSON.stringify({ type: 'message_stop' }) + '\n\n');
            return;
          }
          try {
            const chatChunk = JSON.parse(payload);
            if (isFirst) {
              isFirst = false;
              const startMsg = {
                id: (chatChunk.id || '').replace('chatcmpl-', 'msg_') || ('msg_' + newRequestId()),
                type: 'message', role: 'assistant', model: data.model || chatChunk.model || '',
                content: [], stop_reason: null, stop_sequence: null,
                usage: { input_tokens: 0, output_tokens: 0 },
              };
              res.write('event: message_start\ndata: ' + JSON.stringify({ type: 'message_start', message: startMsg }) + '\n\n');
              res.write('event: content_block_start\ndata: ' + JSON.stringify({
                type: 'content_block_start', index: 0, content_block: { type: 'text', text: '' },
              }) + '\n\n');
              res.write('event: ping\ndata: ' + JSON.stringify({ type: 'ping' }) + '\n\n');
            }
            const delta = chatChunk.choices?.[0]?.delta;
            if (delta?.content) {
              res.write('event: content_block_delta\ndata: ' + JSON.stringify({
                type: 'content_block_delta', index: 0, delta: { type: 'text_delta', text: delta.content },
              }) + '\n\n');
            }
            if (chatChunk.choices?.[0]?.finish_reason) {
              let sr = 'end_turn';
              if (chatChunk.choices[0].finish_reason === 'length') sr = 'max_tokens';
              else if (chatChunk.choices[0].finish_reason === 'tool_calls') sr = 'tool_use';
              res.write('event: content_block_stop\ndata: ' + JSON.stringify({ type: 'content_block_stop', index: 0 }) + '\n\n');
              res.write('event: message_delta\ndata: ' + JSON.stringify({
                type: 'message_delta', delta: { stop_reason: sr, stop_sequence: null }, usage: { output_tokens: 0 },
              }) + '\n\n');
              res.write('event: message_stop\ndata: ' + JSON.stringify({ type: 'message_stop' }) + '\n\n');
            }
          } catch { }
        }
      },
      end(endData) {
        if (endData) fakeRes.write(endData);
        if (!res.writableEnded) res.end();
        fakeRes.writableEnded = true;
      },
    };
    await handleChatCompletions(req, fakeRes, chatBody, requestId);
    return;
  }

  // Non-streaming
  const chatBody = JSON.stringify(chatData);
  let capturedStatus = 200;
  let capturedBody = '';
  const fakeRes = {
    headersSent: false,
    writableEnded: false,
    writeHead(status) { capturedStatus = status; fakeRes.headersSent = true; },
    setHeader() { },
    getHeader(name) { return res.getHeader(name); },
    write(chunk) { capturedBody += (typeof chunk === 'string' ? chunk : chunk.toString()); },
    end(endData) {
      if (endData) capturedBody += (typeof endData === 'string' ? endData : endData.toString());
      fakeRes.writableEnded = true;
    },
  };
  await handleChatCompletions(req, fakeRes, chatBody, requestId);
  if (capturedStatus >= 400) {
    try {
      const errData = JSON.parse(capturedBody);
      res.writeHead(capturedStatus, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        type: 'error',
        error: { type: errData.error?.type || 'api_error', message: errData.error?.message || 'Unknown error' },
      }));
    } catch {
      res.writeHead(capturedStatus, { 'Content-Type': 'application/json' });
      res.end(capturedBody);
    }
    return;
  }
  try {
    const chatResult = JSON.parse(capturedBody);
    const anthropicResult = convertOpenAIChatResultToAnthropicMessages(chatResult, data.model);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(anthropicResult));
  } catch (err) {
    console.error('Failed to parse chat completion for Anthropic converter:', err.message, 'Captured Body:', capturedBody);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(capturedBody);
  }
}


export {
  handleChatCompletions,
  handleModels,
  handleConfigAPI,
  handleResponses,
  handleAnthropicMessages,
};
