import http from 'node:http';
import https from 'node:https';
import { channelKeyCursors } from './state.mjs';
import {
  writeGatewayLog, logRequest, responseLogFields, requestLogOptions,
  extractResponseLogDetails, extractTokenUsageDetails, truncateText, newRequestId,
  fingerprintKey,
} from './logger.mjs';
import {
  stripModelPrefix, normalizeOpenAIFinishReason, buildUnlimitedChatPayload,
  buildOpenAIChatCompletion, convertOpenAIChatToAnthropic,
  convertAnthropicResponseToOpenAI, getAnthropicBetaHeader,
  shouldBufferNonStreamResponse, isWorkBuddySensitiveClaudeChannel,
} from './format-converters.mjs';
import {
  getChannelKeys, getActiveChannelKeys, isChannelEnabled,
  classifyUpstreamKeyFailure, disableUpstreamChannelKey,
} from './config.mjs';

function handleSelectedKeyFailure(channel, channelKey, selectedKey, statusCode, errorMessage = '') {
  const verdict = classifyUpstreamKeyFailure(statusCode, errorMessage);
  if (!verdict.disable || !selectedKey?.key || !channelKey) return verdict;
  if (disableUpstreamChannelKey(channelKey, selectedKey.key, {
    status: verdict.status,
    reason: verdict.reason,
    error: errorMessage,
  })) {
    writeGatewayLog('upstream_key_disabled', {
      channelKey,
      channel: channel.name,
      upstreamKeyFingerprint: selectedKey.fingerprint,
      statusCode: verdict.status,
      errorMessage,
      reason: verdict.reason,
    });
  }
  return verdict;
}

function selectChannelKey(channel = {}, channelKey = '', excludedKeys = new Set()) {
  const allKeys = getChannelKeys(channel);
  const excluded = excludedKeys instanceof Set ? excludedKeys : new Set(excludedKeys || []);
  const activeKeys = getActiveChannelKeys(channel).filter(key => !excluded.has(key));
  if (allKeys.length === 0 || activeKeys.length === 0) return { key: '', index: -1, count: allKeys.length, fingerprint: '' };
  let selectedKey;
  let index = 0;
  if (channel.key_strategy === 'sticky') {
    selectedKey = activeKeys[0];
  } else {
    const cursorKey = channelKey || channel.name || channel.base_url || 'default';
    const cursor = channelKeyCursors.get(cursorKey) || 0;
    index = cursor % activeKeys.length;
    channelKeyCursors.set(cursorKey, (cursor + 1) % activeKeys.length);
    selectedKey = activeKeys[index];
  }
  // index in allKeys for logging purposes
  const allIndex = allKeys.indexOf(selectedKey);
  return {
    key: selectedKey,
    index: allIndex >= 0 ? allIndex : index,
    count: allKeys.length,
    // 按渠道作用域生成指纹，避免多个渠道共用同一上游 Key 时统计合并
    fingerprint: fingerprintKey(selectedKey, channelKey || channel.name || ''),
  };
}

function hasUntriedActiveKey(channel = {}, attemptedKeys = new Set()) {
  const attempted = attemptedKeys instanceof Set ? attemptedKeys : new Set(attemptedKeys || []);
  return getActiveChannelKeys(channel).some(key => !attempted.has(key));
}

function shouldRetryWithAnotherKey(verdict = {}, channel = {}, attemptedKeys = new Set()) {
  return Boolean(verdict.disable || verdict.retry) && hasUntriedActiveKey(channel, attemptedKeys);
}

function payloadHasToolCalls(payload) {
  if (!payload || typeof payload !== 'object') return false;
  if (Array.isArray(payload)) return payload.some(payloadHasToolCalls);
  if (Array.isArray(payload.tool_calls) && payload.tool_calls.length > 0) return true;
  if (payload.function_call && typeof payload.function_call === 'object') return true;
  if (payload.type === 'tool_use' || payload.type === 'function_call') return true;
  return Object.values(payload).some(payloadHasToolCalls);
}

function responseHasToolCalls(responseData = '') {
  const raw = String(responseData || '').trim();
  if (!raw) return false;
  try {
    return payloadHasToolCalls(JSON.parse(raw));
  } catch {}
  for (const line of raw.split(/\r?\n/)) {
    if (!line.startsWith('data:')) continue;
    const value = line.slice(5).trim();
    if (!value || value === '[DONE]') continue;
    try {
      if (payloadHasToolCalls(JSON.parse(value))) return true;
    } catch {}
  }
  return false;
}

function shouldRepairToolArguments(channelKey = '', modelName = '') {
  return channelKey === 'aprilseries' && String(modelName).includes('claude-opus-5');
}

// freepi 上游在工具调用时会憋到整段生成完才回响应头，期间连接完全静默。
// 网关先回 SSE 头并定时发注释行保活，避免客户端/反代判定空闲断开。
const SSE_HEARTBEAT_MS = 15000;

function shouldSendSseHeartbeat(channelKey = '') {
  return channelKey === 'freepi';
}

function startSseHeartbeat(res) {
  if (res.sseHeartbeat || res.headersSent) return;
  res.writeHead(200, {
    'Content-Type': 'text/event-stream; charset=utf-8',
    'Cache-Control': 'no-cache',
    'X-Accel-Buffering': 'no',
  });
  res.write(': keepalive\n\n');
  const timer = setInterval(() => {
    if (!res.writableEnded) res.write(': keepalive\n\n');
  }, SSE_HEARTBEAT_MS);
  res.sseHeartbeat = { timer, upstreamDataSent: false };
  res.on('close', () => clearInterval(timer));
}

function stopSseHeartbeat(res) {
  if (res.sseHeartbeat) clearInterval(res.sseHeartbeat.timer);
}

// 只发过心跳、还没转发任何上游数据时，仍可换 Key 重试
function canRetryResponse(res) {
  return !res.headersSent || (res.sseHeartbeat && !res.sseHeartbeat.upstreamDataSent);
}

function endSseWithError(res, statusCode, message) {
  stopSseHeartbeat(res);
  if (res.writableEnded) return;
  res.write(`data: ${JSON.stringify({ error: { message, type: 'upstream_error', code: statusCode } })}\n\n`);
  res.end();
}

function shouldUnwrapClineResponse(channelKey = '') {
  return channelKey === 'cline';
}

function unwrapClineResponse(responseData = '') {
  const raw = String(responseData || '');
  if (!raw.trim()) return raw;
  try {
    const payload = JSON.parse(raw);
    if (payload?.success === true && payload.data && typeof payload.data === 'object') {
      return JSON.stringify(payload.data);
    }
  } catch {}
  return raw;
}

function normalizeMlpalResponse(responseData = '', modelName = '') {
  try {
    const payload = JSON.parse(responseData);
    if (!payload || typeof payload !== 'object' || Array.isArray(payload) || Array.isArray(payload.choices)) return responseData;
    if (payload.role !== 'assistant' || (!Object.hasOwn(payload, 'content') && !Array.isArray(payload.tool_calls))) return responseData;
    const tokens = payload.cost?.tokens || {};
    const content = typeof payload.content === 'string'
      ? payload.content
      : Array.isArray(payload.content)
        ? payload.content.map((part) => typeof part === 'string' ? part : part?.text || '').join('')
        : null;
    return JSON.stringify({
      id: payload.metadata?.trace_id || `chatcmpl-${newRequestId()}`,
      object: 'chat.completion',
      created: Math.floor(Date.now() / 1000),
      model: modelName || payload.cost?.model_name || '',
      choices: [{
        index: 0,
        message: {
          role: 'assistant',
          content,
          ...(Array.isArray(payload.tool_calls) && payload.tool_calls.length ? { tool_calls: payload.tool_calls } : {}),
        },
        finish_reason: normalizeOpenAIFinishReason(payload.finish_reason || 'stop'),
      }],
      usage: {
        prompt_tokens: Number(tokens.input_tokens) || 0,
        completion_tokens: Number(tokens.output_tokens) || 0,
        total_tokens: Number(tokens.total_tokens) || 0,
      },
    });
  } catch {
    return responseData;
  }
}

function mlpalResponseToSse(responseData = '') {
  try {
    const payload = JSON.parse(responseData);
    if (payload?.object !== 'chat.completion' || !Array.isArray(payload.choices)) return responseData;
    const choice = payload.choices[0] || {};
    const message = choice.message || {};
    const common = {
      id: payload.id,
      object: 'chat.completion.chunk',
      created: payload.created,
      model: payload.model,
    };
    const delta = {
      role: 'assistant',
      ...(message.content != null ? { content: message.content } : {}),
      ...(Array.isArray(message.tool_calls) && message.tool_calls.length ? { tool_calls: message.tool_calls } : {}),
    };
    return [
      `data: ${JSON.stringify({ ...common, choices: [{ index: 0, delta, finish_reason: null }] })}\n\n`,
      `data: ${JSON.stringify({ ...common, choices: [{ index: 0, delta: {}, finish_reason: choice.finish_reason || 'stop' }] })}\n\n`,
      'data: [DONE]\n\n',
    ].join('');
  } catch {
    return responseData;
  }
}

function normalizeMlpalStreamBody(body) {
  const source = JSON.parse(body);
  const allowed = new Set([
    'model', 'messages', 'temperature', 'max_tokens', 'top_p', 'tools',
    'fallback_models', 'model_kwargs', 'tool_choice', 'parallel_tool_calls',
    'response_format', 'mcp_servers', 'reasoning_effort', 'reasoning_effort_strict',
  ]);
  const payload = Object.fromEntries(Object.entries(source).filter(([key, value]) => allowed.has(key) && value != null));
  if (payload.max_tokens == null && source.max_completion_tokens != null) payload.max_tokens = source.max_completion_tokens;
  payload.stream = true;
  return JSON.stringify(payload);
}

async function proxyMlpalStreamRequest(channel, req, res, body, modelName = '', requestId = '', logContext = {}, channelKey = '', attemptedKeys = new Set()) {
  const selectedKey = selectChannelKey(channel, channelKey, attemptedKeys);
  if (!selectedKey.key) throw new Error('渠道没有可用 Key，请在管理面板恢复或导入 Key');
  attemptedKeys.add(selectedKey.key);
  logContext.upstreamKeyFingerprint = selectedKey.fingerprint;
  logContext.upstreamKeyIndex = selectedKey.index;

  const streamBody = normalizeMlpalStreamBody(body);
  const parsed = new URL(`${channel.base_url.replace(/\/$/, '')}/chat/completions/stream`);
  const startedAt = Date.now();
  const completionId = `chatcmpl-${requestId || newRequestId()}`;
  const created = Math.floor(startedAt / 1000);
  const clientModel = logContext.requestedModel || modelName;
  writeGatewayLog('upstream_request', {
    requestId, model: modelName || 'unknown', channel: channel.name,
    clientIp: logContext.clientIp, requestedModel: logContext.requestedModel,
    upstreamHost: parsed.host, upstreamPath: parsed.pathname, method: req.method,
    requestBytes: Buffer.byteLength(streamBody), inputContent: logContext.inputContent,
    upstreamKeyIndex: selectedKey.index, upstreamKeyCount: selectedKey.count,
    upstreamKeyFingerprint: selectedKey.fingerprint,
  });

  return new Promise((resolve) => {
    let settled = false;
    let finished = false;
    let sawOutput = false;
    let firstEvent = true;
    let lineBuffer = '';
    let outputPreview = '';
    let inputTokens = 0;
    let outputTokens = 0;
    let upstreamStatus = 0;
    let upstreamError = '';
    let responseStarted = false;
    const streamChunk = (delta, finishReason = null) => ({
      id: completionId, object: 'chat.completion.chunk', created, model: clientModel,
      choices: [{ index: 0, delta, finish_reason: finishReason }],
    });
    const startResponse = () => {
      if (responseStarted) return;
      responseStarted = true;
      res.writeHead(200, {
        'content-type': 'text/event-stream; charset=utf-8',
        'cache-control': 'no-cache, no-transform',
        'x-accel-buffering': 'no',
      });
    };
    const sendEvent = (value) => {
      startResponse();
      res.write(`data: ${typeof value === 'string' ? value : JSON.stringify(value)}\n\n`);
    };
    const finish = (statusCode, errorMessage = '') => {
      if (settled) return;
      settled = true;
      const success = statusCode < 400 && !errorMessage;
      const tokens = inputTokens + outputTokens;
      const details = {
        statusCode, inputTokens, outputTokens, totalTokens: tokens,
        outputContent: outputPreview,
      };
      logRequest(modelName || 'unknown', channel.name, tokens, success,
        requestLogOptions(logContext, requestId, errorMessage || null, details));
      writeGatewayLog('request_complete', responseLogFields(logContext, {
        requestId, model: modelName || 'unknown', channel: channel.name,
        statusCode, durationMs: Date.now() - startedAt, tokens,
        inputTokens, outputTokens, totalTokens: tokens,
        outputContent: outputPreview,
        ...(errorMessage ? { errorMessage } : {}),
        upstreamKeyIndex: selectedKey.index, upstreamKeyCount: selectedKey.count,
        upstreamKeyFingerprint: selectedKey.fingerprint,
      }));
      if (!res.writableEnded) {
        if (success) {
          sendEvent('[DONE]');
        } else if (responseStarted) {
          sendEvent({ error: { message: errorMessage, type: 'upstream_error', code: 'stream_interrupted' } });
        } else {
          const payload = JSON.stringify({ error: { message: errorMessage, type: 'upstream_error' } });
          res.writeHead(statusCode, { 'content-type': 'application/json; charset=utf-8', 'content-length': Buffer.byteLength(payload) });
          res.write(payload);
        }
        res.end();
      }
      resolve();
    };
    const processLine = (line) => {
      if (!line.startsWith('data:') || finished || settled) return;
      const data = line.slice(5).trim();
      if (!data) return;
      if (data === '[DONE]') {
        if (!sawOutput) upstreamError = 'Upstream stream ended without assistant content or tool calls';
        else if (!finished) {
          sendEvent(streamChunk({}, 'stop'));
          finished = true;
        }
        return;
      }
      let event;
      try { event = JSON.parse(data); } catch { upstreamError = 'Malformed upstream stream event'; return; }
      if (!event || typeof event !== 'object') return;
      if (event.error) {
        upstreamError = typeof event.error === 'string' ? event.error : String(event.error.message || 'Upstream stream error');
        return;
      }
      const tokens = event.cost?.tokens;
      if (tokens) {
        inputTokens = Number(tokens.input_tokens) || inputTokens;
        outputTokens = Number(tokens.output_tokens) || outputTokens;
      }
      const delta = {};
      if (firstEvent) delta.role = 'assistant';
      if (typeof event.content === 'string' && event.content) {
        delta.content = event.content;
        sawOutput = true;
        if (outputPreview.length < 2000) outputPreview += event.content.slice(0, 2000 - outputPreview.length);
      }
      if (Array.isArray(event.tool_calls) && event.tool_calls.length) {
        delta.tool_calls = event.tool_calls.map((call, index) => ({ index, ...call }));
        sawOutput = true;
      }
      if (event.done && !sawOutput) {
        upstreamError = 'Upstream stream ended without assistant content or tool calls';
        return;
      }
      if (Object.keys(delta).length || event.done) {
        sendEvent(streamChunk(delta, event.done ? normalizeOpenAIFinishReason(event.finish_reason || 'stop') : null));
        firstEvent = false;
      }
      if (event.done) finished = true;
    };

    const options = {
      hostname: parsed.hostname, port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search, method: 'POST', timeout: 600000,
      headers: {
        'content-type': 'application/json', 'accept': 'text/event-stream',
        'authorization': `Bearer ${selectedKey.key}`,
        'content-length': Buffer.byteLength(streamBody),
      },
    };
    const transport = parsed.protocol === 'https:' ? https : http;
    const proxy = transport.request(options, (proxyRes) => {
      upstreamStatus = proxyRes.statusCode || 502;
      if (upstreamStatus >= 400) {
        proxyRes.resume();
        proxyRes.on('end', () => {
          handleSelectedKeyFailure(channel, channelKey, selectedKey, upstreamStatus, `HTTP ${upstreamStatus}`);
          finish(upstreamStatus, `Upstream HTTP ${upstreamStatus}`);
        });
      } else {
        proxyRes.setEncoding('utf8');
        proxyRes.on('data', (chunk) => {
          lineBuffer += chunk;
          const lines = lineBuffer.split(/\r?\n/);
          lineBuffer = lines.pop() || '';
          for (const line of lines) processLine(line);
        });
        proxyRes.on('end', () => {
          if (lineBuffer) processLine(lineBuffer);
          if (!upstreamError && !sawOutput) upstreamError = 'Upstream stream ended without assistant content or tool calls';
          if (!upstreamError && !finished) upstreamError = 'Upstream stream ended without a completion marker';
          finish(upstreamError ? 502 : 200, upstreamError);
        });
      }
      proxyRes.on('error', (err) => finish(502, `Upstream stream error: ${err.message}`));
    });
    proxy.on('socket', (socket) => socket.setKeepAlive(true, 10000));
    proxy.on('error', (err) => finish(502, `Upstream request error: ${err.message}`));
    proxy.on('timeout', () => proxy.destroy(new Error('Upstream stream timeout')));
    res.on('close', () => { if (!res.writableEnded) proxy.destroy(); });
    proxy.end(streamBody);
  });
}

function repairToolArgumentsPayload(payload) {
  if (!payload || typeof payload !== 'object') return payload;
  if (Array.isArray(payload)) {
    payload.forEach(repairToolArgumentsPayload);
    return payload;
  }
  const args = payload.function?.arguments;
  if (typeof args === 'string' && args.startsWith('{}') && args.length > 2) {
    const repaired = args.slice(2);
    try {
      JSON.parse(repaired);
      payload.function.arguments = repaired;
    } catch {}
  }
  Object.values(payload).forEach(repairToolArgumentsPayload);
  return payload;
}

function repairToolArgumentsResponse(responseData = '') {
  const raw = String(responseData || '');
  if (!raw.trim()) return raw;
  try {
    return JSON.stringify(repairToolArgumentsPayload(JSON.parse(raw)));
  } catch {}
  return raw.split(/(?<=\n)/).map((line) => {
    const match = line.match(/^(data:\s*)(.*?)(\r?\n)?$/);
    if (!match || !match[2] || match[2] === '[DONE]') return line;
    try {
      const payload = repairToolArgumentsPayload(JSON.parse(match[2]));
      return `${match[1]}${JSON.stringify(payload)}${match[3] || ''}`;
    } catch {
      return line;
    }
  }).join('');
}

function isEmptyUpstreamSuccess(channelKey, modelName, responseDetails, responseData) {
  if (channelKey === 'mlpal') {
    try {
      const payload = JSON.parse(responseData);
      if (!Array.isArray(payload?.choices)) return false;
      const choices = payload.choices;
      const hasContent = choices.some((choice) => {
        const content = choice?.message?.content;
        if (typeof content === 'string') return Boolean(content.trim());
        if (Array.isArray(content)) return content.some((part) =>
          typeof part === 'string' ? Boolean(part.trim()) : Boolean(String(part?.text ?? part?.content ?? '').trim()));
        return false;
      });
      return !hasContent && !responseHasToolCalls(responseData);
    } catch {
      return false;
    }
  }
  if (!isWorkBuddySensitiveClaudeChannel(channelKey, modelName)) return false;
  return Number(responseDetails?.totalTokens || 0) === 0
    && !String(responseDetails?.outputContent || '').trim()
    && !responseHasToolCalls(responseData);
}

function isYepApiChannel(channel = {}) {
  try {
    return channel.format === 'yepapi' || new URL(channel.base_url).hostname.toLowerCase() === 'api.yepapi.com';
  } catch {
    return channel.format === 'yepapi';
  }
}

async function proxyUnlimitedChatRequest(channel, req, res, data, upstreamModel = '', requestedModel = '', requestId = '', logContext = {}, channelKey = '', attemptedKeys = new Set()) {
  const fullUrl = `${channel.base_url.replace(/\/$/, '')}/api/chat`;
  const parsed = new URL(fullUrl);
  const realModel = stripModelPrefix(upstreamModel, channelKey);
  const unlimitedPayload = buildUnlimitedChatPayload(data, realModel);
  const body = JSON.stringify(unlimitedPayload);
  const wantsStream = data.stream === true;
  const startedAt = Date.now();
  const selectedKey = selectChannelKey(channel, channelKey, attemptedKeys);
  if (!selectedKey.key) throw new Error('渠道没有可用 Key，请在管理面板恢复或导入 Key');
  attemptedKeys.add(selectedKey.key);
  logContext.upstreamKeyFingerprint = selectedKey.fingerprint;
  logContext.upstreamKeyIndex = selectedKey.index;
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
      timeout: 480000,
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
      const verdict = handleSelectedKeyFailure(channel, channelKey, selectedKey, safeStatusCode, errorMessage);
      const { forceRetry = false, ...logExtra } = extra;
      logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, errorMessage, { statusCode: safeStatusCode }));
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
        ...logExtra,
      }));
      const canRetry = !streamStarted && !res.headersSent
        && (forceRetry || verdict.disable || verdict.retry)
        && hasUntriedActiveKey(channel, attemptedKeys);
      if (canRetry) {
        proxyUnlimitedChatRequest(channel, req, res, data, upstreamModel, requestedModel, requestId, logContext, channelKey, attemptedKeys)
          .then(resolve, reject);
        return true;
      }
      if (res.writableEnded) return false;
      if (wantsStream) {
        if (!res.headersSent) {
          res.writeHead(safeStatusCode, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: errorMessage, type: 'upstream_error' } }));
          return false;
        }
        if (streamStarted) {
          writeOpenAIStreamChunk('', 'stop');
          res.write('data: [DONE]\n\n');
          res.end();
        }
        return false;
      }
      if (!res.headersSent) {
        res.writeHead(safeStatusCode, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: errorMessage, type: 'upstream_error' } }));
      }
      return false;
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
          const retried = finishWithUpstreamError(proxyRes.statusCode >= 400 ? proxyRes.statusCode : inferUnlimitedErrorStatus(errorMessage), errorMessage);
          if (!retried) resolve();
          return;
        }

        completed = true;
        logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, true, requestLogOptions(logContext, requestId, null, { statusCode: proxyRes.statusCode }));
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
        const retried = finishWithUpstreamError(424, err.message || 'upstream aborted', { upstreamEvent: 'response_error', forceRetry: true });
        if (!retried) resolve();
      });
      proxyRes.on('aborted', () => {
        const retried = finishWithUpstreamError(424, 'upstream aborted', { upstreamEvent: 'response_aborted', forceRetry: true });
        if (!retried) resolve();
      });
    });

    // Some slow relay providers do not emit response bytes for tens of
    // seconds. Match curl's connection behavior so NAT/LB idle tracking does
    // not tear down an otherwise live request before the first token arrives.
    proxy.on('socket', (socket) => {
      socket.setKeepAlive(true, 10000);
    });

    proxy.on('error', (err) => {
      const retried = finishWithUpstreamError(inferUnlimitedErrorStatus(err.message), err.message || 'upstream error', { upstreamEvent: 'request_error', forceRetry: true });
      if (!retried) resolve();
    });

    proxy.on('timeout', () => {
      const retried = finishWithUpstreamError(408, 'timeout', { upstreamEvent: 'request_timeout', forceRetry: true });
      proxy.destroy();
      if (!retried) resolve();
    });

    proxy.write(body);
    proxy.end();
  });
}

async function proxyRequest(channel, req, res, body, modelName = '', requestId = '', logContext = {}, channelKey = '', attemptedKeys = new Set()) {
  const targetUrl = new URL(channel.base_url);
  // Append the request path (strip /v1 prefix if base_url already has it)
  const reqPath = req.url.startsWith('/v1/') ? req.url.slice(3) : req.url;
  const fullUrl = `${channel.base_url}${reqPath}`;
  const requestedBuffering = shouldBufferNonStreamResponse(channelKey, modelName, body);
  const repairToolArguments = shouldRepairToolArguments(channelKey, modelName);
  const unwrapCline = shouldUnwrapClineResponse(channelKey);
  let mlpalWantsStream = false;
  if (channelKey === 'mlpal' && req.url.startsWith('/v1/chat/completions')) {
    try { mlpalWantsStream = JSON.parse(body).stream === true; } catch {}
  }
  if (mlpalWantsStream) {
    return proxyMlpalStreamRequest(channel, req, res, body, modelName, requestId, logContext, channelKey, attemptedKeys);
  }
  // Anthropic-style `thinking` (passed through from /v1/messages) is not an OpenAI chat field; strict upstreams reject it.
  if (req.url.startsWith('/v1/chat/completions') && body && body.includes('"thinking"')) {
    try {
      const parsedBody = JSON.parse(body);
      if (parsedBody.thinking !== undefined) {
        delete parsedBody.thinking;
        body = JSON.stringify(parsedBody);
      }
    } catch {}
  }

  const headers = {};
  // Forward only necessary headers
  if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  if (req.headers['accept']) headers['accept'] = req.headers['accept'];
  const selectedKey = selectChannelKey(channel, channelKey, attemptedKeys);
  if (!selectedKey.key) throw new Error('渠道没有可用 Key，请在管理面板恢复或导入 Key');
  attemptedKeys.add(selectedKey.key);
  logContext.upstreamKeyFingerprint = selectedKey.fingerprint;
  logContext.upstreamKeyIndex = selectedKey.index;
  if (isYepApiChannel(channel)) {
    headers['x-api-key'] = selectedKey.key;
  } else {
    headers['authorization'] = `Bearer ${selectedKey.key}`;
  }
  headers['content-length'] = body ? Buffer.byteLength(body) : 0;

  let wantsStream = false;
  try { wantsStream = JSON.parse(body).stream === true; } catch {}
  if (wantsStream && shouldSendSseHeartbeat(channelKey) && !requestedBuffering && !repairToolArguments && !unwrapCline) {
    startSseHeartbeat(res);
  }

  return new Promise((resolve, rejectRaw) => {
    const reject = (err) => {
      if (res.sseHeartbeat) endSseWithError(res, 502, `Upstream error: ${err.message}`);
      rejectRaw(err);
    };
    const parsed = new URL(fullUrl);
    const options = {
      hostname: parsed.hostname,
      port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
      path: parsed.pathname + parsed.search,
      method: req.method,
      headers,
      timeout: 480000,
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
      ...(requestedBuffering ? { bufferNonStream: true } : {}),
      upstreamKeyIndex: selectedKey.index,
      upstreamKeyCount: selectedKey.count,
      upstreamKeyFingerprint: selectedKey.fingerprint,
    });

    const proxy = transport.request(options, (proxyRes) => {
      // Always hold error responses until they have been classified so another
      // key can be tried without leaking the failed response to the client.
      // Cline now wraps non-stream JSON as { success: true, data: <OpenAI response> }.
      // Buffer its responses so JSON can be normalized while leaving SSE unchanged.
      const bufferResponse = channelKey === 'mlpal' || requestedBuffering || repairToolArguments || unwrapCline || proxyRes.statusCode >= 400;
      if (!bufferResponse) {
        if (res.sseHeartbeat) {
          // 头已由心跳发出；停掉心跳，避免注释行插进上游的半截事件
          stopSseHeartbeat(res);
        } else {
          res.writeHead(proxyRes.statusCode, proxyRes.headers);
        }
      }
      // 收集响应数据以提取 token 使用量
      proxyRes.on('data', chunk => {
        responseData += chunk.toString();
        if (!bufferResponse) {
          if (res.sseHeartbeat) res.sseHeartbeat.upstreamDataSent = true;
          res.write(chunk);
        }
      });

      proxyRes.on('end', () => {
        if (truncatedAbort) return;
        if (unwrapCline && proxyRes.statusCode < 400) {
          responseData = unwrapClineResponse(responseData);
        }
        if (repairToolArguments && proxyRes.statusCode < 400) {
          responseData = repairToolArgumentsResponse(responseData);
        }
        let mlpalResponseMeta;
        if (channelKey === 'mlpal' && proxyRes.statusCode < 400 && req.url.startsWith('/v1/chat/completions')) {
          try {
            const rawPayload = JSON.parse(responseData);
            mlpalResponseMeta = {
              upstreamResponseKeys: Object.keys(rawPayload || {}).slice(0, 30),
              upstreamFinishReason: rawPayload?.finish_reason ?? null,
              upstreamOutputTokens: rawPayload?.cost?.tokens?.output_tokens ?? null,
              upstreamContentType: Array.isArray(rawPayload?.content) ? 'array' : typeof rawPayload?.content,
              upstreamContentLength: typeof rawPayload?.content === 'string' ? rawPayload.content.length : null,
            };
          } catch {
            mlpalResponseMeta = { upstreamResponseFormat: 'non_json' };
          }
          responseData = normalizeMlpalResponse(responseData, modelName);
        }
        // 尝试解析 token 使用量和输出内容
        const responseDetails = extractResponseLogDetails(responseData);
        if (logContext.autoTruncateEnabled
          && logContext.autoTruncateMarker
          && responseData.includes(logContext.autoTruncateMarker)) {
          logContext.autoTruncated = true;
        }
        const emptySuccess = proxyRes.statusCode < 400
          && !responseDetails.errorMessage
          && isEmptyUpstreamSuccess(channelKey, modelName, responseDetails, responseData);
        const errorMessage = responseDetails.errorMessage
          || (emptySuccess ? 'Upstream returned HTTP 200 with no assistant content or tool calls' : '');
        const tokens = responseDetails.totalTokens;

        // 记录成功的请求
        if (proxyRes.statusCode < 400 && !errorMessage) {
          logRequest(modelName || 'unknown', channel.name, tokens, true, requestLogOptions(logContext, requestId, null, { ...responseDetails, statusCode: proxyRes.statusCode }));
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
            ...(mlpalResponseMeta ? { mlpalResponseMeta } : {}),
          }));
          if (bufferResponse && !res.headersSent) {
            if (channelKey === 'mlpal' && mlpalWantsStream) responseData = mlpalResponseToSse(responseData);
            const responseHeaders = { ...proxyRes.headers };
            delete responseHeaders['transfer-encoding'];
            responseHeaders['content-length'] = Buffer.byteLength(responseData);
            if (channelKey === 'mlpal') responseHeaders['content-type'] = mlpalWantsStream
              ? 'text/event-stream; charset=utf-8'
              : 'application/json; charset=utf-8';
            res.writeHead(proxyRes.statusCode, responseHeaders);
            res.end(responseData);
          } else if (!res.writableEnded) {
            stopSseHeartbeat(res);
            res.end();
          }
        } else {
          const finalStatusCode = emptySuccess ? 502 : proxyRes.statusCode;
          const finalErrorMessage = errorMessage || `HTTP ${proxyRes.statusCode}`;
          const verdict = emptySuccess
            ? { disable: false, retry: true }
            : handleSelectedKeyFailure(channel, channelKey, selectedKey, proxyRes.statusCode, finalErrorMessage);
          logRequest(modelName || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, finalErrorMessage, { ...responseDetails, statusCode: finalStatusCode }));
          writeGatewayLog('request_complete', responseLogFields(logContext, {
            requestId,
            model: modelName || 'unknown',
            channel: channel.name,
            statusCode: finalStatusCode,
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
            ...(!mlpalResponseMeta ? { responseBody: truncateText(responseData) } : {}),
            ...(mlpalResponseMeta ? { mlpalResponseMeta } : {}),
          }));
          if (bufferResponse && canRetryResponse(res) && shouldRetryWithAnotherKey(verdict, channel, attemptedKeys)) {
            proxyRequest(channel, req, res, body, modelName, requestId, logContext, channelKey, attemptedKeys)
              .then(resolve, reject);
            return;
          }
          if (bufferResponse && res.sseHeartbeat) {
            endSseWithError(res, finalStatusCode, finalErrorMessage);
          } else if (bufferResponse && !res.headersSent) {
            if (emptySuccess) {
              const payload = JSON.stringify({
                error: {
                  message: finalErrorMessage,
                  type: 'upstream_error',
                  code: 'empty_upstream_response',
                },
              });
              res.writeHead(502, {
                'content-type': 'application/json; charset=utf-8',
                'content-length': Buffer.byteLength(payload),
              });
              res.end(payload);
            } else {
              const responseHeaders = { ...proxyRes.headers };
              delete responseHeaders['transfer-encoding'];
              responseHeaders['content-length'] = Buffer.byteLength(responseData);
              res.writeHead(proxyRes.statusCode, responseHeaders);
              res.end(responseData);
            }
          } else if (!res.writableEnded) {
            res.end();
          }
        }

        resolve();
      });

      proxyRes.on('error', (err) => {
        if (truncatedAbort) return;
        logRequest(modelName || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message, { statusCode: 502 }));
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
          upstreamKeyIndex: selectedKey.index,
          upstreamKeyCount: selectedKey.count,
          upstreamKeyFingerprint: selectedKey.fingerprint,
        }));
        if (canRetryResponse(res) && hasUntriedActiveKey(channel, attemptedKeys)) {
          proxyRequest(channel, req, res, body, modelName, requestId, logContext, channelKey, attemptedKeys)
            .then(resolve, reject);
          return;
        }
        reject(err);
      });
    });

    // 自动截断命中后由响应包装器调用：断开上游，按截断成功记账，不再重试其他 Key
    let truncatedAbort = false;
    res.setUpstreamAbort?.(() => {
      if (truncatedAbort) return;
      truncatedAbort = true;
      logRequest(modelName || 'unknown', channel.name, 0, true, requestLogOptions(logContext, requestId, null, { statusCode: 200 }));
      writeGatewayLog('request_complete', responseLogFields(logContext, {
        requestId,
        model: modelName || 'unknown',
        channel: channel.name,
        statusCode: 200,
        durationMs: Date.now() - startedAt,
        inputTokens: 0,
        outputTokens: 0,
        totalTokens: 0,
        outputContent: truncateText(responseData),
        upstreamAborted: true,
        upstreamKeyIndex: selectedKey.index,
        upstreamKeyCount: selectedKey.count,
        upstreamKeyFingerprint: selectedKey.fingerprint,
      }));
      proxy.destroy();
      resolve();
    });

    proxy.on('socket', (socket) => {
      socket.setKeepAlive(true, 10000);
    });

    proxy.on('error', (err) => {
      if (truncatedAbort) return;
      logRequest(modelName || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message, { statusCode: 502 }));
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
        upstreamKeyIndex: selectedKey.index,
        upstreamKeyCount: selectedKey.count,
        upstreamKeyFingerprint: selectedKey.fingerprint,
      }));
      if (canRetryResponse(res) && hasUntriedActiveKey(channel, attemptedKeys)) {
        proxyRequest(channel, req, res, body, modelName, requestId, logContext, channelKey, attemptedKeys)
          .then(resolve, reject);
        return;
      }
      reject(err);
    });

    proxy.on('timeout', () => {
      logRequest(modelName || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, 'timeout', { statusCode: 504 }));
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
        upstreamKeyIndex: selectedKey.index,
        upstreamKeyCount: selectedKey.count,
        upstreamKeyFingerprint: selectedKey.fingerprint,
      }));
      proxy.destroy();
      if (canRetryResponse(res) && hasUntriedActiveKey(channel, attemptedKeys)) {
        proxyRequest(channel, req, res, body, modelName, requestId, logContext, channelKey, attemptedKeys)
          .then(resolve, reject);
        return;
      }
      reject(new Error('timeout'));
    });

    if (body) proxy.write(body);
    proxy.end();
  });
}

async function proxyAnthropicChatRequest(channel, req, res, data, upstreamModel = '', requestedModel = '', requestId = '', logContext = {}, channelKey = '', attemptedKeys = new Set()) {
  const parsedBase = new URL(channel.base_url);
  const fullUrl = `${channel.base_url.replace(/\/$/, '')}/messages`;
  const parsed = new URL(fullUrl);
  const anthropicPayload = convertOpenAIChatToAnthropic(data, stripModelPrefix(upstreamModel, channelKey), channel);
  const wantsStream = data.stream === true;
  if (wantsStream) anthropicPayload.stream = true;
  const body = JSON.stringify(anthropicPayload);
  const startedAt = Date.now();
  const selectedKey = selectChannelKey(channel, channelKey, attemptedKeys);
  if (!selectedKey.key) throw new Error('渠道没有可用 Key，请在管理面板恢复或导入 Key');
  attemptedKeys.add(selectedKey.key);
  logContext.upstreamKeyFingerprint = selectedKey.fingerprint;
  logContext.upstreamKeyIndex = selectedKey.index;

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
      timeout: 480000,
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
              logRequest(upstreamModel || requestedModel || 'unknown', channel.name, tokens, true, requestLogOptions(logContext, requestId, null, { ...usageDetails, statusCode: proxyRes.statusCode }));
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
              logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message, { statusCode: 502 }));
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
            inputTokens: streamInputTokens,
            outputTokens: streamOutputTokens,
            statusCode: proxyRes.statusCode,
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
          const verdict = handleSelectedKeyFailure(channel, channelKey, selectedKey, proxyRes.statusCode, errorMessage);
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, errorMessage, { ...responseDetails, statusCode: proxyRes.statusCode }));
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
            upstreamKeyIndex: selectedKey.index,
            upstreamKeyCount: selectedKey.count,
            upstreamKeyFingerprint: selectedKey.fingerprint,
          }));
          if (!res.headersSent && shouldRetryWithAnotherKey(verdict, channel, attemptedKeys)) {
            proxyAnthropicChatRequest(channel, req, res, data, upstreamModel, requestedModel, requestId, logContext, channelKey, attemptedKeys)
              .then(resolve, reject);
            return;
          }
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
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, tokens, true, requestLogOptions(logContext, requestId, null, { ...usageDetails, statusCode: proxyRes.statusCode }));
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
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message, { statusCode: 502 }));
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
            upstreamKeyIndex: selectedKey.index,
            upstreamKeyCount: selectedKey.count,
            upstreamKeyFingerprint: selectedKey.fingerprint,
          }));
          reject(err);
        }
      });

      proxyRes.on('error', (err) => {
        logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message, { statusCode: 502 }));
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
          upstreamKeyIndex: selectedKey.index,
          upstreamKeyCount: selectedKey.count,
          upstreamKeyFingerprint: selectedKey.fingerprint,
        }));
        if (!res.headersSent && hasUntriedActiveKey(channel, attemptedKeys)) {
          proxyAnthropicChatRequest(channel, req, res, data, upstreamModel, requestedModel, requestId, logContext, channelKey, attemptedKeys)
            .then(resolve, reject);
          return;
        }
        reject(err);
      });
    });

    proxy.on('error', (err) => {
      logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, err.message, { statusCode: 502 }));
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
        upstreamKeyIndex: selectedKey.index,
        upstreamKeyCount: selectedKey.count,
        upstreamKeyFingerprint: selectedKey.fingerprint,
      }));
      if (!res.headersSent && hasUntriedActiveKey(channel, attemptedKeys)) {
        proxyAnthropicChatRequest(channel, req, res, data, upstreamModel, requestedModel, requestId, logContext, channelKey, attemptedKeys)
          .then(resolve, reject);
        return;
      }
      reject(err);
    });

    proxy.on('timeout', () => {
      logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, 'timeout', { statusCode: 504 }));
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
        upstreamKeyIndex: selectedKey.index,
        upstreamKeyCount: selectedKey.count,
        upstreamKeyFingerprint: selectedKey.fingerprint,
      }));
      proxy.destroy();
      if (!res.headersSent && hasUntriedActiveKey(channel, attemptedKeys)) {
        proxyAnthropicChatRequest(channel, req, res, data, upstreamModel, requestedModel, requestId, logContext, channelKey, attemptedKeys)
          .then(resolve, reject);
        return;
      }
      reject(new Error('timeout'));
    });

    proxy.write(body);
    proxy.end();
  });
}


export {
  selectChannelKey,
  isYepApiChannel,
  proxyUnlimitedChatRequest,
  proxyRequest,
  proxyAnthropicChatRequest,
};
