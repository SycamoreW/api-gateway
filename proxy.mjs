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
  shouldBufferNonStreamResponse,
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
  const cursorKey = channelKey || channel.name || channel.base_url || 'default';
  const cursor = channelKeyCursors.get(cursorKey) || 0;
  const index = cursor % activeKeys.length;
  channelKeyCursors.set(cursorKey, (cursor + 1) % activeKeys.length);
  const selectedKey = activeKeys[index];
  // index in allKeys for logging purposes
  const allIndex = allKeys.indexOf(selectedKey);
  return {
    key: selectedKey,
    index: allIndex >= 0 ? allIndex : index,
    count: allKeys.length,
    fingerprint: fingerprintKey(selectedKey),
  };
}

function hasUntriedActiveKey(channel = {}, attemptedKeys = new Set()) {
  const attempted = attemptedKeys instanceof Set ? attemptedKeys : new Set(attemptedKeys || []);
  return getActiveChannelKeys(channel).some(key => !attempted.has(key));
}

function shouldRetryWithAnotherKey(verdict = {}, channel = {}, attemptedKeys = new Set()) {
  return Boolean(verdict.disable || verdict.retry) && hasUntriedActiveKey(channel, attemptedKeys);
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
      ...(requestedBuffering ? { bufferNonStream: true } : {}),
      upstreamKeyIndex: selectedKey.index,
      upstreamKeyCount: selectedKey.count,
      upstreamKeyFingerprint: selectedKey.fingerprint,
    });

    const proxy = transport.request(options, (proxyRes) => {
      // Always hold error responses until they have been classified so another
      // key can be tried without leaking the failed response to the client.
      const bufferResponse = requestedBuffering || proxyRes.statusCode >= 400;
      if (!bufferResponse) {
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
      }
      // 收集响应数据以提取 token 使用量
      proxyRes.on('data', chunk => {
        responseData += chunk.toString();
        if (!bufferResponse) {
          res.write(chunk);
        }
      });

      proxyRes.on('end', () => {
        // 尝试解析 token 使用量和输出内容
        const responseDetails = extractResponseLogDetails(responseData);
        const errorMessage = responseDetails.errorMessage;
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
          }));
          if (bufferResponse && !res.headersSent) {
            const responseHeaders = { ...proxyRes.headers };
            delete responseHeaders['transfer-encoding'];
            responseHeaders['content-length'] = Buffer.byteLength(responseData);
            res.writeHead(proxyRes.statusCode, responseHeaders);
            res.end(responseData);
          } else if (!res.writableEnded) {
            res.end();
          }
        } else {
          const finalErrorMessage = errorMessage || `HTTP ${proxyRes.statusCode}`;
          const verdict = handleSelectedKeyFailure(channel, channelKey, selectedKey, proxyRes.statusCode, finalErrorMessage);
          logRequest(modelName || 'unknown', channel.name, 0, false, requestLogOptions(logContext, requestId, finalErrorMessage, { ...responseDetails, statusCode: proxyRes.statusCode }));
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
          if (bufferResponse && !res.headersSent && shouldRetryWithAnotherKey(verdict, channel, attemptedKeys)) {
            proxyRequest(channel, req, res, body, modelName, requestId, logContext, channelKey, attemptedKeys)
              .then(resolve, reject);
            return;
          }
          if (bufferResponse && !res.headersSent) {
            const responseHeaders = { ...proxyRes.headers };
            delete responseHeaders['transfer-encoding'];
            responseHeaders['content-length'] = Buffer.byteLength(responseData);
            res.writeHead(proxyRes.statusCode, responseHeaders);
            res.end(responseData);
          } else if (!res.writableEnded) {
            res.end();
          }
        }

        resolve();
      });

      proxyRes.on('error', (err) => {
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
        if (!res.headersSent && hasUntriedActiveKey(channel, attemptedKeys)) {
          proxyRequest(channel, req, res, body, modelName, requestId, logContext, channelKey, attemptedKeys)
            .then(resolve, reject);
          return;
        }
        reject(err);
      });
    });

    proxy.on('error', (err) => {
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
      if (!res.headersSent && hasUntriedActiveKey(channel, attemptedKeys)) {
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
      if (!res.headersSent && hasUntriedActiveKey(channel, attemptedKeys)) {
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
