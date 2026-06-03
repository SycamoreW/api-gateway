import http from 'node:http';
import https from 'node:https';
import fs from 'node:fs';
import path from 'node:path';

const config = JSON.parse(fs.readFileSync(path.resolve(process.argv[2] || 'config.json'), 'utf-8'));
const LOG_DIR = path.resolve('logs');
const LOG_MAX_BODY_CHARS = 2000;

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

function readGatewayLogs(limit = 100) {
  try {
    const file = currentLogFile();
    if (!fs.existsSync(file)) return [];
    const lines = fs.readFileSync(file, 'utf-8').trim().split('\n').filter(Boolean);
    return lines.slice(-limit).reverse().map((line) => {
      try {
        return JSON.parse(line);
      } catch {
        return { timestamp: null, event: 'parse_error', raw: truncateText(line) };
      }
    });
  } catch (err) {
    return [{ timestamp: new Date().toISOString(), event: 'read_error', error: err.message }];
  }
}

function newRequestId() {
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`;
}

function toTokenNumber(value) {
  const number = Number(value);
  return Number.isFinite(number) && number > 0 ? number : 0;
}

function extractTokenUsage(data) {
  return extractTokenUsageDetails(data).totalTokens;
}

function extractTokenUsageDetails(data) {
  if (!data || typeof data !== 'object') return { inputTokens: 0, outputTokens: 0, totalTokens: 0 };

  const usage = data.usage && typeof data.usage === 'object' ? data.usage : {};
  const tokenUsage = data.token_usage && typeof data.token_usage === 'object' ? data.token_usage : {};
  const inputTokens =
    toTokenNumber(usage.prompt_tokens) +
    toTokenNumber(usage.input_tokens) +
    toTokenNumber(usage.cache_creation_input_tokens) +
    toTokenNumber(usage.cache_read_input_tokens) +
    toTokenNumber(tokenUsage.prompt_tokens) +
    toTokenNumber(tokenUsage.input_tokens);
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
  return { inputTokens, outputTokens, totalTokens };
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
      outputContent += extractOutputContent(data);
      errorMessage ||= extractErrorMessage(data);
      if (data.type === 'content_block_delta' && data.delta?.text) outputContent += data.delta.text;
      if (data.type === 'message_start') inputTokens = Math.max(inputTokens, toTokenNumber(data.message?.usage?.input_tokens));
      if (data.type === 'message_delta') outputTokens = Math.max(outputTokens, toTokenNumber(data.usage?.output_tokens));
    } catch {
      // Ignore non-JSON stream lines.
    }
  }
  return {
    inputTokens,
    outputTokens,
    totalTokens: totalTokens || inputTokens + outputTokens,
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
  };
}

function responseLogFields(context = {}, extra = {}) {
  const fields = { ...extra };
  if (context.clientIp) fields.clientIp = context.clientIp;
  if (context.requestedModel && context.requestedModel !== extra.model) fields.requestedModel = context.requestedModel;
  if (context.inputContent) fields.inputContent = context.inputContent;
  if (context.stream != null) fields.stream = context.stream;
  if (fields.totalTokens == null && fields.tokens != null) fields.totalTokens = fields.tokens;
  return fields;
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
    dailyStats: {},
    recentLogs: []
  };
}

// 保存统计数据
function saveStats() {
  fs.writeFileSync(STATS_FILE, JSON.stringify(stats, null, 2));
}

// 记录访问日志
function logRequest(model, channel, tokens = 0, success = true, error = null) {
  const now = new Date();
  const date = now.toISOString().split('T')[0];
  const time = now.toLocaleTimeString('zh-CN', { timeZone: 'Asia/Shanghai' });
  
  // 更新总计数
  stats.totalRequests++;
  
  // 更新模型使用统计
  if (!stats.modelUsage[model]) {
    stats.modelUsage[model] = { count: 0, tokens: 0 };
  }
  stats.modelUsage[model].count++;
  stats.modelUsage[model].tokens += tokens;
  
  // 更新渠道使用统计
  if (!stats.channelUsage[channel]) {
    stats.channelUsage[channel] = { count: 0, tokens: 0 };
  }
  stats.channelUsage[channel].count++;
  stats.channelUsage[channel].tokens += tokens;
  
  // 更新每日统计
  if (!stats.dailyStats[date]) {
    stats.dailyStats[date] = { requests: 0, tokens: 0, models: {}, channels: {} };
  }
  if (!stats.dailyStats[date].models) stats.dailyStats[date].models = {};
  if (!stats.dailyStats[date].channels) stats.dailyStats[date].channels = {};
  stats.dailyStats[date].requests++;
  stats.dailyStats[date].tokens += tokens;
  if (!stats.dailyStats[date].models[model]) {
    stats.dailyStats[date].models[model] = { count: 0, tokens: 0 };
  }
  stats.dailyStats[date].models[model].count++;
  stats.dailyStats[date].models[model].tokens += tokens;
  if (!stats.dailyStats[date].channels[channel]) {
    stats.dailyStats[date].channels[channel] = { count: 0, tokens: 0 };
  }
  stats.dailyStats[date].channels[channel].count++;
  stats.dailyStats[date].channels[channel].tokens += tokens;
  
  // 添加到最近日志（保留最近100条）
  const logEntry = {
    timestamp: now.toISOString(),
    time: time,
    model: model,
    channel: channel,
    tokens: tokens,
    success: success,
    error: error
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
    for (const m of ch.models) {
      modelMap.set(m, { channelKey: ckey, upstreamModel: m });
    }
  }

}
rebuildModelMap();

function auth(req, res) {
  const authHeader = req.headers['authorization'] || '';
  if (authHeader !== `Bearer ${config.api_key}`) {
    res.writeHead(401, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'Invalid API key', type: 'auth_error' } }));
    writeGatewayLog('request_complete', {
      requestId: res.getHeader('X-Request-Id') || '',
      method: req.method,
      url: req.url,
      clientIp: getClientIp(req),
      statusCode: 401,
      inputTokens: 0,
      outputTokens: 0,
      totalTokens: 0,
      errorMessage: 'Invalid API key',
    });
    return false;
  }
  return true;
}

function stripModelPrefix(modelName = '') {
  return modelName.replace(/^[a-z0-9_]+\//i, '');
}

function convertOpenAIContentToAnthropic(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return content;
  return content.map((part) => {
    if (typeof part === 'string') return { type: 'text', text: part };
    if (part?.type === 'text') return { type: 'text', text: part.text || '' };
    return part;
  });
}

function convertOpenAIChatToAnthropic(data, realModel) {
  const messages = [];
  const system = [];

  for (const message of data.messages || []) {
    if (message.role === 'system') {
      if (typeof message.content === 'string') {
        system.push(message.content);
      }
      continue;
    }

    messages.push({
      role: message.role === 'assistant' ? 'assistant' : 'user',
      content: convertOpenAIContentToAnthropic(message.content),
    });
  }

  const payload = {
    model: realModel,
    messages,
    max_tokens: data.max_tokens || data.max_completion_tokens || 4096,
  };

  if (system.length > 0) payload.system = system.join('\n\n');
  if (typeof data.temperature === 'number') payload.temperature = data.temperature;
  if (typeof data.top_p === 'number') payload.top_p = data.top_p;
  if (typeof data.stop === 'string' || Array.isArray(data.stop)) payload.stop_sequences = Array.isArray(data.stop) ? data.stop : [data.stop];

  return payload;
}

function convertAnthropicResponseToOpenAI(data, requestedModel) {
  const text = Array.isArray(data.content)
    ? data.content.map((part) => part?.text || '').join('')
    : '';
  const inputTokens = data.usage?.input_tokens || 0;
  const outputTokens = data.usage?.output_tokens || 0;

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
          content: text,
        },
        finish_reason: data.stop_reason || 'stop',
      },
    ],
    usage: {
      prompt_tokens: inputTokens,
      completion_tokens: outputTokens,
      total_tokens: inputTokens + outputTokens,
    },
  };
}

// 历史默认值：未显式配置的 pio 渠道仍按 <answer> 截断。
const CHANNEL_STOP_SEQUENCES = {
  pio: ['<answer>'],
};

function normalizeStopSequences(value) {
  if (Array.isArray(value)) {
    return [...new Set(value.map(v => String(v || '').trim()).filter(Boolean))];
  }
  if (typeof value === 'string') {
    return [...new Set(value.split(/[\n,，]+/).map(v => v.trim()).filter(Boolean))];
  }
  return [];
}

function getChannelStopSequences(channel) {
  if (Object.prototype.hasOwnProperty.call(channel, 'stream_stop_sequences')) {
    return normalizeStopSequences(channel.stream_stop_sequences);
  }
  if (Object.prototype.hasOwnProperty.call(channel, 'stop_sequences')) {
    return normalizeStopSequences(channel.stop_sequences);
  }
  return normalizeStopSequences(CHANNEL_STOP_SEQUENCES[channel.name]);
}

async function proxyRequest(channel, req, res, body, modelName = '', requestId = '', logContext = {}) {
  const targetUrl = new URL(channel.base_url);
  // Append the request path (strip /v1 prefix if base_url already has it)
  const reqPath = req.url.startsWith('/v1/') ? req.url.slice(3) : req.url;
  const fullUrl = `${channel.base_url}${reqPath}`;
  
  const headers = {};
  // Forward only necessary headers
  if (req.headers['content-type']) headers['content-type'] = req.headers['content-type'];
  if (req.headers['accept']) headers['accept'] = req.headers['accept'];
  headers['authorization'] = `Bearer ${channel.key}`;
  headers['content-length'] = body ? Buffer.byteLength(body) : 0;
  
  // 检查是否需要停止序列检测
  const stopSequences = getChannelStopSequences(channel);
  const needsStopDetection = stopSequences.length > 0;
  const maxStopSequenceLength = Math.max(1, ...stopSequences.map(seq => seq.length));
  
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
    let accumulatedContent = ''; // 累积的内容用于检测停止序列
    let pendingContent = ''; // 暂存末尾字符，避免截断词跨 chunk 时泄露前半段
    let lastContentEvent = null;
    let streamBuffer = '';
    let stopped = false; // 是否已触发停止
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
    });
    
    const proxy = transport.request(options, (proxyRes) => {
      res.writeHead(proxyRes.statusCode, proxyRes.headers);
      const contentType = String(proxyRes.headers['content-type'] || '');
      const isEventStream = contentType.includes('text/event-stream');

      function findStopSequence(text) {
        let found = null;
        for (const seq of stopSequences) {
          const idx = text.indexOf(seq);
          if (idx !== -1 && (!found || idx < found.idx)) {
            found = { seq, idx };
          }
        }
        return found;
      }

      function completeWithStopSequence(seq, idx) {
        stopped = true;
        console.log(`[stop-seq] ${channel.name}/${modelName}: detected "${seq}" at pos ${idx}, truncating`);
        writeGatewayLog('stop_sequence_detected', {
          requestId,
          model: modelName || 'unknown',
          channel: channel.name,
          sequence: seq,
          position: idx,
          contentLength: accumulatedContent.length,
        });

        if (!res.writableEnded) {
          res.write('data: [DONE]\n\n');
          res.end();
        }

        proxy.destroy();
        logRequest(modelName || 'unknown', channel.name, 0, true, 'stop_sequence');
        writeGatewayLog('request_complete', responseLogFields(logContext, {
          requestId,
          model: modelName || 'unknown',
          channel: channel.name,
          statusCode: proxyRes.statusCode,
          durationMs: Date.now() - startedAt,
          inputTokens: 0,
          outputTokens: 0,
          totalTokens: 0,
          outputContent: truncateText(accumulatedContent),
          errorMessage: 'stop_sequence',
        }));
        resolve();
      }

      function writeStreamLine(rawLine) {
        const line = rawLine.replace(/\r$/, '');
        if (line === 'data: [DONE]') {
          flushPendingContent();
          res.write(`${rawLine}\n`);
          return true;
        }
        if (!line.startsWith('data: ') || line === 'data: [DONE]') {
          res.write(`${rawLine}\n`);
          return true;
        }

        try {
          const json = JSON.parse(line.slice(6));
          const choice = json?.choices?.[0];
          const content = choice?.delta?.content;
          if (typeof content !== 'string' || content.length === 0) {
            res.write(`${rawLine}\n`);
            return true;
          }

          lastContentEvent = json;
          pendingContent += content;
          const nextContent = accumulatedContent + pendingContent;
          const found = findStopSequence(nextContent);
          if (!found) return flushSafePendingContent(json);

          const allowedLength = Math.max(0, found.idx - accumulatedContent.length);
          const allowedContent = pendingContent.slice(0, allowedLength);
          accumulatedContent += allowedContent;
          if (allowedContent) {
            choice.delta.content = allowedContent;
            res.write(`data: ${JSON.stringify(json)}\n\n`);
          }
          completeWithStopSequence(found.seq, found.idx);
          return false;
        } catch (e) {
          // 解析不了就按原样转发，避免破坏非标准 SSE。
          res.write(`${rawLine}\n`);
          return true;
        }
      }

      function writeContentEvent(content) {
        if (!content) return;
        const json = lastContentEvent ? JSON.parse(JSON.stringify(lastContentEvent)) : {
          choices: [{ delta: { content } }],
        };
        if (!json.choices) json.choices = [{ delta: {} }];
        if (!json.choices[0]) json.choices[0] = { delta: {} };
        if (!json.choices[0].delta) json.choices[0].delta = {};
        json.choices[0].delta.content = content;
        res.write(`data: ${JSON.stringify(json)}\n\n`);
      }

      function flushSafePendingContent(json) {
        const safeLength = Math.max(0, pendingContent.length - maxStopSequenceLength + 1);
        if (safeLength <= 0) return true;
        const safeContent = pendingContent.slice(0, safeLength);
        pendingContent = pendingContent.slice(safeLength);
        accumulatedContent += safeContent;
        json.choices[0].delta.content = safeContent;
        res.write(`data: ${JSON.stringify(json)}\n\n`);
        return true;
      }

      function flushPendingContent() {
        if (!pendingContent) return;
        accumulatedContent += pendingContent;
        writeContentEvent(pendingContent);
        pendingContent = '';
      }

      function writeFilteredStreamChunk(chunkStr) {
        streamBuffer += chunkStr;
        const lines = streamBuffer.split('\n');
        streamBuffer = lines.pop() || '';
        for (const line of lines) {
          if (!writeStreamLine(line)) return;
        }
      }
      
      // 收集响应数据以提取 token 使用量
      proxyRes.on('data', chunk => {
        if (stopped) return; // 已停止，忽略后续数据
        
        const chunkStr = chunk.toString();
        responseData += chunkStr;
        
        // 仅处理 OpenAI SSE 流式响应；普通 JSON 响应原样转发。
        if (needsStopDetection && isEventStream && proxyRes.statusCode < 400) {
          writeFilteredStreamChunk(chunkStr);
          return;
        }
        
        res.write(chunk);
      });
      
      proxyRes.on('end', () => {
        if (stopped) return; // 已经处理过了
        if (needsStopDetection && isEventStream && streamBuffer) {
          writeStreamLine(streamBuffer);
          streamBuffer = '';
        }
        if (needsStopDetection && isEventStream) {
          flushPendingContent();
        }
        
        if (!res.writableEnded) {
          res.end();
        }
        
        // 尝试解析 token 使用量和输出内容
        const responseDetails = extractResponseLogDetails(responseData);
        const tokens = responseDetails.totalTokens;
        
        // 记录成功的请求
        if (proxyRes.statusCode < 400) {
          logRequest(modelName || 'unknown', channel.name, tokens, true);
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
            outputContent: responseDetails.outputContent,
          }));
        } else {
          const errorMessage = responseDetails.errorMessage || `HTTP ${proxyRes.statusCode}`;
          logRequest(modelName || 'unknown', channel.name, 0, false, errorMessage);
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
            outputContent: responseDetails.outputContent,
            errorMessage,
            responseBody: truncateText(responseData),
          }));
        }
        
        resolve();
      });
      
      proxyRes.on('error', reject);
    });
    
    proxy.on('error', (err) => {
      if (stopped) return;
      logRequest(modelName || 'unknown', channel.name, 0, false, err.message);
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
      if (stopped) return;
      logRequest(modelName || 'unknown', channel.name, 0, false, 'timeout');
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

async function proxyAnthropicChatRequest(channel, req, res, data, upstreamModel = '', requestedModel = '', requestId = '', logContext = {}) {
  const parsedBase = new URL(channel.base_url);
  const fullUrl = `${channel.base_url.replace(/\/$/, '')}/messages`;
  const parsed = new URL(fullUrl);
  const anthropicPayload = convertOpenAIChatToAnthropic(data, stripModelPrefix(upstreamModel));
  const wantsStream = data.stream === true;
  if (wantsStream) anthropicPayload.stream = true;
  const body = JSON.stringify(anthropicPayload);
  const startedAt = Date.now();

  const headers = {
    'content-type': 'application/json',
    'accept': 'application/json',
    'x-api-key': channel.key,
    'anthropic-version': channel.anthropic_version || '2023-06-01',
    'content-length': Buffer.byteLength(body),
  };

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
    let streamOutputContent = '';
    const streamId = `chatcmpl-${requestId || newRequestId()}`;
    const streamCreated = Math.floor(Date.now() / 1000);

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
            finish_reason: finishReason,
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
              streamInputTokens = eventData.message?.usage?.input_tokens || 0;
              writeOpenAIStreamChunk('');
            } else if (eventData.type === 'content_block_delta') {
              const text = eventData.delta?.text || '';
              if (text) {
                streamOutputContent += text;
                writeOpenAIStreamChunk(text);
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
              const tokens = extractTokenUsage(openAIData);
              logRequest(upstreamModel || requestedModel || 'unknown', channel.name, tokens, true);
              writeGatewayLog('request_complete', responseLogFields(logContext, {
                requestId,
                model: upstreamModel || 'unknown',
                channel: channel.name,
                requestedModel,
                statusCode: proxyRes.statusCode,
                durationMs: Date.now() - startedAt,
                tokens,
                ...extractTokenUsageDetails(openAIData),
                outputContent: truncateText(content),
                format: 'anthropic_stream_json_fallback',
              }));
              resolve();
            } catch (err) {
              logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, err.message);
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
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, tokens, true);
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
            outputContent: truncateText(streamOutputContent),
            format: 'anthropic_stream',
          }));
          resolve();
          return;
        }

        if (proxyRes.statusCode >= 400) {
          const responseDetails = extractResponseLogDetails(responseData);
          const errorMessage = responseDetails.errorMessage || `HTTP ${proxyRes.statusCode}`;
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, errorMessage);
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
          const tokens = extractTokenUsage(openAIData);
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, tokens, true);
          writeGatewayLog('request_complete', responseLogFields(logContext, {
            requestId,
            model: upstreamModel || 'unknown',
            channel: channel.name,
            requestedModel,
            statusCode: proxyRes.statusCode,
            durationMs: Date.now() - startedAt,
            tokens,
            ...extractTokenUsageDetails(openAIData),
            outputContent: truncateText(openAIData.choices?.[0]?.message?.content || ''),
            format: 'anthropic',
          }));
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify(openAIData));
          resolve();
        } catch (err) {
          logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, err.message);
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
      logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, err.message);
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
      logRequest(upstreamModel || requestedModel || 'unknown', channel.name, 0, false, 'timeout');
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

// Optional model-specific parameter filters.
// Example: { "provider/model": ["temperature", "top_p"] }
const MODEL_PARAM_FILTERS = {};

// 根据模型过滤不支持的参数
function filterModelParams(data, modelName, requestId = '') {
  // 调试：打印收到的参数
  const paramKeys = Object.keys(data).filter(k => !['model', 'messages', 'stream'].includes(k));
  if (paramKeys.length > 0) {
    console.log(`[debug] ${modelName}: incoming params [${paramKeys.join(', ')}]`);
    writeGatewayLog('model_params', {
      requestId,
      model: modelName,
      params: paramKeys,
    });
  }
  
  const paramsToRemove = MODEL_PARAM_FILTERS[modelName];
  if (paramsToRemove) {
    const actuallyRemoved = paramsToRemove.filter(p => p in data);
    for (const param of paramsToRemove) {
      delete data[param];
    }
    if (actuallyRemoved.length > 0) {
      console.log(`[filter] ${modelName}: removed params [${actuallyRemoved.join(', ')}]`);
      writeGatewayLog('model_params_filtered', {
        requestId,
        model: modelName,
        removed: actuallyRemoved,
      });
    }
  }
  return data;
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
  
  // 应用参数过滤
  data = filterModelParams(data, modelName, requestId);
  
  let entry = modelMap.get(modelName);
  if (!entry) {
    // Try partial match: any channel model that ends with the requested name
    const candidates = [...modelMap.entries()].filter(([k]) => k.endsWith(modelName));
    if (candidates.length === 0) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: `Model not found: ${modelName}`, type: 'model_not_found' } }));
      logRequest(modelName, 'none', 0, false, 'model_not_found');
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
  
  // Strip prefix from model name for upstream
  const upstreamModel = entry.upstreamModel;
  // Remove provider prefixes like "local/" before passing upstream.
  const realModel = stripModelPrefix(upstreamModel);
  data.model = realModel;
  body = JSON.stringify(data);  // 已经过滤过参数的 data
  writeGatewayLog('model_routed', {
    requestId,
    requestedModel: modelName,
    upstreamModel,
    upstreamPayloadModel: realModel,
    channelKey: entry.channelKey,
    channel: channel.name,
    finalParams: Object.keys(data).filter(k => !['model', 'messages', 'stream'].includes(k)),
  });
  
  try {
    if (channel.format === 'anthropic') {
      await proxyAnthropicChatRequest(channel, req, res, data, upstreamModel, modelName, requestId, logContext);
    } else {
      await proxyRequest(channel, req, res, body, upstreamModel, requestId, logContext);
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
  fs.writeFileSync(path.resolve('config.json'), JSON.stringify(config, null, 2));
}

async function handleConfigAPI(req, res, url, body) {
  if (url === '/api/config' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ channels: config.channels }));
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

  if (url.startsWith('/api/logs') && req.method === 'GET') {
    const parsed = new URL(url, 'http://localhost');
    const limit = Math.min(Math.max(parseInt(parsed.searchParams.get('limit') || '100', 10) || 100, 1), 500);
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      file: currentLogFile(),
      logs: readGatewayLogs(limit),
    }));
    return true;
  }
  
  // 统计数据 API
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
    const { channelKey, name, base_url, key, models, format, anthropic_version, stream_stop_sequences, isNew } = d;
    
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
    
    const existingChannel = config.channels[channelKey] || {};
    config.channels[channelKey] = {
      name: name || existingChannel.name || channelKey,
      base_url: base_url || existingChannel.base_url || '',
      key: key || existingChannel.key || '',
      ...(format || existingChannel.format ? { format: format || existingChannel.format } : {}),
      ...(anthropic_version || existingChannel.anthropic_version ? { anthropic_version: anthropic_version || existingChannel.anthropic_version } : {}),
      ...(stream_stop_sequences !== undefined ? { stream_stop_sequences: normalizeStopSequences(stream_stop_sequences) } : (
        existingChannel.stream_stop_sequences !== undefined ? { stream_stop_sequences: normalizeStopSequences(existingChannel.stream_stop_sequences) } : {}
      )),
      models: models || [],
    };
    
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
  
  // API routes - need auth
  if (!auth(req, res)) return;
  
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
    const handled = await handleConfigAPI(req, res, url, req.method === 'POST' ? body : '');
    if (!handled) {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'API not found' } }));
    }
    return;
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
