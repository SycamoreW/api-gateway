import http from 'node:http';
import fs from 'node:fs';
import { serveDetector, detectorSameOrigin } from './gateway-static.mjs';
import { createDetectorUpdater } from './detector-updates.mjs';
const detectorUpdates = createDetectorUpdater();
import { config, modelMap, stats, SERVE_UI, UI_FILE } from './state.mjs';
import {
  writeGatewayLog, newRequestId, saveStats,
  backfillHourlyStatsFromRecentLogs, backfillUsageCacheFromRecentLogs,
  backfillUpstreamKeyUsageFromRecentLogs,
} from './logger.mjs';
import { rebuildModelMap } from './config.mjs';
import { adminAuth, clientAuth } from './auth.mjs';
import {
  handleChatCompletions, handleModels, handleConfigAPI,
  handleResponses, handleAnthropicMessages,
} from './handlers.mjs';

// 初始化
rebuildModelMap();
backfillHourlyStatsFromRecentLogs();
backfillUsageCacheFromRecentLogs();
backfillUpstreamKeyUsageFromRecentLogs();

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

  // Protected by the same Nginx login boundary as the management UI.
  if (SERVE_UI && await serveDetector(req, res)) return;

  // Web UI
  if (SERVE_UI && (url === '/' || url === '/ui')) {
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(fs.readFileSync(UI_FILE, 'utf-8'));
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

  // Detector uses the existing admin session; no API keys reach the browser.
  if (url.startsWith('/api/lm-detector/')) {
    res.removeHeader('Access-Control-Allow-Origin');
    res.setHeader('Cache-Control', 'no-store');
    if (!adminAuth(req, res)) return;
    if (url === '/api/lm-detector/updates' && ['GET', 'POST'].includes(req.method)) {
      if (req.method === 'POST' && !detectorSameOrigin(req)) {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: { message: 'Same-origin JSON request required' } }));
        return;
      }
      // Updates download fixed, public fingerprint data only; no upstream model calls.
      if (req.method === 'POST') { req.resume(); void detectorUpdates.sync().catch(() => {}); }
      res.writeHead(req.method === 'POST' ? 202 : 200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(await detectorUpdates.getStatus()));
      return;
    }
    if (url === '/api/lm-detector/v1/models' && req.method === 'GET') {
      await handleModels(req, res);
      return;
    }
    if (url !== '/api/lm-detector/v1/chat/completions' || req.method !== 'POST') {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'Detector API not found' } }));
      return;
    }
    if (!detectorSameOrigin(req)) {
      res.writeHead(403, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: { message: 'Same-origin JSON request required' } }));
      return;
    }
    const chunks = [];
    let size = 0;
    try {
      for await (const chunk of req) {
        size += chunk.length;
        if (size > 1024 * 1024) {
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: { message: 'Request too large' } }));
          return;
        }
        chunks.push(chunk);
      }
      // The shared proxy derives the upstream path from req.url, not this route's handler.
      // Normalize the private alias just like the Responses/Anthropic adapters do.
      const originalUrl = req.url;
      req.url = '/v1/chat/completions';
      try {
        await handleChatCompletions(req, res, Buffer.concat(chunks).toString(), requestId);
      } finally {
        req.url = originalUrl;
      }
    } catch {
      if (!res.headersSent) res.writeHead(500, { 'Content-Type': 'application/json' });
      if (!res.writableEnded) res.end(JSON.stringify({ error: { message: 'Detector request failed' } }));
    }
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
  } else if (url === '/v1/responses' && req.method === 'POST') {
    await handleResponses(req, res, body, requestId);
  } else if (url.split('?')[0] === '/v1/messages' && req.method === 'POST') {
    await handleAnthropicMessages(req, res, body, requestId);
  } else if (url.startsWith('/v1/')) {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: `Not supported: ${url}`, type: 'not_implemented' } }));
  } else {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: { message: 'Not found' } }));
  }
});

// 保存统计数据（程序退出时）
process.on('SIGINT', async () => {
  console.log('\n保存统计数据...');
  await detectorUpdates.stop();
  saveStats();
  process.exit();
});

process.on('SIGTERM', async () => {
  await detectorUpdates.stop();
  saveStats();
  process.exit();
});

server.listen(config.port, '127.0.0.1', () => {
  if (SERVE_UI) detectorUpdates.start();
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
