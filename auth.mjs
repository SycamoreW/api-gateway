import { config, modelMap } from './state.mjs';
import { fingerprintKey, writeGatewayLog, getClientIp } from './logger.mjs';
import {
  isChannelEnabled,
  normalizeClientKeyEntry,
  saveConfig,
} from './config.mjs';

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
  if (!isChannelEnabled(config.channels?.[channelKey])) return false;
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
  if (authHeader.startsWith('Bearer ')) return authHeader.slice(7);
  // Also accept x-api-key header (Anthropic native format)
  const xApiKey = String(req.headers['x-api-key'] || '');
  if (xApiKey) return xApiKey;
  return '';
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


export {
  getClientKeyEntries,
  saveClientKeyEntries,
  findClientKeyEntry,
  isClientKeyExpired,
  clientCanUseChannel,
  clientCanUseModel,
  getAccessibleModelEntries,
  getModelQuotaCost,
  consumeClientQuota,
  getBearerToken,
  rejectAuth,
  adminAuth,
  clientAuth,
};
