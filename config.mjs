import fs from 'node:fs';
import { config, modelMap, CONFIG_FILE } from './state.mjs';

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

function normalizeChannelForSave(channel = {}) {
  const keys = getChannelKeys(channel);
  const next = { ...channel };
  next.enabled = channel.enabled !== false;
  if (Object.prototype.hasOwnProperty.call(channel, 'model_prefix')) {
    next.model_prefix = String(channel.model_prefix || '').trim();
  }
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

function isChannelEnabled(channel = {}) {
  return channel?.enabled !== false;
}

function normalizePromptCacheTtl(ttl = '') {
  return String(ttl || '').trim() === '1h' ? '1h' : '5m';
}

function rebuildModelMap() {
  modelMap.clear();
  for (const [ckey, ch] of Object.entries(config.channels)) {
    if (!isChannelEnabled(ch)) continue;
    const overrides = (ch && typeof ch.model_overrides === 'object' && ch.model_overrides) || {};
    for (const m of ch.models) {
      // Allow per-channel model_overrides to rewrite the upstream model id.
      // Example: { "provider/auto": "provider/model-id" } makes inbound
      // `provider/auto` resolve to the same channel but forward `model-id`
      // (after stripModelPrefix) to the upstream provider.
      const override = Object.prototype.hasOwnProperty.call(overrides, m) ? overrides[m] : null;
      const upstreamModel = (typeof override === 'string' && override.trim()) ? override.trim() : m;
      modelMap.set(m, { channelKey: ckey, upstreamModel });
    }
  }

}

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


export {
  normalizeKeyList,
  getChannelKeys,
  normalizeChannelForSave,
  isChannelEnabled,
  normalizePromptCacheTtl,
  rebuildModelMap,
  normalizeStringArray,
  normalizeExpiresAt,
  normalizeClientKeyEntry,
  saveConfig,
  normalizeImportedConfig,
};
