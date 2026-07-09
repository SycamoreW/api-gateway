import fs from 'node:fs';
import path from 'node:path';

let CONFIG_FILE = path.resolve(process.argv[2] || 'config.json');
if (!fs.existsSync(CONFIG_FILE)) {
  const fallback = path.resolve(import.meta.dirname, 'config.json');
  if (fs.existsSync(fallback)) {
    CONFIG_FILE = fallback;
  }
}
const config = JSON.parse(fs.readFileSync(CONFIG_FILE, 'utf-8'));
if (!Array.isArray(config.api_keys)) config.api_keys = [];

const LOG_DIR = path.resolve('logs');
const LOG_MAX_BODY_CHARS = 2000;
const HIDDEN_UI_LOG_EVENTS = new Set(['http_request', 'model_params', 'model_routed']);
const channelKeyCursors = new Map();

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
    hourlyStats: {},
    recentLogs: []
  };
}
if (!stats.hourlyStats || typeof stats.hourlyStats !== 'object') stats.hourlyStats = {};

const SERVE_UI = fs.existsSync(path.resolve('ui.html'));

const LEGACY_MODEL_ALIASES = new Map([
]);

const modelMap = new Map();

export function resetStats() {
  for (const key of Object.keys(stats)) delete stats[key];
  Object.assign(stats, {
    totalRequests: 0,
    modelUsage: {},
    channelUsage: {},
    ipUsage: {},
    dailyStats: {},
    hourlyStats: {},
    recentLogs: [],
  });
}

export {
  CONFIG_FILE,
  config,
  LOG_DIR,
  LOG_MAX_BODY_CHARS,
  HIDDEN_UI_LOG_EVENTS,
  channelKeyCursors,
  STATS_FILE,
  SERVE_UI,
  LEGACY_MODEL_ALIASES,
  modelMap,
  stats,
};
