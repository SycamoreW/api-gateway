# API Gateway

OpenAI-compatible aggregate API gateway with a WebUI for channels, models, logs, stats, prompt cache, and Claude thinking controls.

## Three Steps

```bash
git clone https://github.com/SycamoreW/api-gateway.git
cd api-gateway
sh start.sh
```

After startup, the terminal prints the WebUI address:

```text
WebUI: http://127.0.0.1:8300
API:   http://127.0.0.1:8300/v1
```

Open the WebUI and enter the initial management key:

```text
123456
```

Then edit channels, upstream API keys, and change the management key in the WebUI.

## Termux

Install Node.js and Git once:

```bash
pkg update && pkg install -y nodejs git
```

Then run the same three steps:

```bash
git clone https://github.com/SycamoreW/api-gateway.git
cd api-gateway
sh start.sh
```

On Termux, `start.sh` will try to open the WebUI automatically. If it does not open, copy the printed `WebUI` address into your browser.

## Features

- OpenAI-compatible `/v1/models` and `/v1/chat/completions`
- Route models to multiple upstream channels
- WebUI channel and model management
- Request logs and usage stats
- Pioneer billing status in the WebUI header
- Prompt Cache controls for Anthropic Messages API and compatible Claude proxy channels
- Anthropic thinking controls for compatible Claude models and providers

## Anthropic Prompt Cache

Enable Prompt Cache per channel in the WebUI. For channels that use the Anthropic Messages API, set the channel format to `anthropic`; the gateway converts OpenAI-compatible chat requests to `/v1/messages` and adds top-level Anthropic cache control.

For OpenAI-compatible Claude proxy channels, leave the format as OpenAI compatible and enable Prompt Cache only if the upstream accepts Anthropic-style `cache_control` on message content blocks. The gateway marks the last cacheable message before the latest user message:

```json
{
  "role": "system",
  "content": [
    {
      "type": "text",
      "text": "long reusable instructions...",
      "cache_control": {
        "type": "ephemeral",
        "ttl": "1h"
      }
    }
  ]
}
```

The WebUI defaults this option to `1h` for longer conversations. Use `5m` for short-lived cache if the provider charges less for 5-minute writes. The 1-hour cache can reduce repeated context processing after longer pauses, but cache writes cost more than the default 5-minute cache on Anthropic.

The WebUI stats header shows cache hit count, cache read tokens, and cache creation tokens. Usage tables also show per-model, per-channel, and per-IP cache hits; recent requests show whether a request hit cache.

## Anthropic Thinking

Anthropic-format channels can optionally inject thinking controls in the request body. The WebUI supports two modes:

- `enabled + budget_tokens`: sends `thinking: {"type":"enabled","budget_tokens":32000}`. If `max_tokens` is lower than the thinking budget, the gateway raises `max_tokens` to `budget_tokens + 1024`.
- `adaptive + effort`: sends `thinking: {"type":"adaptive"}` and, when selected, `output_config: {"effort":"max"}` or another effort level.

If a client request already includes `thinking` or `output_config`, the gateway passes those through and does not replace them.

## Files

- `index.mjs`: server, auth, routing, proxying, logs, stats, config API
- `ui.html`: WebUI
- `start.sh`: three-step startup script
- `config.example.json`: sanitized example config
- `config.json`: local runtime config, ignored by Git
- `stats.json`: runtime stats, ignored by Git

## Config

On first startup, `start.sh` creates `config.json` from `config.example.json`.

Important fields:

```json
{
  "port": 8300,
  "api_key": "123456",
  "channels": {
    "pio": {
      "name": "pio",
      "base_url": "https://api.pioneer.ai/v1",
      "key": "pio_sk_...",
      "prompt_cache_enabled": true,
      "prompt_cache_ttl": "1h",
      "models": ["claude-opus-4-7"]
    }
  }
}
```

Use `api_key` as the Bearer token for clients:

```text
Authorization: Bearer 123456
```

Change this key from the WebUI after first login.
