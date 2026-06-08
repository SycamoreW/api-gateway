# API Gateway

OpenAI-compatible aggregate API gateway with a WebUI for channels, models, logs, stats, and custom streaming stop keywords.

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
- Custom streaming stop keywords per channel
- Batch stop-keyword setting with selectable channels

## Streaming Stop Keywords

In the WebUI, click `流式截断设置`.

You can:

- Enter one or more stop keywords, one per line or comma-separated
- Select which channels the keywords apply to
- Optionally inject a user prompt before the last user message so the model appends the stop keyword near the end of its own output
- Save and use immediately

Config field:

```json
{
  "stream_stop_sequences": [],
  "stream_stop_prompt": ""
}
```

When a keyword is detected in an SSE streaming response, the gateway stops forwarding and sends `[DONE]`. The keyword itself is not forwarded to the client.

For Pioneer channels, use `https://api.pioneer.ai/v1` when stream stop keywords are enabled. If a Pioneer channel is saved as `https://api.pioneer.ai` with stop keywords configured, the gateway normalizes it to the native `/v1` endpoint to avoid the aggregate upstream charging before the local truncation takes effect.

`stream_stop_prompt` is sent upstream as a `user` message inserted before the last original `user` message. This prompts the model to emit the stop keyword itself near the end, letting the gateway abort the upstream stream as soon as the keyword appears.

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
  "channels": {}
}
```

Use `api_key` as the Bearer token for clients:

```text
Authorization: Bearer 123456
```

Change this key from the WebUI after first login.
