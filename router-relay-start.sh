#!/bin/sh
set -eu

proxy_json=$(curl -fsS 'https://proxy.webshare.io/api/v2/proxy/list/?mode=direct&page=1&page_size=100' \
  -H "Authorization: Token ${WEBSHARE_API_KEY}")
proxy_url=$(printf '%s' "$proxy_json" | node -e '
  let input = "";
  process.stdin.on("data", chunk => input += chunk);
  process.stdin.on("end", () => {
    const rows = JSON.parse(input).results || [];
    const proxy = rows.find(item => item.country_code === "US" && item.valid !== false);
    if (!proxy) process.exit(2);
    const user = encodeURIComponent(proxy.username);
    const pass = encodeURIComponent(proxy.password);
    process.stdout.write(`http://${user}:${pass}@${proxy.proxy_address}:${proxy.port}`);
  });
')

export HTTP_PROXY="$proxy_url"
export HTTPS_PROXY="$proxy_url"
export NO_PROXY='127.0.0.1,localhost'
export NODE_USE_ENV_PROXY=1
exec /usr/bin/node /home/ubuntu/api-gateway/router-relay.mjs
