import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('./lm-detector-dist/', import.meta.url));
const mime = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml', '.png': 'image/png', '.webp': 'image/webp', '.ico': 'image/x-icon',
  '.woff2': 'font/woff2', '.woff': 'font/woff', '.txt': 'text/plain; charset=utf-8',
  '.md': 'text/plain; charset=utf-8', '.wasm': 'application/wasm',
};

/** Mount only the built site, never the repository, config, or Cloudflare worker. */
export async function serveDetector(req, res) {
  const pathname = req.url.split('?')[0];
  if (pathname !== '/lm-detector' && !pathname.startsWith('/lm-detector/')) return false;
  const fail = status => { res.writeHead(status); res.end(); return true; };
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.setHeader('Allow', 'GET, HEAD');
    return fail(405);
  }
  if (['/lm-detector', '/lm-detector/', '/lm-detector/index.html'].includes(pathname)) {
    res.writeHead(302, { Location: '/#/detector', 'Cache-Control': 'no-store' }); res.end(); return true;
  }
  // Only the headless detection engine and fingerprint data remain public.
  if (!pathname.startsWith('/lm-detector/native/') && !pathname.startsWith('/lm-detector/data/')) return fail(404);
  let relative;
  try { relative = decodeURIComponent(pathname.slice('/lm-detector/'.length)); } catch { return fail(400); }
  if (relative.includes('\\') || relative.includes('\0') || relative.split('/').some(part => part.startsWith('.') || part.startsWith('_'))) return fail(404);
  let target = path.resolve(root, relative || 'index.html');
  if (!target.startsWith(root)) return fail(404);
  try {
    let stat = await fs.promises.stat(target);
    if (stat.isDirectory()) {
      if (!pathname.endsWith('/')) {
        res.writeHead(302, { Location: pathname + '/', 'Cache-Control': 'no-store' }); res.end(); return true;
      }
      target = path.join(target, 'index.html'); stat = await fs.promises.stat(target);
    }
    if (!stat.isFile()) return fail(404);
    const real = await fs.promises.realpath(target);
    const realRoot = await fs.promises.realpath(root);
    if (!real.startsWith(realRoot + path.sep)) return fail(404);
    res.writeHead(200, {
      'Content-Type': mime[path.extname(target)] || 'application/octet-stream',
      'Content-Length': stat.size,
      'Cache-Control': 'private, no-cache',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin',
      'X-Robots-Tag': 'noindex, nofollow',
    });
    if (req.method === 'HEAD') { res.end(); return true; }
    const stream = fs.createReadStream(target);
    stream.on('error', () => res.destroy());
    res.on('close', () => stream.destroy());
    stream.pipe(res);
  } catch (error) { return fail(error.code === 'ENOENT' || error.code === 'ENOTDIR' ? 404 : 500); }
  return true;
}

/** Cookie-authenticated sampling must not be triggerable by another website. */
export function detectorSameOrigin(req) {
  if (req.headers['sec-fetch-site'] && req.headers['sec-fetch-site'] !== 'same-origin') return false;
  const proto = req.headers['x-forwarded-proto'] || 'http';
  return req.headers.origin === `${proto}://${req.headers.host}` &&
    /^application\/json(?:\s*;|$)/i.test(req.headers['content-type'] || '');
}
