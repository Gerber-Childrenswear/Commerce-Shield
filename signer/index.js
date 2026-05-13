const express = require('express');
const crypto = require('crypto');
const http = require('http');
const https = require('https');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 8080;
const SHARED_SECRET = process.env.EDGE_BOT_SHARED_SECRET || '';
const WORKER_URL = process.env.WORKER_URL || 'https://commerce-shield-prod.ncassidy.workers.dev';
const BLOCKED_FORWARD_SOURCES = process.env.BLOCKED_FORWARD_SOURCES || 'gtm-server';
const FORWARD_TIMEOUT_MS = Number(process.env.FORWARD_TIMEOUT_MS) > 0
  ? Number(process.env.FORWARD_TIMEOUT_MS)
  : 5000;

function parseSourceDenylist(value) {
  return new Set(
    String(value || '')
      .split(',')
      .map((entry) => entry.trim().toLowerCase())
      .filter(Boolean)
  );
}

const blockedSources = parseSourceDenylist(BLOCKED_FORWARD_SOURCES);

function normalizeSource(value) {
  return String(value || '').trim().toLowerCase();
}

function getHttpClient(url) {
  return url.protocol === 'https:' ? https : http;
}

function createHmacSignature(secret, timestamp, nonce, body) {
  const message = `${timestamp}.${nonce}.${body}`;
  return 'sha256=' + crypto
    .createHmac('sha256', Buffer.from(secret, 'base64'))
    .update(message)
    .digest('hex');
}

function generateNonce(length = 32) {
  return crypto.randomBytes(Math.ceil(length / 2)).toString('hex').slice(0, length);
}

app.post('/api/integrations/edge-bot-event', async (req, res) => {
  try {
    if (!SHARED_SECRET) {
      return res.status(503).json({ error: 'Signer not configured: EDGE_BOT_SHARED_SECRET is missing' });
    }

    if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
      return res.status(400).json({ error: 'Invalid JSON body' });
    }

    const source = normalizeSource(req.body.source);
    if (source && blockedSources.has(source)) {
      return res.status(200).json({ ok: true, accepted: false, reason: 'blocked_source' });
    }

    const bodyString = JSON.stringify(req.body);
    const timestamp = Date.now().toString();
    const nonce = generateNonce();
    const signature = createHmacSignature(SHARED_SECRET, timestamp, nonce, bodyString);

    const base = WORKER_URL.endsWith('/') ? WORKER_URL.slice(0, -1) : WORKER_URL;
    const targetUrl = new URL(`${base}/api/integrations/edge-bot-event`);
    const client = getHttpClient(targetUrl);

    const forwardReq = new Promise((resolve, reject) => {
      const options = {
        method: 'POST',
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || (targetUrl.protocol === 'https:' ? 443 : 80),
        path: `${targetUrl.pathname}${targetUrl.search || ''}`,
        timeout: FORWARD_TIMEOUT_MS,
        headers: {
          Host: targetUrl.host,
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyString),
          'X-CS-Timestamp': timestamp,
          'X-CS-Nonce': nonce,
          'X-CS-Signature': signature,
        },
      };

      const request = client.request(options, (response) => {
        let data = '';
        response.on('data', chunk => data += chunk);
        response.on('end', () => {
          resolve({
            status: response.statusCode,
            headers: response.headers,
            body: data,
          });
        });
      });

      request.on('error', reject);
      request.on('timeout', () => {
        request.destroy(new Error(`Forward request timed out after ${FORWARD_TIMEOUT_MS}ms`));
      });
      request.write(bodyString);
      request.end();
    });

    const result = await forwardReq;

    res.status(result.status || 200);
    Object.entries(result.headers || {}).forEach(([k, v]) => {
      if (!k.startsWith('content-encoding') && !k.startsWith('transfer-encoding')) {
        res.setHeader(k, v);
      }
    });

    try {
      res.json(JSON.parse(result.body));
    } catch (e) {
      res.send(result.body);
    }
  } catch (err) {
    console.error('Signer error:', err);
    res.status(500).json({ error: 'Signer service error', details: err.message });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', service: 'commerce-shield-signer' });
});

app.listen(PORT, () => {
  console.log(`Commerce Shield signer service listening on port ${PORT}`);
  console.log(`Worker URL: ${WORKER_URL}`);
  console.log(`Secret configured: ${SHARED_SECRET ? 'YES' : 'NO'}`);
  console.log(`Blocked forward sources: ${Array.from(blockedSources).join(', ') || 'none'}`);
});
