const express = require('express');
const crypto = require('crypto');
const http = require('http');

const app = express();
app.use(express.json({ limit: '10mb' }));

const PORT = process.env.PORT || 8080;
const SHARED_SECRET = process.env.EDGE_BOT_SHARED_SECRET || '';
const WORKER_URL = process.env.WORKER_URL || 'https://commerce-shield-prod.ncassidy.workers.dev';

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

    const bodyString = JSON.stringify(req.body);
    const timestamp = Date.now().toString();
    const nonce = generateNonce();
    const signature = createHmacSignature(SHARED_SECRET, timestamp, nonce, bodyString);

    const targetUrl = `${WORKER_URL}/api/integrations/edge-bot-event`;

    const forwardReq = new Promise((resolve, reject) => {
      const options = {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(bodyString),
          'X-CS-Timestamp': timestamp,
          'X-CS-Nonce': nonce,
          'X-CS-Signature': signature,
        },
      };

      const request = http.request(targetUrl, options, (response) => {
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
});
