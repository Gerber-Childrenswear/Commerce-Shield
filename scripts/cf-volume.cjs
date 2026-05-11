'use strict';
const https = require('https');
const token = process.env.CLOUDFLARE_API_TOKEN;
const acct = process.env.CLOUDFLARE_ACCOUNT_ID;
const scriptName = process.env.CLOUDFLARE_WORKER_NAME || 'commerce-shield-prod';

if (!token || !acct) {
  console.error('Missing required env vars: CLOUDFLARE_API_TOKEN and CLOUDFLARE_ACCOUNT_ID');
  console.error('Optional env var: CLOUDFLARE_WORKER_NAME (defaults to commerce-shield-prod)');
  process.exit(1);
}

const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
const until = new Date().toISOString();

const query = `{
  viewer {
    accounts(filter: { accountTag: "${acct}" }) {
      workersInvocationsAdaptive(
        limit: 200
        filter: {
          datetime_geq: "${since}"
          datetime_leq: "${until}"
          scriptName: "${scriptName}"
        }
      ) {
        sum { requests subrequests errors }
        dimensions { status }
      }
    }
  }
}`;

const body = JSON.stringify({ query });
const req = https.request({
  hostname: 'api.cloudflare.com',
  path: '/client/v4/graphql',
  method: 'POST',
  headers: {
    Authorization: 'Bearer ' + token,
    'Content-Type': 'application/json',
    'Content-Length': Buffer.byteLength(body),
  },
}, r => {
  let d = '';
  r.on('data', c => (d += c));
  r.on('end', () => {
    const j = JSON.parse(d);
    if (j.errors) {
      console.error('GraphQL errors:', JSON.stringify(j.errors, null, 2));
      return;
    }
    const rows = j.data?.viewer?.accounts?.[0]?.workersInvocationsAdaptive || [];
    console.log(`Last 24h on ${scriptName}:`);
    rows.forEach(r => console.log(' ', r.dimensions.status, 'requests:', r.sum.requests, 'subrequests:', r.sum.subrequests, 'errors:', r.sum.errors));
    const total = rows.reduce((a, r) => a + r.sum.requests, 0);
    console.log('TOTAL:', total.toLocaleString());
  });
});
req.write(body);
req.end();
