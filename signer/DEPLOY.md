# Commerce Shield GTM Signer Service – Cloud Run Deployment

## What This Does
Signs requests from GTM with HMAC-SHA256 headers before forwarding to the Commerce Shield Worker.

GTM → Signer (adds headers) → Worker

## Prerequisites
- Google Cloud Project (same as your GTM server container, if using GCP)
- `gcloud` CLI installed
- EDGE_BOT_SHARED_SECRET value (already set in Wrangler)

## Deployment Steps

### Step 1: Get Your Secret

From your local terminal (you already have this set):
```powershell
# Retrieve the secret you set in Wrangler
$env:EDGE_BOT_SHARED_SECRET = "your-secret-value"
# (If you don't have it, regenerate one and note it)
```

### Step 2: Build and Push to Cloud Run

```bash
# Set your Google Cloud Project
export PROJECT_ID="your-google-cloud-project-id"
export REGION="us-central1"
export SERVICE_NAME="commerce-shield-signer"

# Navigate to signer directory
cd signer

# Build and deploy in one command
gcloud run deploy $SERVICE_NAME \
  --source . \
  --platform managed \
  --region $REGION \
  --allow-unauthenticated \
  --set-env-vars "EDGE_BOT_SHARED_SECRET=your-base64-encoded-secret" \
  --set-env-vars "WORKER_URL=https://<your-worker-origin>" \
  --project $PROJECT_ID
```

### Step 3: Copy Your Signer URL

After deployment completes, Cloud Run will output:
```
Service URL: https://commerce-shield-signer-xxxxx.run.app
```

Save this URL.

### Step 4: Update GTM Tag

1. Go to GTM server container
2. Open the CS - Edge Bot Forwarder tag
3. Change **Request URL** to:
   ```
   https://commerce-shield-signer-xxxxx.run.app/api/integrations/edge-bot-event
   ```

### Step 5: Test

1. GTM Preview
2. Send a test event through your GTM container
3. In Cloud Run logs, you should see the forwarded request
4. Commerce Shield dashboard should show bot event accepted

---

## PowerShell One-Liner Deployment

If you prefer a single command from your machine:

```powershell
$ProjectId = "your-google-cloud-project-id"
$Region = "us-central1"
$Secret = "your-base64-encoded-secret"
$WorkerUrl = "https://<your-worker-origin>"

gcloud run deploy "commerce-shield-signer" `
  --source ./signer `
  --platform managed `
  --region $Region `
  --allow-unauthenticated `
  --set-env-vars EDGE_BOT_SHARED_SECRET=$Secret,WORKER_URL=$WorkerUrl `
  --project $ProjectId
```

---

## Health Check

After deployment, test the signer:

```bash
curl https://commerce-shield-signer-xxxxx.run.app/health
```

Expected response:
```json
{"status":"ok","service":"commerce-shield-signer"}
```

---

## Environment Variables

| Var | Required | Example |
|-----|----------|---------|
| `EDGE_BOT_SHARED_SECRET` | YES | Base64-encoded HMAC key |
| `WORKER_URL` | NO (default shown) | https://<your-worker-origin> |
| `PORT` | NO (default 8080) | 8080 |

---

## Local Testing

Run locally before deploying:

```bash
cd signer
npm install
EDGE_BOT_SHARED_SECRET="your-secret" npm start
```

Then test:
```bash
curl -X POST http://localhost:8080/api/integrations/edge-bot-event \
  -H "Content-Type: application/json" \
  -d '{
    "shop":"gerberchildrenswear.myshopify.com",
    "source":"gtm-server",
    "page":"/products/test",
    "ua":"Mozilla/5.0 ...",
    "isBot":true,
    "botScore":0.95,
    "confidence":"high",
    "isMobile":false,
    "isLegitimate":false
  }'
```

Expected response:
```json
{"ok":true,"accepted":true,"botScore":0.95,"confidence":"high","intensity":5}
```

---

## Troubleshooting

### 503 Error: Signer not configured
- EDGE_BOT_SHARED_SECRET env var is empty or not set.
- Check Cloud Run environment variables in the console.

### 401 Error: Invalid signature
- Secret mismatch between GTM signer and Worker.
- Ensure both use the exact same base64-encoded secret.

### 502 Bad Gateway
- Worker endpoint unreachable.
- Check WORKER_URL is correct and Worker is deployed.

---

## Files Included

```
signer/
├── index.js            # Main signer server
├── package.json        # Node dependencies
├── Dockerfile          # Cloud Run container
└── DEPLOY.md           # This file
```
