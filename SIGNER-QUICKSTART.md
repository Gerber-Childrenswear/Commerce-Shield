# Commerce Shield GTM Server-Side Bot Detection – Complete Setup

## Status Summary
✅ Worker deployed (production)
✅ GTM import file created + variables added
✅ Signer service code ready
⏳ Signer deployed to Cloud Run (YOU ARE HERE)
⏳ GTM tag configured
⏳ End-to-end tested

---

## What You Have Right Now

### In Your Repo
- `worker/src/index.js` – production endpoint `/api/integrations/edge-bot-event` (signed requests only)
- `worker/wrangler.toml` – production Worker config
- `signer/` – Cloud Run deployment code (Node.js + Express)
- `GTM-N45F3JCC_commerce-shield-edge-import.json` – GTM import file
- `GTM-SETUP-FIELD-VALUES.md` – GTM field reference

### In GTM Server Container (imported)
- Variables: CS - Worker Endpoint, CS - Shop Domain, CS - Source
- Trigger: CS - Edge Bot Forwarder - Always
- (No tags yet)

### In Your Wrangler Secrets
- `EDGE_BOT_SHARED_SECRET` – already configured

---

## NEXT STEPS (In Order)

### 1. Deploy Signer to Cloud Run

**Fastest approach (single command):**

```powershell
# Edit these three values first:
$ProjectId = "YOUR_GOOGLE_CLOUD_PROJECT_ID"
$Secret = "YOUR_BASE64_ENCODED_SECRET"  # Must match what you put in Wrangler
$Region = "us-central1"

# Then run:
gcloud run deploy "commerce-shield-signer" `
  --source "./signer" `
  --platform managed `
  --region $Region `
  --allow-unauthenticated `
  --set-env-vars "EDGE_BOT_SHARED_SECRET=$Secret,WORKER_URL=https://commerce-shield-prod.ncassidy.workers.dev" `
  --project $ProjectId
```

After a few minutes, you'll get:
```
Service URL: https://commerce-shield-signer-XXXXX.run.app
```

**Copy that URL — you'll need it next.**

### 2. Create GTM HTTP Request Tag

In your GTM server container:

1. Go to **Tags** → **New**
2. Name: `CS - Edge Bot Forwarder`
3. Choose type: **HTTP Request**
4. Fill in:
   - **Request URL:** `https://commerce-shield-signer-XXXXX.run.app/api/integrations/edge-bot-event` (from step 1)
   - **Request Method:** POST
   - **Trigger:** CS - Edge Bot Forwarder - Always
   - **Add Header:** Content-Type = application/json
   - **Request Body (JSON):**
     ```json
     {
       "shop": "{{CS - Shop Domain}}",
       "source": "{{CS - Source}}",
       "page": "{{getRequestPath}}",
       "ua": "{{getRequestHeader|User-Agent}}",
       "isBot": false,
       "botScore": 0.1,
       "confidence": "low",
       "isMobile": false,
       "isLegitimate": true
     }
     ```
5. Save and publish

### 3. Test in GTM Preview

1. GTM container → **Preview**
2. Send any server event to your container
3. Look for "CS - Edge Bot Forwarder" tag in the firing list
4. Click it → check "Network" or response status

Expected: `{"ok":true,"accepted":false,"reason":"below_threshold"}`

Or if `isBot: true` in body: `{"ok":true,"accepted":true}`

### 4. Verify in Commerce Shield Dashboard

1. Go to `https://commerce-shield.onrender.com` (or your Render URL)
2. **Dashboard** tab
3. Look for "Bot Events (GTM Server)" row
4. Should see counts increment when events fire

### 5. Check Worker Logs

```powershell
# From your local machine:
Set-Location "d:\Users\ncassidy\Desktop\GCW-Dev Repository\commerce-shield\worker"
$env:CLOUDFLARE_API_TOKEN = "YOUR_CLOUDFLARE_API_TOKEN"
$env:CLOUDFLARE_ACCOUNT_ID = "YOUR_CLOUDFLARE_ACCOUNT_ID"

npx wrangler tail --name commerce-shield-prod
```

You should see entries like:
```
{"timestamp":"...","level":"info","message":"Edge bot event accepted: shop=gerberchildrenswear.myshopify.com, botScore=0.95, intensity=5"}
```

---

## File Reference

| File | Purpose |
|------|---------|
| `signer/index.js` | Signer server code |
| `signer/package.json` | Node dependencies |
| `signer/Dockerfile` | Cloud Run container spec |
| `signer/DEPLOY.md` | Detailed deployment guide |
| `GTM-SETUP-FIELD-VALUES.md` | GTM field mappings |
| `GTM-N45F3JCC_commerce-shield-edge-import.json` | GTM import file |

---

## Troubleshooting

### "EDGE_BOT_SHARED_SECRET env var is empty"
- The signer didn't get the environment variable.
- In Cloud Run console, edit the service and re-set the env var.
- Or redeploy with the gcloud command above.

### GTM tag shows "error"
- Check signer URL is correct (no typo)
- Test signer health: `curl https://commerce-shield-signer-XXXXX.run.app/health`
- Check Cloud Run logs for the signer service.

### Worker returns 401 Unauthorized
- Secret mismatch.
- Verify `EDGE_BOT_SHARED_SECRET` is the SAME base64 value in both Wrangler and Cloud Run.

### No bot events appearing in dashboard
- Check GTM Preview is actually firing the tag.
- Verify bot protection is enabled in Commerce Shield settings (slider > 0).
- Check `botScore` and `isBot` values in the body.

---

## Done?

Once you see bot events flowing through:
1. ✅ GTM is signing and forwarding
2. ✅ Worker is accepting and processing
3. ✅ Dashboard is counting them
4. ✅ System is live

You can now adjust bot protection intensity in the Commerce Shield admin UI (0-10 slider), and it will apply in real-time to GTM server-side events.

---

## Questions?

- **GTM setup:** See `GTM-SETUP-FIELD-VALUES.md`
- **Signer deployment:** See `signer/DEPLOY.md`
- **Worker code:** See `worker/src/index.js` line ~1500 (handleEdgeBotEvent)
