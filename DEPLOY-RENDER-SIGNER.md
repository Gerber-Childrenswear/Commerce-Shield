# Deploy Signer to Render (Alternative to Cloud Run)

Since gcloud is having PATH issues, deploy to Render instead (you already use it for the UI).

## Step 1: Push Signer Code to GitHub

```powershell
cd "d:\Users\ncassidy\Desktop\GCW-Dev Repository\commerce-shield"
git add signer/
git commit -m "Add GTM signer service for edge bot events"
git push origin main
```

## Step 2: Create Service on Render

1. Go to https://dashboard.render.com
2. Click **New +** → **Web Service**
3. Connect your GitHub repo: `ncassidy233/commerce-shield`
4. Fill in:
   - **Name:** `commerce-shield-signer`
   - **Root Directory:** `signer`
   - **Environment:** `Node`
   - **Build Command:** `npm ci`
   - **Start Command:** `npm start`
5. Click **Create Web Service**

## Step 3: Add Environment Variables

On the Render service page:
1. Go to **Environment**
2. Add:
   - `EDGE_BOT_SHARED_SECRET` = your-base64-secret
   - `WORKER_URL` = https://commerce-shield-prod.ncassidy.workers.dev
3. Save

Render will auto-deploy. Service URL will be:
```
https://commerce-shield-signer.onrender.com
```

## Step 4: Update GTM

In your GTM HTTP Request tag:
- **Request URL:** `https://commerce-shield-signer.onrender.com/api/integrations/edge-bot-event`

Done. Simpler than Cloud Run, same result.
