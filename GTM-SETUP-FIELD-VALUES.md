# GTM HTTP Request Tag Setup

## Where to Find Each Field in GTM Server Container

### Step 1: Create or Open Tag
- Go to: **Tags** menu
- Click: **New** (or edit existing tag)
- Choose: **HTTP Request** (template type)

### Step 2: Basic Configuration

**Field: Request URL** (top of tag form)
- Type or paste: `https://commerce-shield-prod.ncassidy.workers.dev/api/integrations/edge-bot-event`
- OR use variable picker → select `CS - Worker Endpoint`

**Field: Request Method**
- Choose: **POST**

**Field: Triggering**
- Click trigger field
- Select: `CS - Edge Bot Forwarder - Always`

### Step 3: Headers (scroll down or expand "Additional settings")

**Add Header Row 1:**
- Key: `Content-Type`
- Value: `application/json`

### Step 4: Request Body (scroll down, usually labeled "Body")

Paste this JSON exactly:
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

---

## Exact GTM Field Mapping Table

| GTM Field | Value |
|-----------|-------|
| **Request URL** | https://commerce-shield-prod.ncassidy.workers.dev/api/integrations/edge-bot-event |
| **Request Method** | POST |
| **Headers: Content-Type** | application/json |
| **Trigger** | CS - Edge Bot Forwarder - Always |
| **Body (JSON)** | See JSON block above |

---

## IMPORTANT: Signature Headers Missing

The Worker expects signed requests with these headers:
- `X-CS-Timestamp`
- `X-CS-Nonce`
- `X-CS-Signature`

GTM's built-in HTTP Request tag **cannot generate HMAC signatures**.

**You have two options:**

### Option A: Use Signer Service (Recommended)
Deploy signer code to Cloud Run or your own server, then:
1. Replace Request URL with: `https://your-signer-endpoint/sign?target=edge-bot-event`
2. Signer adds headers + forwards to Worker

### Option B: Modify GTM Tag Type
Use a custom template tag (requires GTM admin access) that can compute HMAC-SHA256.

---

## Checklist

- [x] Variables created (CS - Worker Endpoint, CS - Shop Domain, CS - Source)
- [x] Trigger created (CS - Edge Bot Forwarder - Always)
- [ ] HTTP Request tag created with fields above
- [ ] Signer service deployed to Cloud Run
- [ ] Test GTM Preview: verify tag fires
- [ ] Test Worker endpoint: confirm accepted=true responses
- [ ] Verify Commerce Shield dashboard: bot visits increment
