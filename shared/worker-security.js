const encoder = new TextEncoder();

function toHex(bytes) {
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function decodeSharedSecret(secret) {
  const normalized = typeof secret === "string" ? secret.trim() : "";
  if (!normalized) return encoder.encode("");

  const looksBase64 = normalized.length % 4 === 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(normalized);
  if (!looksBase64) {
    return encoder.encode(normalized);
  }

  try {
    const binary = atob(normalized);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  } catch {
    return encoder.encode(normalized);
  }
}

export function buildSignaturePayload(timestamp, nonce, bodyText) {
  return `${timestamp}.${nonce}.${bodyText}`;
}

export async function createHmacSignature(secret, timestamp, nonce, bodyText) {
  const key = await crypto.subtle.importKey(
    "raw",
    decodeSharedSecret(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(buildSignaturePayload(timestamp, nonce, bodyText)));
  return toHex(new Uint8Array(signature));
}

export function timingSafeEqualHex(left, right) {
  if (typeof left !== "string" || typeof right !== "string") return false;
  if (left.length !== right.length) return false;
  let result = 0;
  for (let index = 0; index < left.length; index += 1) {
    result |= left.charCodeAt(index) ^ right.charCodeAt(index);
  }
  return result === 0;
}

export function parseAllowedOrigins(value) {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}
