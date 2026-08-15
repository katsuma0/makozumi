// ============================================================
// Makozumi verification core — ECDSA P-256 (secp256r1) + SHA-256
//
// SECURITY MODEL
// This file is PUBLIC. It contains only public keys, which can verify
// signatures but — by the hardness of the elliptic curve discrete
// logarithm problem — cannot create them. Publishing it gives a forger
// nothing.
//
// HARD RULES enforced below (each one closes a specific attack):
//   1. Nothing from a token is displayed until its signature verifies.
//   2. The algorithm, curve, and hash are pinned in code. The token
//      cannot select them, so there is no "alg confusion" attack.
//   3. All rendering uses textContent. No token data ever reaches
//      innerHTML, so a signed-but-hostile payload still cannot script.
//   4. Inputs are size- and charset-limited before any parsing.
//   5. Unknown key ids, revoked serials, and expired items fail closed.
// ============================================================

export const VERSION = "2";

// Origins where the official verifier is served. Anything else is a mirror
// or an impostor, and the UI says so loudly.
export const OFFICIAL_ORIGINS = [
  "https://katsuma0.github.io",
];

// Public keys, by key id. Adding a key here (never removing one) lets keys
// rotate without invalidating tags already in the field.
export const PUBLIC_KEYS = {
  k1: {
    jwk: {
      kty: "EC",
      crv: "P-256",
      x: "sx2H14imF2Nnbvqu851Plz6Ix6Ln0j1EOr29uIYgYCk",
      y: "UpJseEdlrvRy4jrGvJ5Kq_FkVJLgRQZU7tHfj6rgeSM",
    },
    label: "Makozumi issuing key 1",
    retired: false,
  },
};

export const DEFAULT_KID = "k1";

// Bounds. A real tag token is ~250 chars; anything near these limits is
// an attacker probing for a parser or memory problem.
const MAX_TOKEN_CHARS = 4096;
const MAX_PAYLOAD_BYTES = 2048;
const MAX_FIELD_CHARS = 160;
const SIG_BYTES = 64; // P-256 r||s, IEEE P1363

// Fields shown in the UI, in display order.
export const DISPLAY_FIELDS = [
  ["p", "Item"],
  ["t", "Type"],
  ["o", "Issued by"],
  ["d", "Issued"],
  ["exp", "Valid until"],
  ["b", "Batch"],
  ["n", "Note"],
  ["sn", "Serial"],
];

// ---------- low-level, defensive parsing --------------------

const B64URL_RE = /^[A-Za-z0-9_-]+$/;

export function b64urlToBytes(s) {
  if (typeof s !== "string" || s.length === 0 || !B64URL_RE.test(s)) {
    throw new Error("not valid base64url");
  }
  let t = s.replace(/-/g, "+").replace(/_/g, "/");
  while (t.length % 4) t += "=";
  const bin = atob(t); // throws on malformed input; caller catches
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// Strip control characters and bidirectional-override characters. Without
// this, a signed payload could use U+202E to make "notebook" render as
// "koobeton", or hide text from the reader.
const UNSAFE_CHARS =
  /[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g;

export function sanitizeText(value) {
  if (value === undefined || value === null) return "";
  if (typeof value === "number" || typeof value === "boolean") value = String(value);
  if (typeof value !== "string") return "";
  const cleaned = value.replace(UNSAFE_CHARS, "").trim();
  return cleaned.length > MAX_FIELD_CHARS
    ? cleaned.slice(0, MAX_FIELD_CHARS) + "…"
    : cleaned;
}

// Accepts a raw token, a full tag URL, or pasted text with stray
// whitespace. Returns "<payload>.<signature>" or null.
export function extractToken(input) {
  if (typeof input !== "string") return null;
  let text = input.trim();
  if (!text || text.length > MAX_TOKEN_CHARS * 2) return null;

  // If it looks like a URL, pull the code out of the fragment (preferred)
  // or the ?c= query parameter (fallback for tools that drop fragments).
  if (/^https?:\/\//i.test(text)) {
    let url;
    try {
      url = new URL(text);
    } catch {
      return null;
    }
    text = url.hash ? url.hash.slice(1) : url.searchParams.get("c") || "";
  }

  text = text.replace(/\s+/g, "");
  if (!text) return null;

  // Some tag writers percent-encode the fragment.
  if (text.includes("%")) {
    try {
      text = decodeURIComponent(text);
    } catch {
      /* keep the raw text; validation below will reject it if malformed */
    }
  }

  if (text.length > MAX_TOKEN_CHARS) return null;
  return text.includes(".") ? text : null;
}

// ---------- verification ------------------------------------

const keyCache = new Map();

async function importVerifyKey(kid) {
  if (keyCache.has(kid)) return keyCache.get(kid);
  const entry = PUBLIC_KEYS[kid];
  if (!entry) return null;
  const key = await crypto.subtle.importKey(
    "jwk",
    entry.jwk,
    { name: "ECDSA", namedCurve: "P-256" }, // pinned: token cannot choose
    false,
    ["verify"] // this key can NEVER sign, even by mistake
  );
  keyCache.set(kid, key);
  return key;
}

function parsePayloadBytes(bytes) {
  if (bytes.length > MAX_PAYLOAD_BYTES) throw new Error("payload too large");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  const obj = JSON.parse(text);
  if (obj === null || typeof obj !== "object" || Array.isArray(obj)) {
    throw new Error("payload is not an object");
  }
  return obj;
}

// Read a field as an own property only. Guards against a payload that
// tries to smuggle values through the prototype chain.
function own(obj, key) {
  return Object.prototype.hasOwnProperty.call(obj, key) ? obj[key] : undefined;
}

function isIsoDate(s) {
  return typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s);
}

/**
 * Verify a Makozumi token.
 *
 * Resolves to an object with:
 *   state  — "authentic" | "expired" | "revoked" | "forged" | "malformed" | "unsupported"
 *   detail — human-readable explanation
 *   item   — sanitized fields, ONLY when the signature verified
 *   kid    — key id that verified it
 *
 * It never throws and never returns unverified payload data.
 */
export async function verifyToken(rawToken, options = {}) {
  const revoked = options.revoked instanceof Set ? options.revoked : null;
  const now = options.now instanceof Date ? options.now : new Date();

  const token = extractToken(rawToken);
  if (!token) {
    return { state: "malformed", detail: "This is not a Makozumi code." };
  }

  const parts = token.split(".");
  if (parts.length !== 2 || !parts[0] || !parts[1]) {
    return {
      state: "malformed",
      detail: "A Makozumi code has exactly two parts separated by a dot.",
    };
  }
  const [payloadB64, sigB64] = parts;

  let sigBytes, payloadBytes, payload;
  try {
    sigBytes = b64urlToBytes(sigB64);
    payloadBytes = b64urlToBytes(payloadB64);
  } catch {
    return { state: "malformed", detail: "This code is damaged or incomplete." };
  }

  // A P-256 signature is exactly 64 bytes. Reject anything else before
  // touching WebCrypto.
  if (sigBytes.length !== SIG_BYTES) {
    return {
      state: "forged",
      detail: "The signature is the wrong size for a Makozumi code.",
    };
  }

  // Parse the payload only to learn which key id to check against. Nothing
  // from it is displayed unless verification below succeeds.
  try {
    payload = parsePayloadBytes(payloadBytes);
  } catch {
    return { state: "malformed", detail: "This code is damaged or incomplete." };
  }

  const rawKid = own(payload, "kid");
  const kid = rawKid === undefined ? DEFAULT_KID : rawKid;
  if (typeof kid !== "string" || !Object.prototype.hasOwnProperty.call(PUBLIC_KEYS, kid)) {
    return {
      state: "forged",
      detail: "This code names a signing key that Makozumi does not publish.",
    };
  }

  // If WebCrypto itself is missing or refuses (very old browser, or a page
  // somehow loaded outside a secure context), say so plainly. Never let a
  // failure to check masquerade as either a pass or a forgery.
  if (!globalThis.crypto || !crypto.subtle) {
    return {
      state: "unsupported",
      detail:
        "This browser cannot perform the signature check. Open the official site over https in an up-to-date browser.",
    };
  }

  let key;
  try {
    key = await importVerifyKey(kid);
  } catch {
    key = null;
  }
  if (!key) {
    return {
      state: "unsupported",
      detail: "This verifier could not load the signing key needed to check this code.",
    };
  }

  let valid = false;
  try {
    valid = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" }, // pinned
      key,
      sigBytes,
      new TextEncoder().encode(payloadB64)
    );
  } catch {
    valid = false;
  }

  if (!valid) {
    return {
      state: "forged",
      detail:
        "The signature does not match. This code was not issued by Makozumi, or its details were altered.",
    };
  }

  // ---- signature is good; from here the payload is trusted data ----

  const version = own(payload, "v");
  if (version !== undefined && version !== 1 && version !== 2) {
    return {
      state: "unsupported",
      detail: "This code uses a newer format. Reload the page to update the verifier.",
    };
  }

  const item = {};
  for (const [field] of DISPLAY_FIELDS) {
    const v = sanitizeText(own(payload, field));
    if (v) item[field] = v;
  }
  item.kid = kid;
  item.retiredKey = PUBLIC_KEYS[kid].retired === true;

  // A correctly signed code that names nothing tells a customer nothing.
  // Refuse to show a bare "AUTHENTIC" over an empty card.
  if (!item.p || !item.sn) {
    return {
      state: "unsupported",
      detail:
        "This code carries a valid signature but is missing the item name or serial number, so it cannot be shown as a complete record.",
    };
  }

  const serial = item.sn || "";
  if (revoked && serial && revoked.has(serial)) {
    return {
      state: "revoked",
      detail:
        "This code was signed by Makozumi but has since been revoked — the item was reported lost, stolen, or withdrawn.",
      item,
      kid,
    };
  }

  const exp = own(payload, "exp");
  if (isIsoDate(exp)) {
    // Compare date-only strings to avoid timezone edge cases.
    const today = now.toISOString().slice(0, 10);
    if (exp < today) {
      return {
        state: "expired",
        detail: "This code is genuine, but its validity period ended on " + exp + ".",
        item,
        kid,
      };
    }
  }

  return {
    state: "authentic",
    detail: "Signature verified against the Makozumi public key.",
    item,
    kid,
  };
}

// ---------- revocation list ---------------------------------

/**
 * Fetch the published revocation list. Returns { revoked:Set, available:bool }.
 * A network failure never turns a genuine item into a fake one — the UI
 * says the revocation check could not run instead of guessing.
 */
export async function loadRevocations(url = "revoked.json") {
  try {
    const res = await fetch(url, { cache: "no-cache" });
    if (!res.ok) throw new Error("http " + res.status);
    const data = await res.json();
    const list = Array.isArray(data) ? data : data && data.revoked;
    if (!Array.isArray(list)) throw new Error("bad format");
    const set = new Set();
    for (const entry of list) {
      if (typeof entry === "string") set.add(entry);
      else if (entry && typeof entry.sn === "string") set.add(entry.sn);
    }
    return { revoked: set, available: true };
  } catch {
    return { revoked: new Set(), available: false };
  }
}

// ---------- page safety helpers -----------------------------

export function isOfficialOrigin(origin = location.origin) {
  return OFFICIAL_ORIGINS.includes(origin);
}

export function isFramed() {
  try {
    return window.top !== window.self;
  } catch {
    return true; // cross-origin access threw: we are definitely framed
  }
}

// WebCrypto only exists in a secure context. If this page was somehow
// served over plain http, send the visitor to the canonical https site,
// carrying the code along so verification still happens.
export function enforceSecureContext() {
  const local = ["localhost", "127.0.0.1", "[::1]", ""];
  if (location.protocol === "http:" && !local.includes(location.hostname)) {
    location.replace(OFFICIAL_ORIGINS[0] + "/makozumi/" + location.hash);
    return false;
  }
  return true;
}
