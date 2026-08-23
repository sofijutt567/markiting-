/**
 * =============================================================================
 *  Health Jobs Portal — "Advertise With Us" Worker
 * =============================================================================
 *  A complete, standalone Cloudflare Worker for the ad-booking flow:
 *
 *    1. /advertise                 → Start page ("Create Now")
 *    2. /advertise/package         → Choose a package (after account check)
 *    3. /advertise/details         → Enter ad content / requirements
 *    4. /advertise/payment         → Choose payment method + submit proof
 *    5. /advertise/thank-you       → Confirmation page
 *
 *  API endpoints:
 *    GET  /api/advertise/account-type   → { loggedIn, type: 'employer'|'candidate' }
 *    POST /api/advertise/submit         → saves the final ad request to D1 + R2
 *    GET/POST /api/ads/*                → ad-serving + admin endpoints (see below)
 *
 *  Admin auth: the same Google Sign-In already used on your main Admin
 *  Panel. The browser sends the Firebase ID token as
 *  "Authorization: Bearer <idToken>", and this worker verifies it directly
 *  against Google's public keys using the built-in Web Crypto API — no npm
 *  packages, no build step. Safe to paste straight into the Cloudflare
 *  dashboard's Quick Edit editor as a single file.
 *
 *  HOW TO ADD MORE ROUTES:
 *    Just add another `if (path === "/your-route") { ... }` block inside the
 *    ROUTES section below (or another `else if` inside handleApi for APIs).
 * =============================================================================
 */

// ─────────────────────────────────────────────────────────────────────────
//  ADMIN AUTH — must match the Firebase project + admin email used on the
//  main Admin Panel (admin-index.html) exactly. No external libraries: this
//  verifies the Firebase ID token's RS256 signature by hand using the
//  Worker runtime's built-in Web Crypto API.
// ─────────────────────────────────────────────────────────────────────────
const FIREBASE_PROJECT_ID = "jobs-45cc9";
const ADMIN_EMAIL = "sufiangsufiang50@gmail.com";
const GOOGLE_JWKS_URL = "https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com";

// Small in-memory cache so we don't re-fetch Google's public keys on every
// single request — they only rotate occasionally. Lives for the lifetime
// of this Worker isolate (which is fine; it'll naturally refresh).
let _jwksCache = null;
let _jwksCacheAt = 0;
const JWKS_CACHE_MS = 60 * 60 * 1000; // 1 hour

async function getGoogleJWKS() {
  if (_jwksCache && Date.now() - _jwksCacheAt < JWKS_CACHE_MS) return _jwksCache;
  const res = await fetch(GOOGLE_JWKS_URL);
  const data = await res.json();
  _jwksCache = data.keys || [];
  _jwksCacheAt = Date.now();
  return _jwksCache;
}

function base64UrlToUint8Array(base64url) {
  const base64 = base64url.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(base64url.length / 4) * 4, "=");
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function base64UrlDecodeToString(base64url) {
  return new TextDecoder().decode(base64UrlToUint8Array(base64url));
}

/**
 * Verifies a Firebase-issued ID token's signature + standard claims by
 * hand, with no external libraries:
 *   1. Split the JWT and find the matching public key by "kid".
 *   2. Import that JWK and verify the RS256 signature with Web Crypto.
 *   3. Check issuer / audience / expiry / auth-time per Firebase's rules.
 * Returns the decoded payload if everything checks out, otherwise null.
 */
async function verifyFirebaseIdToken(idToken) {
  const parts = idToken.split(".");
  if (parts.length !== 3) return null;
  const [headerB64, payloadB64, signatureB64] = parts;

  let header, payload;
  try {
    header = JSON.parse(base64UrlDecodeToString(headerB64));
    payload = JSON.parse(base64UrlDecodeToString(payloadB64));
  } catch (e) {
    return null;
  }

  if (header.alg !== "RS256") return null;

  const keys = await getGoogleJWKS();
  const jwk = keys.find((k) => k.kid === header.kid);
  if (!jwk) return null;

  let cryptoKey;
  try {
    cryptoKey = await crypto.subtle.importKey(
      "jwk",
      jwk,
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"]
    );
  } catch (e) {
    return null;
  }

  const signedData = new TextEncoder().encode(`${headerB64}.${payloadB64}`);
  const signature = base64UrlToUint8Array(signatureB64);

  const isSignatureValid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", cryptoKey, signature, signedData);
  if (!isSignatureValid) return null;

  const now = Math.floor(Date.now() / 1000);
  if (typeof payload.exp !== "number" || payload.exp < now) return null; // expired
  if (typeof payload.iat !== "number" || payload.iat > now + 60) return null; // issued in the future
  if (payload.aud !== FIREBASE_PROJECT_ID) return null;
  if (payload.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`) return null;
  if (!payload.sub) return null;

  return payload;
}

/**
 * Verifies the Authorization: Bearer <idToken> header on a request against
 * Google's public keys. Works for ANY signed-in user on the site (not just
 * the admin) — callers decide what to do with the returned payload.
 * Returns the token payload if valid, otherwise null.
 */
async function verifyUserToken(request) {
  const authHeader = request.headers.get("Authorization") || "";
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  return verifyFirebaseIdToken(match[1]);
}

/**
 * Same as verifyUserToken, but additionally requires the token to belong
 * to ADMIN_EMAIL — used to gate the Ad Manager endpoints.
 */
async function verifyAdminRequest(request) {
  const payload = await verifyUserToken(request);
  if (!payload) return null;
  if (payload.email !== ADMIN_EMAIL) return null;
  if (!payload.email_verified) return null;
  return payload;
}

// ─────────────────────────────────────────────────────────────────────────
//  CONFIG — edit these freely
// ─────────────────────────────────────────────────────────────────────────
const SITE_NAME = "Health Jobs Portal";
const SITE_URL = "https://healthjobportal.com"; // already set to your domain
const BRAND_COLOR = "#0a66c2";
const LOGO_URL = `${SITE_URL}/images/logo.png`;

// Footer contact / social details — edit freely.
const CONTACT_EMAIL = "supporthealthjobs@gmail.com";
const CONTACT_PHONE = "0314-1303160";
const FACEBOOK_URL = "https://www.facebook.com/share/18NgAzQLrp/";
const WHATSAPP_CHANNEL_URL = "https://whatsapp.com/channel/0029VbCe3Mf2kNFroj9qx223";
const TIKTOK_URL = "https://www.tiktok.com/@healthjobs.portal?_r=1&_t=ZS-98ybHKEhcNZ";

// ── EMAIL WORKER ────────────────────────────────────────────────────────
// URL of the separate "Email Worker" (Resend-based) that sends the
// pending/approved/rejected status emails. Replace this with the real
// deployed URL of that worker once you have it.
const EMAIL_WORKER_URL = "https://markitingemails.sufiangsufiang50.workers.dev";
// The shared secret itself now comes from env.EMAIL_SECRET (a Worker
// secret you add on THIS worker) — must be the EXACT same value as the
// EMAIL_SECRET secret on the email worker.

// The four ad-image shapes we accept, in the order they're always shown.
// "ratio" = width / height, used to check an uploaded image against.
const ASPECT_RATIOS = [
  { id: "1:1", label: "Square (1:1)", ratio: 1 / 1 },
  { id: "5:4", label: "Landscape (5:4)", ratio: 5 / 4 },
  { id: "4:3", label: "Landscape (4:3)", ratio: 4 / 3 },
  { id: "3:4", label: "Portrait (3:4)", ratio: 3 / 4 },
];

// Each platform can be selected on its own or combined with others — the
// total price is just the sum of whichever ones are checked. Each platform
// keeps its OWN duration even inside a combo (e.g. WhatsApp still expires
// after 7 days even if bundled with permanent Facebook + TikTok).
const PLATFORMS = [
  {
    id: "whatsapp",
    name: "WhatsApp",
    price: 300,
    duration: "7 Days",
    durationDays: 7,
    onSite: false,
    color: "#25D366",
    icon: `<svg viewBox="0 0 24 24" fill="white"><path d="M12.04 2C6.58 2 2.13 6.45 2.13 11.91c0 1.75.46 3.45 1.32 4.95L2.05 22l5.25-1.38a9.9 9.9 0 0 0 4.74 1.21h.01c5.46 0 9.91-4.45 9.91-9.91C21.96 6.45 17.5 2 12.04 2zm5.8 14.11c-.24.68-1.4 1.3-1.94 1.38-.5.08-1.13.11-1.82-.11-.42-.13-.96-.31-1.65-.6-2.9-1.25-4.79-4.17-4.94-4.36-.14-.19-1.18-1.57-1.18-3 0-1.43.75-2.13 1.02-2.42.27-.29.58-.36.78-.36.2 0 .39 0 .56.01.18.01.42-.07.66.5.24.58.83 2.01.9 2.16.07.15.12.32.02.51-.09.19-.14.31-.28.48-.14.17-.29.37-.42.5-.14.14-.28.29-.12.57.16.28.71 1.17 1.53 1.9 1.05.94 1.94 1.23 2.22 1.37.28.14.44.12.6-.07.16-.19.68-.79.87-1.06.19-.27.37-.22.62-.13.25.09 1.6.75 1.87.89.27.14.45.2.51.32.07.11.07.65-.17 1.33z"/></svg>`,
    desc: "Posted on our WhatsApp Channel.",
    // WhatsApp Channel posts accept any of the four shapes.
    allowedRatios: ["1:1", "5:4", "4:3", "3:4"],
  },
  {
    id: "facebook",
    name: "Facebook",
    price: 400,
    duration: "Permanent",
    durationDays: null,
    onSite: false,
    color: "#1877F2",
    icon: `<svg viewBox="0 0 24 24" fill="white"><path d="M22 12.06C22 6.51 17.52 2 12 2S2 6.51 2 12.06c0 5.02 3.66 9.18 8.44 9.94v-7.03H7.9v-2.91h2.54V9.85c0-2.51 1.49-3.9 3.77-3.9 1.09 0 2.24.2 2.24.2v2.46h-1.26c-1.24 0-1.63.77-1.63 1.56v1.89h2.78l-.44 2.91h-2.34V22c4.78-.76 8.44-4.92 8.44-9.94z"/></svg>`,
    desc: "Posted on our Facebook Page.",
    // Facebook accepts any of the four shapes, including portrait.
    allowedRatios: ["1:1", "5:4", "4:3", "3:4"],
  },
  {
    id: "tiktok",
    name: "TikTok",
    price: 400,
    duration: "Permanent",
    durationDays: null,
    onSite: false,
    color: "#000000",
    icon: `<svg viewBox="0 0 24 24" fill="white"><path d="M16.6 5.82c-.99-.99-1.53-2.31-1.53-3.68h-3.09v13.19a2.85 2.85 0 1 1-2.02-2.73V9.4a6 6 0 1 0 5.11 5.93V9.53a8.5 8.5 0 0 0 4.53 1.31V7.75c-1.09 0-2.11-.34-2.99-.93z"/></svg>`,
    desc: "Posted on our TikTok account.",
    // TikTok only accepts Square or Landscape 5:4 — no 4:3, no portrait.
    allowedRatios: ["1:1", "5:4"],
  },
  {
    id: "website",
    name: "Website Ad",
    price: 500,
    duration: "7 Days",
    durationDays: 7,
    onSite: true, // the only platform actually rendered inside the on-site popup
    color: "#0a66c2",
    icon: `<svg viewBox="0 0 24 24" fill="white"><path d="M12 2a10 10 0 1 0 0 20 10 10 0 0 0 0-20zm6.93 6h-2.95a15.65 15.65 0 0 0-1.38-3.56A8.03 8.03 0 0 1 18.93 8zM12 4.04c.83 1.2 1.48 2.53 1.91 3.96h-3.82c.43-1.43 1.08-2.76 1.91-3.96zM4.26 14a7.94 7.94 0 0 1 0-4h3.38a16.6 16.6 0 0 0 0 4H4.26zm.81 2h2.95c.35 1.25.8 2.45 1.38 3.56A8.03 8.03 0 0 1 5.07 16zm2.95-8H5.07a8.03 8.03 0 0 1 4.33-3.56A15.65 15.65 0 0 0 8.02 8zM12 19.96a15.6 15.6 0 0 1-1.91-3.96h3.82c-.43 1.43-1.08 2.76-1.91 3.96zM14.4 14H9.6a14.6 14.6 0 0 1 0-4h4.8a14.6 14.6 0 0 1 0 4zm.19 5.56c.58-1.11 1.03-2.31 1.38-3.56h2.95a8.03 8.03 0 0 1-4.33 3.56zM16.36 14a16.6 16.6 0 0 0 0-4h3.38a7.94 7.94 0 0 1 0 4h-3.38z"/></svg>`,
    desc: "Shown as a banner on the website.",
    // Website banner only accepts Square or Landscape 5:4.
    allowedRatios: ["1:1", "5:4"],
  },
];

// Kept only so old code/DB rows referencing "PACKAGES" style objects don't
// break — new logic below uses PLATFORMS directly.
const PACKAGES = PLATFORMS;

// Fallback list — used only if the "payment_methods" D1 table doesn't
// exist yet or ADS_DB isn't bound. Once the table is created and the
// admin panel has saved rows into it, those DB rows take over completely
// and this fallback is never used.
const PAYMENT_METHODS_FALLBACK = [
  { id: "easypaisa", name: "EasyPaisa", account: "0300-0000000 (Account Title)" },
  { id: "jazzcash", name: "JazzCash", account: "0300-0000000 (Account Title)" },
  { id: "bank", name: "Bank Transfer", account: "Bank Name — Account #0000000000" },
];

// Run this once against your D1 database (e.g. via `wrangler d1 execute`)
// so the admin panel has a table to manage payment methods in:
//
//   CREATE TABLE IF NOT EXISTS payment_methods (
//     id TEXT PRIMARY KEY,
//     name TEXT NOT NULL,
//     account TEXT NOT NULL,
//     enabled INTEGER NOT NULL DEFAULT 1,
//     sort_order INTEGER NOT NULL DEFAULT 0
//   );
//
// Then have your admin panel call:
//   GET    /api/ads/payment-methods          (admin) → list all, incl. disabled
//   POST   /api/ads/payment-methods          (admin) → upsert one { id, name, account, enabled, sortOrder }
//   POST   /api/ads/payment-methods/delete   (admin) → delete one { id }
// Whatever the admin marks "enabled" there is exactly what shows up on the
// live /advertise/payment page — nothing else needs to change.

// Returns only the ENABLED payment methods, for the public payment page.
async function getPaymentMethods(env) {
  if (!env.ADS_DB) return PAYMENT_METHODS_FALLBACK;
  try {
    const { results } = await env.ADS_DB
      .prepare("SELECT id, name, account FROM payment_methods WHERE enabled = 1 ORDER BY sort_order ASC, name ASC")
      .all();
    return results && results.length ? results : PAYMENT_METHODS_FALLBACK;
  } catch (e) {
    // Table probably doesn't exist yet — fall back quietly rather than
    // breaking the payment page.
    return PAYMENT_METHODS_FALLBACK;
  }
}

// ─────────────────────────────────────────────────────────────────────────
//  MAIN FETCH HANDLER
// ─────────────────────────────────────────────────────────────────────────
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // ---- API routes -----------------------------------------------------
    if (path.startsWith("/api/advertise/")) {
      return handleApi(request, env, url, path, ctx);
    }
    if (path.startsWith("/api/ads/")) {
      return handleAdsApi(request, env, url, path, ctx);
    }

    // ---- PAGE routes ------------------------------------------------------
    if (path === "/advertise" || path === "/advertise/") {
      return html(pageStart());
    }
    if (path === "/advertise/package") {
      return html(pagePackage(url.searchParams.get("type") || ""));
    }
    if (path === "/advertise/details") {
      return html(pageDetails(url.searchParams.get("type") || "", url.searchParams.get("packages") || ""));
    }
    if (path === "/advertise/payment") {
      return html(await pagePayment(env));
    }
    if (path === "/advertise/thank-you") {
      return html(pageThankYou(url.searchParams.get("ref") || ""));
    }
    if (path === "/advertise/status") {
      return html(pageStatus());
    }

    // Add more routes here as needed:
    // if (path === "/advertise/something-new") { return html(pageSomethingNew()); }

    return new Response("Not found", { status: 404 });
  },
};

// ─────────────────────────────────────────────────────────────────────────
//  API HANDLERS
// ─────────────────────────────────────────────────────────────────────────
async function handleApi(request, env, url, path, ctx) {
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

  // GET /api/advertise/my-ad
  // Requires "Authorization: Bearer <idToken>" from ANY signed-in user
  // (verified server-side — this is what replaces the old, unreliable
  // account-type/cookie check). Returns the caller's own most recent ad
  // request, if any — used to decide whether "Create Now" should go to
  // the status page instead of starting a brand-new campaign.
  if (path === "/api/advertise/my-ad" && request.method === "GET") {
    const payload = await verifyUserToken(request);
    if (!payload) return json({ loggedIn: false, ad: null }, cors, 401);
    if (!env.ADS_DB) return json({ loggedIn: true, ad: null, note: "ADS_DB not bound" }, cors);

    const row = await env.ADS_DB
      .prepare("SELECT * FROM ads WHERE user_id = ? ORDER BY created_at DESC LIMIT 1")
      .bind(payload.sub)
      .first();

    // Total number of ads this user has EVER submitted (any status) — shown
    // on the start page as a small "Ads Created So Far" dashboard stat.
    const countRow = await env.ADS_DB
      .prepare("SELECT COUNT(*) AS total FROM ads WHERE user_id = ?")
      .bind(payload.sub)
      .first();

    // Whether ANY of this user's ads was ever approved/activated by admin
    // (approved_at gets set exactly once, when an ad first goes active —
    // it stays set even if the ad later expires or is deactivated). The
    // "Check My Ad Status" button on the start page only shows once this
    // is true — a merely-submitted, still-pending ad isn't enough.
    const everActiveRow = await env.ADS_DB
      .prepare("SELECT COUNT(*) AS c FROM ads WHERE user_id = ? AND approved_at IS NOT NULL")
      .bind(payload.sub)
      .first();

    return json(
      {
        loggedIn: true,
        ad: row ? jsonRow(row) : null,
        totalCount: countRow ? countRow.total : 0,
        everActive: !!(everActiveRow && everActiveRow.c > 0),
      },
      cors
    );
  }

  // GET /api/advertise/my-ad-image
  // Lets the SIGNED-IN OWNER of an ad view its own creative image — the
  // existing /api/ads/ad-image route is admin-only, so users had no way
  // to see the ad media they uploaded. Ownership is checked against the
  // token's own uid, never a client-supplied one.
  if (path === "/api/advertise/my-ad-image" && request.method === "GET") {
    const payload = await verifyUserToken(request);
    if (!payload) return json({ success: false, error: "Not signed in" }, cors, 401);
    if (!env.ADS_DB || !env.AD_SCREENSHOTS) return json({ success: false, error: "Not configured" }, cors, 500);

    const row = await env.ADS_DB
      .prepare("SELECT ad_image_r2_key FROM ads WHERE user_id = ? ORDER BY created_at DESC LIMIT 1")
      .bind(payload.sub)
      .first();
    if (!row || !row.ad_image_r2_key) return json({ success: false, error: "No ad image" }, cors, 404);

    const obj = await env.AD_SCREENSHOTS.get(row.ad_image_r2_key);
    if (!obj) return json({ success: false, error: "File missing in R2" }, cors, 404);

    return new Response(obj.body, { headers: { ...cors, "Content-Type": obj.httpMetadata?.contentType || "image/jpeg" } });
  }

  // POST /api/advertise/submit
  // Also requires a valid "Authorization: Bearer <idToken>" — the ad is
  // always attributed to whoever the token actually belongs to server-side,
  // never to a client-supplied user id (which could be spoofed).
  if (path === "/api/advertise/submit" && request.method === "POST") {
    try {
      const payload = await verifyUserToken(request);
      if (!payload) return json({ success: false, error: "Not signed in" }, cors, 401);

      const body = await request.json();

      const required = ["accountType", "platformIds", "adTitle", "adDescription", "contactPhone", "paymentMethod", "transactionId", "adImageBase64"];
      for (const field of required) {
        if (!body[field] || (Array.isArray(body[field]) && body[field].length === 0)) {
          return json({ success: false, error: `Missing field: ${field}` }, cors, 400);
        }
      }

      // Same link-free rule as the client-side check on the Ad Details
      // page, enforced again here so it can't be bypassed by calling the
      // API directly.
      const LINK_PATTERN = /https?:\/\/|www\.[a-z0-9-]+\.[a-z]{2,}|\b[a-z0-9-]+\.(com|net|org|pk|io|co|info|biz|xyz)\b/i;
      if (LINK_PATTERN.test(body.adDescription)) {
        return json({ success: false, error: "Ad description cannot contain links or website mentions." }, cors, 400);
      }

      // Look up each selected platform server-side — never trust a
      // client-supplied price/name, only the ids of which platforms were
      // checked. The combo's total price is just the sum of the parts.
      const chosen = body.platformIds.map((id) => PLATFORMS.find((p) => p.id === id)).filter(Boolean);
      if (chosen.length === 0) return json({ success: false, error: "Invalid platform selection" }, cors, 400);

      // "Website Ad" is a clickable on-site banner, so it needs a
      // destination link — enforced again here, same as client-side.
      const requiresLink = chosen.some((p) => p.onSite);
      if (requiresLink && !body.adLink) {
        return json({ success: false, error: "Ad Link is required when Website Ad is selected." }, cors, 400);
      }

      const pkg = {
        id: chosen.map((p) => p.id).join(","),
        name: chosen.map((p) => p.name).join(" + "),
        price: chosen.reduce((sum, p) => sum + p.price, 0),
        // A combo can mix a permanent platform with a timed one (e.g.
        // Facebook [permanent] + WhatsApp [7 days]). We store a single
        // combined expiry: permanent wins if any selected platform is
        // permanent, otherwise the longest of the selected durations.
        durationDays: chosen.some((p) => p.durationDays === null)
          ? null
          : Math.max(...chosen.map((p) => p.durationDays)),
      };

      const ref = "AD-" + Date.now().toString(36).toUpperCase();
      const createdAt = new Date().toISOString();

      // Screenshot goes to R2 — never into the database itself.
      let screenshotKey = null;
      if (body.screenshotBase64 && env.AD_SCREENSHOTS) {
        screenshotKey = `screenshots/${ref}.jpg`;
        const bytes = base64ToBytes(body.screenshotBase64);
        await env.AD_SCREENSHOTS.put(screenshotKey, bytes, {
          httpMetadata: { contentType: "image/jpeg" },
        });
      }

      // The ad's own creative image — its aspect ratio was already checked
      // client-side against the selected platforms' allowed shapes before
      // it ever got here. Stored in the same bucket, separate prefix.
      let adImageKey = null;
      if (body.adImageBase64 && env.AD_SCREENSHOTS) {
        adImageKey = `ad-images/${ref}.jpg`;
        const bytes = base64ToBytes(body.adImageBase64);
        await env.AD_SCREENSHOTS.put(adImageKey, bytes, {
          httpMetadata: { contentType: "image/jpeg" },
        });
      }

      if (!env.ADS_DB) {
        return json({ success: false, error: "ADS_DB not bound" }, cors, 500);
      }

      // NOTE: this needs "user_email" AND "ad_link" columns on the ads
      // table — run these once against your D1 database if you haven't
      // already:
      //   ALTER TABLE ads ADD COLUMN user_email TEXT;
      //   ALTER TABLE ads ADD COLUMN ad_link TEXT;
      await env.ADS_DB.prepare(
        `INSERT INTO ads (ref, user_id, user_email, account_type, package_id, package_name, price, duration_days, ad_title, ad_link, ad_description, requirements, contact_phone, payment_method, transaction_id, screenshot_r2_key, ad_image_r2_key, status, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending_review', ?)`
      )
        .bind(
          ref,
          payload.sub,
          payload.email || "",
          body.accountType,
          pkg.id,
          pkg.name,
          pkg.price,
          pkg.durationDays,
          body.adTitle,
          body.adLink || "",
          body.adDescription,
          body.requirements || "",
          body.contactPhone,
          body.paymentMethod,
          body.transactionId,
          screenshotKey,
          adImageKey,
          createdAt
        )
        .run();

      // Fire the "Pending Review" email to the user — doesn't block the response.
      sendAdEmail(ctx, env, {
        type: "pending",
        to: payload.email,
        ref,
        adTitle: body.adTitle,
        packageName: pkg.name,
        price: pkg.price,
      });

      // Also notify the admin that a new order came in — same call, just
      // a different "type" + recipient, so the email worker builds the
      // admin-facing template instead of the user-facing one. Passing the
      // R2 keys (not the base64 itself) lets the email worker fetch the
      // payment screenshot + ad image straight from R2 and attach them.
      sendAdEmail(ctx, env, {
        type: "admin_notify",
        to: ADMIN_EMAIL,
        ref,
        adTitle: body.adTitle,
        adLink: body.adLink || "",
        packageName: pkg.name,
        price: pkg.price,
        accountType: body.accountType,
        userEmail: payload.email,
        contactPhone: body.contactPhone,
        paymentMethod: body.paymentMethod,
        transactionId: body.transactionId,
        screenshotKey,
        adImageKey,
      });

      // TODO: optionally notify yourself (e.g. Telegram/WhatsApp/Slack webhook)
      // that a new ad request came in, so you can review + activate it.

      return json({ success: true, ref }, cors);
    } catch (e) {
      return json({ success: false, error: e.message }, cors, 500);
    }
  }

  return json({ success: false, error: "Not found" }, cors, 404);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

function jsonRow(row) {
  // Converts a D1 row (snake_case) into the camelCase shape the rest of
  // the code / frontend expects.
  return {
    ref: row.ref,
    userId: row.user_id,
    accountType: row.account_type,
    package: { id: row.package_id, name: row.package_name, price: row.price, durationDays: row.duration_days },
    adTitle: row.ad_title,
    adLink: row.ad_link,
    adDescription: row.ad_description,
    requirements: row.requirements,
    contactPhone: row.contact_phone,
    paymentMethod: row.payment_method,
    transactionId: row.transaction_id,
    screenshotKey: row.screenshot_r2_key,
    adImageKey: row.ad_image_r2_key,
    status: row.status,
    rejectionReason: row.rejection_reason,
    impressions: row.impressions,
    clicks: row.clicks,
    createdAt: row.created_at,
    approvedAt: row.approved_at,
    expiresAt: row.expires_at,
  };
}

// ─────────────────────────────────────────────────────────────────────────
//  ADS-SERVING API — this is the "AdSense-like" part:
//    • only approved, non-expired "website" ads are ever served
//    • ads rotate (a random one is picked each time) instead of always the
//      same ad, so multiple advertisers' slots get fair rotation
//    • impressions/clicks are counted per-ad, same idea as AdSense stats
// ─────────────────────────────────────────────────────────────────────────
async function handleAdsApi(request, env, url, path, ctx) {
  const cors = {
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  };
  if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });

  // GET /api/ads/active?slot=post-popup
  // One SQL query does all the work: only approved, on-site, non-expired
  // website ads are candidates, and D1 itself picks a random one — no
  // need to pull every row back to the Worker and filter in JS.
  if (path === "/api/ads/active" && request.method === "GET") {
    if (!env.ADS_DB) return json({ ad: null, note: "ADS_DB not bound" }, cors);

    const onSiteIds = PLATFORMS.filter((p) => p.onSite).map((p) => p.id);
    if (onSiteIds.length === 0) return json({ ad: null }, cors);

    // package_id can now be a comma-joined combo (e.g. "facebook,website")
    // since one ad request may cover several platforms at once, so we
    // match an on-site id as a whole token inside that list rather than
    // requiring an exact equality match.
    const likeClauses = onSiteIds.map(() => `(',' || package_id || ',') LIKE ?`).join(" OR ");
    const likeParams = onSiteIds.map((id) => `%,${id},%`);
    const stmt = env.ADS_DB.prepare(
      `SELECT ref, ad_title, ad_link, ad_description, contact_phone FROM ads
       WHERE status = 'active'
         AND (${likeClauses})
         AND (expires_at IS NULL OR expires_at > ?)
       ORDER BY RANDOM() LIMIT 1`
    ).bind(...likeParams, new Date().toISOString());

    const row = await stmt.first();
    if (!row) return json({ ad: null }, cors);

    return json(
      { ad: { ref: row.ref, title: row.ad_title, link: row.ad_link, description: row.ad_description, contactPhone: row.contact_phone } },
      cors
    );
  }

  // POST /api/ads/track   body: { ref, type: "impression" | "click" }
  if (path === "/api/ads/track" && request.method === "POST") {
    try {
      const body = await request.json();
      if (!body.ref || !["impression", "click"].includes(body.type)) {
        return json({ success: false, error: "Invalid payload" }, cors, 400);
      }
      if (!env.ADS_DB) return json({ success: false, error: "ADS_DB not bound" }, cors);

      const column = body.type === "impression" ? "impressions" : "clicks";
      const result = await env.ADS_DB.prepare(`UPDATE ads SET ${column} = ${column} + 1 WHERE ref = ?`).bind(body.ref).run();

      if (!result.meta || result.meta.changes === 0) {
        return json({ success: false, error: "Ad not found" }, cors, 404);
      }
      return json({ success: true }, cors);
    } catch (e) {
      return json({ success: false, error: e.message }, cors, 500);
    }
  }

  // ---- Admin-only endpoints (require a valid Firebase ID token for
  //      ADMIN_EMAIL, sent as "Authorization: Bearer <idToken>") ---------
  const isAdmin = !!(await verifyAdminRequest(request));

  // GET /api/ads/list?status=pending_review|active|rejected|all
  if (path === "/api/ads/list" && request.method === "GET") {
    if (!isAdmin) return json({ success: false, error: "Unauthorized" }, cors, 401);
    if (!env.ADS_DB) return json({ success: false, error: "ADS_DB not bound" }, cors);

    const statusFilter = url.searchParams.get("status") || "all";
    const stmt =
      statusFilter === "all"
        ? env.ADS_DB.prepare("SELECT * FROM ads ORDER BY created_at DESC LIMIT 200")
        : env.ADS_DB.prepare("SELECT * FROM ads WHERE status = ? ORDER BY created_at DESC LIMIT 200").bind(statusFilter);

    const { results } = await stmt.all();
    return json({ success: true, ads: results.map(jsonRow) }, cors);
  }

  // GET /api/ads/screenshot?ref=AD-XXXX   (admin only — streams the R2 image)
  if (path === "/api/ads/screenshot" && request.method === "GET") {
    if (!isAdmin) return json({ success: false, error: "Unauthorized" }, cors, 401);
    if (!env.ADS_DB || !env.AD_SCREENSHOTS) return json({ success: false, error: "Not configured" }, cors, 500);

    const ref = url.searchParams.get("ref");
    const row = await env.ADS_DB.prepare("SELECT screenshot_r2_key FROM ads WHERE ref = ?").bind(ref).first();
    if (!row || !row.screenshot_r2_key) return json({ success: false, error: "No screenshot" }, cors, 404);

    const obj = await env.AD_SCREENSHOTS.get(row.screenshot_r2_key);
    if (!obj) return json({ success: false, error: "File missing in R2" }, cors, 404);

    return new Response(obj.body, { headers: { ...cors, "Content-Type": obj.httpMetadata?.contentType || "image/jpeg" } });
  }

  // GET /api/ads/ad-image?ref=AD-XXXX   (admin only — streams the ad's own creative image from R2)
  if (path === "/api/ads/ad-image" && request.method === "GET") {
    if (!isAdmin) return json({ success: false, error: "Unauthorized" }, cors, 401);
    if (!env.ADS_DB || !env.AD_SCREENSHOTS) return json({ success: false, error: "Not configured" }, cors, 500);

    const ref = url.searchParams.get("ref");
    const row = await env.ADS_DB.prepare("SELECT ad_image_r2_key FROM ads WHERE ref = ?").bind(ref).first();
    if (!row || !row.ad_image_r2_key) return json({ success: false, error: "No ad image" }, cors, 404);

    const obj = await env.AD_SCREENSHOTS.get(row.ad_image_r2_key);
    if (!obj) return json({ success: false, error: "File missing in R2" }, cors, 404);

    return new Response(obj.body, { headers: { ...cors, "Content-Type": obj.httpMetadata?.contentType || "image/jpeg" } });
  }

  // POST /api/ads/approve   body: { ref }
  if (path === "/api/ads/approve" && request.method === "POST") {
    if (!isAdmin) return json({ success: false, error: "Unauthorized" }, cors, 401);
    if (!env.ADS_DB) return json({ success: false, error: "ADS_DB not bound" }, cors);

    const body = await request.json();
    const row = await env.ADS_DB.prepare("SELECT duration_days FROM ads WHERE ref = ?").bind(body.ref).first();
    if (!row) return json({ success: false, error: "Ad not found" }, cors, 404);

    // duration_days was already computed correctly from the selected
    // platform combo back at submit time — reuse it rather than trying to
    // look it up again via a single PACKAGES.id match (package_id may now
    // be a comma-joined combo like "facebook,website").
    const approvedAt = new Date().toISOString();
    const expiresAt = row.duration_days ? new Date(Date.now() + row.duration_days * 86400000).toISOString() : null;

    await env.ADS_DB.prepare("UPDATE ads SET status = 'active', approved_at = ?, expires_at = ? WHERE ref = ?")
      .bind(approvedAt, expiresAt, body.ref)
      .run();

    return json({ success: true }, cors);
  }

  // POST /api/ads/reject   body: { ref, reason }
  if (path === "/api/ads/reject" && request.method === "POST") {
    if (!isAdmin) return json({ success: false, error: "Unauthorized" }, cors, 401);
    if (!env.ADS_DB) return json({ success: false, error: "ADS_DB not bound" }, cors);

    const body = await request.json();
    const result = await env.ADS_DB.prepare("UPDATE ads SET status = 'rejected', rejection_reason = ? WHERE ref = ?")
      .bind(body.reason || "", body.ref)
      .run();

    if (!result.meta || result.meta.changes === 0) return json({ success: false, error: "Ad not found" }, cors, 404);
    return json({ success: true }, cors);
  }

  // ---- Payment methods management (admin panel wires up to these) ------

  // GET /api/ads/payment-methods
  // Returns EVERY payment method, including disabled ones, so the admin
  // panel can show a full list with toggles. (The public payment page uses
  // getPaymentMethods() instead, which only returns enabled ones.)
  if (path === "/api/ads/payment-methods" && request.method === "GET") {
    if (!isAdmin) return json({ success: false, error: "Unauthorized" }, cors, 401);
    if (!env.ADS_DB) return json({ success: false, error: "ADS_DB not bound" }, cors);

    try {
      const { results } = await env.ADS_DB
        .prepare("SELECT id, name, account, enabled, sort_order FROM payment_methods ORDER BY sort_order ASC, name ASC")
        .all();
      return json({ success: true, methods: results }, cors);
    } catch (e) {
      return json({ success: false, error: "payment_methods table not found — see the CREATE TABLE comment near PAYMENT_METHODS_FALLBACK" }, cors, 500);
    }
  }

  // POST /api/ads/payment-methods   body: { id, name, account, enabled, sortOrder }
  // Upserts one payment method — used both to add a new one and to edit an
  // existing one (same id = update in place) or flip its enabled state.
  if (path === "/api/ads/payment-methods" && request.method === "POST") {
    if (!isAdmin) return json({ success: false, error: "Unauthorized" }, cors, 401);
    if (!env.ADS_DB) return json({ success: false, error: "ADS_DB not bound" }, cors);

    const body = await request.json();
    if (!body.id || !body.name || !body.account) {
      return json({ success: false, error: "id, name, and account are required" }, cors, 400);
    }

    try {
      await env.ADS_DB.prepare(
        `INSERT INTO payment_methods (id, name, account, enabled, sort_order)
         VALUES (?, ?, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET name = excluded.name, account = excluded.account, enabled = excluded.enabled, sort_order = excluded.sort_order`
      )
        .bind(body.id, body.name, body.account, body.enabled === false ? 0 : 1, body.sortOrder || 0)
        .run();
      return json({ success: true }, cors);
    } catch (e) {
      return json({ success: false, error: e.message }, cors, 500);
    }
  }

  // POST /api/ads/payment-methods/delete   body: { id }
  if (path === "/api/ads/payment-methods/delete" && request.method === "POST") {
    if (!isAdmin) return json({ success: false, error: "Unauthorized" }, cors, 401);
    if (!env.ADS_DB) return json({ success: false, error: "ADS_DB not bound" }, cors);

    const body = await request.json();
    if (!body.id) return json({ success: false, error: "id is required" }, cors, 400);

    const result = await env.ADS_DB.prepare("DELETE FROM payment_methods WHERE id = ?").bind(body.id).run();
    if (!result.meta || result.meta.changes === 0) return json({ success: false, error: "Payment method not found" }, cors, 404);
    return json({ success: true }, cors);
  }

  return json({ success: false, error: "Not found" }, cors, 404);
}

// Fires a status email off to the separate Email Worker (Resend) —
// never blocks or fails the actual API response. If EMAIL_WORKER_URL
// hasn't been set yet, there's no recipient email, or EMAIL_SECRET isn't
// configured, it silently does nothing.
function sendAdEmail(ctx, env, data) {
  if (!data.to || !EMAIL_WORKER_URL || EMAIL_WORKER_URL.includes("REPLACE") || !env.EMAIL_SECRET) return;
  const task = fetch(EMAIL_WORKER_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Email-Secret": env.EMAIL_SECRET },
    body: JSON.stringify(data),
  }).catch(() => {});
  if (ctx && ctx.waitUntil) ctx.waitUntil(task);
}

function json(data, headers, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { ...headers, "Content-Type": "application/json" },
  });
}

function html(body) {
  return new Response(body, { headers: { "Content-Type": "text/html; charset=UTF-8" } });
}

// ─────────────────────────────────────────────────────────────────────────
//  SHARED LAYOUT (simple, professional, matches site's brand color)
// ─────────────────────────────────────────────────────────────────────────
function layout({ title, step = null, content, extraScript = "", moduleScript = "", headerExtra = "" }) {
  const steps = ["Start", "Package", "Ad Details", "Payment"];
  const stepper = step
    ? `<div class="stepper">
        ${steps
          .map((s, i) => {
            const n = i + 1;
            const state = n < step ? "done" : n === step ? "active" : "";
            return `<div class="step ${state}"><span class="step-num">${n}</span><span class="step-label">${s}</span></div>`;
          })
          .join('<div class="step-line"></div>')}
      </div>`
    : "";

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${title} | ${SITE_NAME}</title>
<style>
  :root{ --brand:${BRAND_COLOR}; }
  *{box-sizing:border-box;}
  body{margin:0;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Arial,sans-serif;background:#f5f6f7;color:#0f172a;}
  header{background:#fff;border-bottom:1px solid #e2e8f0;padding:14px 20px;display:flex;align-items:center;gap:12px;}
  header img{height:26px;}
  header .header-spacer{flex:1;}
  header .back-btn{width:30px;height:30px;min-width:30px;border:1px solid #e2e8f0;background:#fff;border-radius:50%;display:flex;align-items:center;justify-content:center;cursor:pointer;padding:0;color:#334155;}
  header .back-btn:hover{border-color:var(--brand);color:var(--brand);}
  header .back-btn svg{width:15px;height:15px;}
  header .header-status{font-size:11px;font-weight:800;padding:4px 10px;text-transform:uppercase;letter-spacing:0.4px;text-decoration:none;cursor:pointer;}
  main{max-width:640px;margin:0 auto;padding:24px 16px 60px;}
  .card{background:#fff;border:1px solid #e2e8f0;border-radius:0;padding:24px 20px;}
  h1{font-size:20px;margin:0 0 6px;}
  h2{font-size:16px;margin:0 0 14px;}
  p.sub{color:#64748b;font-size:14px;margin:0 0 20px;}
  .btn{display:inline-block;width:100%;text-align:center;background:var(--brand);color:#fff;border:none;padding:13px 16px;font-size:15px;font-weight:700;cursor:pointer;border-radius:0;letter-spacing:0.2px;text-decoration:none;}
  .btn:hover{background:#08508f;}
  .btn:disabled{opacity:0.6;cursor:not-allowed;}
  .btn-outline{background:#fff;color:var(--brand);border:1px solid var(--brand);}
  .btn-outline:hover{background:#f0f7ff;}
  label{display:block;font-size:13px;font-weight:700;color:#334155;margin:16px 0 6px;}
  input[type=text],input[type=tel],textarea,select{width:100%;padding:11px 12px;border:1px solid #cbd5e1;border-radius:0;font-size:14px;font-family:inherit;}
  textarea{min-height:90px;resize:vertical;}
  input[type=file]{width:100%;font-size:13px;}
  .pkg{border:1px solid #e2e8f0;padding:16px;margin-bottom:10px;cursor:pointer;display:flex;justify-content:space-between;align-items:center;gap:12px;}
  .pkg:hover{border-color:var(--brand);}
  .pkg.selected{border-color:var(--brand);background:#f0f7ff;}
  .pkg-name{font-weight:700;font-size:14px;}
  .pkg-desc{font-size:12px;color:#64748b;margin-top:3px;}
  .pkg-duration{font-size:11px;color:#16a34a;font-weight:700;margin-top:4px;}
  .pkg-price{font-weight:800;color:var(--brand);font-size:15px;white-space:nowrap;}
  .summary{border:1px solid #e2e8f0;background:#f8fafc;padding:14px 16px;margin:18px 0;font-size:13px;}
  .summary-row{display:flex;justify-content:space-between;padding:4px 0;}
  .summary-row.total{border-top:1px solid #e2e8f0;margin-top:6px;padding-top:8px;font-weight:800;color:var(--brand);}
  .presets{display:flex;flex-wrap:wrap;gap:8px;margin:14px 0 22px;}
  .preset-chip{border:1px solid #cbd5e1;background:#fff;color:#334155;font-size:12px;font-weight:700;padding:8px 12px;cursor:pointer;border-radius:999px;transition:border-color .15s,color .15s,background .15s;}
  .preset-chip:hover{border-color:var(--brand);color:var(--brand);}
  .preset-chip.active{background:var(--brand);border-color:var(--brand);color:#fff;}
  .platform{border:1px solid #e2e8f0;padding:14px 16px;margin-bottom:10px;display:flex;align-items:center;gap:14px;cursor:pointer;transition:border-color .15s,background .15s;}
  .platform:hover{border-color:var(--brand);}
  .platform.checked{border-color:var(--brand);background:#f0f7ff;}
  .platform-icon{width:42px;height:42px;min-width:42px;border-radius:12px;display:flex;align-items:center;justify-content:center;}
  .platform-icon svg{width:22px;height:22px;}
  .platform-body{flex:1;min-width:0;}
  .platform-name{font-weight:700;font-size:14px;}
  .platform-desc{font-size:12px;color:#64748b;margin-top:2px;}
  .platform-duration{font-size:11px;color:#16a34a;font-weight:700;margin-top:4px;}
  .platform-price{font-weight:800;color:var(--brand);font-size:15px;white-space:nowrap;}
  .platform-check{width:20px;height:20px;min-width:20px;border:2px solid #cbd5e1;border-radius:5px;display:flex;align-items:center;justify-content:center;transition:border-color .15s,background .15s;}
  .platform.checked .platform-check{background:var(--brand);border-color:var(--brand);}
  .platform-check svg{width:12px;height:12px;display:none;}
  .platform.checked .platform-check svg{display:block;}
  .total-bar{position:sticky;bottom:0;background:#fff;border-top:1px solid #e2e8f0;margin:20px -20px -24px;padding:16px 20px;}
  .total-bar-row{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:12px;}
  .total-bar-label{font-size:13px;color:#64748b;font-weight:700;}
  .total-bar-amount{font-size:22px;font-weight:800;color:var(--brand);}
  .stepper{display:flex;align-items:center;margin-bottom:22px;}
  .step{display:flex;flex-direction:column;align-items:center;gap:4px;font-size:11px;color:#94a3b8;}
  .step-num{width:24px;height:24px;border-radius:50%;background:#e2e8f0;color:#64748b;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:12px;}
  .step.active .step-num{background:var(--brand);color:#fff;}
  .step.done .step-num{background:#16a34a;color:#fff;}
  .step.active .step-label{color:var(--brand);font-weight:700;}
  .step-line{flex:1;height:1px;background:#e2e8f0;margin:0 4px 16px;}
  .type-choice{display:flex;gap:12px;margin-top:18px;}
  .type-btn{flex:1;border:1px solid #cbd5e1;padding:20px 12px;text-align:center;cursor:pointer;font-weight:700;font-size:14px;}
  .type-btn:hover{border-color:var(--brand);color:var(--brand);}
  .error-msg{background:#fff0f0;border:1px solid #fecaca;color:#ef4444;padding:10px 12px;font-size:13px;margin:14px 0;display:none;}
  .req-box{border:1px solid #e2e8f0;background:#f8fafc;margin:18px 0;}
  .req-toggle{width:100%;display:flex;justify-content:space-between;align-items:center;gap:10px;background:none;border:none;padding:13px 14px;font-size:13px;font-weight:700;color:#0f172a;cursor:pointer;text-align:left;}
  .req-toggle svg{width:16px;height:16px;color:#64748b;transition:transform .15s;flex-shrink:0;}
  .req-box.open .req-toggle svg{transform:rotate(180deg);}
  .req-body{max-height:0;overflow:hidden;transition:max-height .2s ease;}
  .req-box.open .req-body{max-height:400px;}
  .req-body ul{margin:0;padding:0 16px 14px 30px;font-size:13px;color:#334155;line-height:1.6;}
  .req-body li{margin-bottom:8px;}
  .pay-method{border:1px solid #e2e8f0;padding:12px 14px;margin-bottom:8px;cursor:pointer;font-size:13px;font-weight:600;display:flex;justify-content:space-between;}
  .pay-method.selected{border-color:var(--brand);background:#f0f7ff;}
  .pay-account{display:none;background:#f8fafc;border:1px solid #e2e8f0;padding:10px 12px;font-size:12px;color:#334155;margin:-4px 0 8px;}
  .pay-account.show{display:block;}
  .status-badge{display:inline-block;font-size:12px;font-weight:800;padding:5px 12px;text-transform:uppercase;letter-spacing:0.5px;margin-bottom:16px;}
  .status-pending_review{background:#fef9c3;color:#854d0e;}
  .status-active{background:#dcfce7;color:#166534;}
  .status-rejected{background:#fee2e2;color:#991b1b;}
  .status-expired{background:#e2e8f0;color:#475569;}
  .days-left{font-size:34px;font-weight:800;color:var(--brand);margin:6px 0;}
  .days-left-label{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.4px;}
  .dash-stats{border:1px solid #e2e8f0;background:#f8fafc;padding:18px 16px;margin:18px 0;text-align:center;}
  .dash-stat-number{font-size:34px;font-weight:800;color:var(--brand);}
  .dash-stat-label{font-size:12px;color:#64748b;text-transform:uppercase;letter-spacing:0.4px;margin-top:4px;}
  footer{display:block;background:#fff;color:#334155;margin-top:40px;border-top:1px solid #e2e8f0;}
  .footer-inner{max-width:960px;margin:0 auto;padding:40px 20px 24px;display:grid;grid-template-columns:1.4fr 1fr 1fr;gap:32px;}
  .footer-col h4{color:#0f172a;font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:0.5px;margin:0 0 14px;}
  .footer-col p{font-size:13px;line-height:1.7;color:#64748b;margin:0;}
  .footer-col ul{list-style:none;margin:0;padding:0;}
  .footer-col li{margin-bottom:9px;}
  .footer-col a{color:#64748b;font-size:13px;text-decoration:none;}
  .footer-col a:hover{color:var(--brand);}
  .footer-brand{display:flex;align-items:center;gap:8px;margin-bottom:12px;}
  .footer-brand img{height:24px;}
  .footer-brand span{color:#0f172a;font-weight:800;font-size:15px;}
  .footer-social{display:flex;gap:10px;margin-top:16px;}
  .footer-social a{width:32px;height:32px;border-radius:50%;background:#f1f5f9;display:flex;align-items:center;justify-content:center;}
  .footer-social a:hover{background:var(--brand);}
  .footer-social a:hover svg{fill:#fff;}
  .footer-social svg{width:15px;height:15px;fill:#64748b;}
  .footer-bottom{border-top:1px solid #e2e8f0;padding:16px 20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;max-width:960px;margin:0 auto;}
  .footer-bottom p{margin:0;font-size:12px;color:#94a3b8;}
  .footer-bottom-links{display:flex;gap:16px;}
  .footer-bottom-links a{font-size:12px;color:#94a3b8;text-decoration:none;}
  .footer-bottom-links a:hover{color:var(--brand);}
  @media(max-width:640px){ .footer-inner{grid-template-columns:1fr;gap:26px;} .footer-bottom{flex-direction:column;text-align:center;} }
</style>
</head>
<body>
<header>
  <button class="back-btn" onclick="history.back()" aria-label="Go back">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="15 18 9 12 15 6"></polyline></svg>
  </button>
  <img src="${LOGO_URL}" alt="${SITE_NAME}">
  <div class="header-spacer"></div>
  ${headerExtra}
</header>
<main>
  ${stepper}
  <div class="card">
    ${content}
  </div>
</main>
<footer>
  <div class="footer-inner">
    <div class="footer-col">
      <div class="footer-brand">
        <img src="${LOGO_URL}" alt="${SITE_NAME}">
        <span>${SITE_NAME}</span>
      </div>
      <p>Connecting healthcare facilities with qualified professionals — find your next job or your next hire, all in one place.</p>
      <div class="footer-social">
        <a href="${FACEBOOK_URL}" target="_blank" rel="noopener" aria-label="Facebook"><svg viewBox="0 0 24 24"><path d="M22 12.06C22 6.51 17.52 2 12 2S2 6.51 2 12.06c0 5.02 3.66 9.18 8.44 9.94v-7.03H7.9v-2.91h2.54V9.85c0-2.51 1.49-3.9 3.77-3.9 1.09 0 2.24.2 2.24.2v2.46h-1.26c-1.24 0-1.63.77-1.63 1.56v1.89h2.78l-.44 2.91h-2.34V22c4.78-.76 8.44-4.92 8.44-9.94z"/></svg></a>
        <a href="${WHATSAPP_CHANNEL_URL}" target="_blank" rel="noopener" aria-label="WhatsApp Channel"><svg viewBox="0 0 24 24"><path d="M12.04 2C6.58 2 2.13 6.45 2.13 11.91c0 1.75.46 3.45 1.32 4.95L2.05 22l5.25-1.38a9.9 9.9 0 0 0 4.74 1.21h.01c5.46 0 9.91-4.45 9.91-9.91C21.96 6.45 17.5 2 12.04 2z"/></svg></a>
        <a href="${TIKTOK_URL}" target="_blank" rel="noopener" aria-label="TikTok"><svg viewBox="0 0 24 24"><path d="M16.6 5.82c-.99-.99-1.53-2.31-1.53-3.68h-3.09v13.19a2.85 2.85 0 1 1-2.02-2.73V9.4a6 6 0 1 0 5.11 5.93V9.53a8.5 8.5 0 0 0 4.53 1.31V7.75c-1.09 0-2.11-.34-2.99-.93z"/></svg></a>
      </div>
    </div>
    <div class="footer-col">
      <h4>Quick Links</h4>
      <ul>
        <li><a href="${SITE_URL}">Home</a></li>
        <li><a href="${SITE_URL}/jobs">Browse Jobs</a></li>
        <li><a href="/advertise">Advertise With Us</a></li>
        <li><a href="/advertise/status">My Ad Status</a></li>
      </ul>
    </div>
    <div class="footer-col">
      <h4>Contact</h4>
      <ul>
        <li><a href="mailto:${CONTACT_EMAIL}">${CONTACT_EMAIL}</a></li>
        <li><a href="tel:${CONTACT_PHONE.replace(/-/g, '')}">${CONTACT_PHONE}</a></li>
      </ul>
    </div>
  </div>
  <div class="footer-bottom">
    <p>© ${new Date().getFullYear()} ${SITE_NAME}. All rights reserved. <span style="color:#cbd5e1;">·</span> Powered by SufianX</p>
    <div class="footer-bottom-links">
      <a href="${SITE_URL}/privacy">Privacy Policy</a>
      <a href="${SITE_URL}/terms">Terms of Service</a>
    </div>
  </div>
</footer>
<script>${extraScript}</script>
${moduleScript ? `<script type="module">${moduleScript}</script>` : ""}
</body>
</html>`;
}

// ─────────────────────────────────────────────────────────────────────────
//  FIREBASE CLIENT SETUP — shared by any page here that needs to know who
//  is signed in (Start, Payment, Status). Same project as the rest of the
//  site, so an already-logged-in visitor is recognized immediately with no
//  extra login step.
// ─────────────────────────────────────────────────────────────────────────
const FIREBASE_CLIENT_INIT = `
import { initializeApp, getApps, getApp } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-app.js";
import { getAuth, onAuthStateChanged } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-auth.js";
import { getFirestore, doc, getDoc } from "https://www.gstatic.com/firebasejs/10.8.0/firebase-firestore.js";

const firebaseConfig = {
  apiKey: "AIzaSyD4Cfni7D2Kk_t6qeZ4jcWesIabnSM15mk",
  authDomain: "jobs-45cc9.firebaseapp.com",
  projectId: "jobs-45cc9",
  storageBucket: "jobs-45cc9.firebasestorage.app",
  messagingSenderId: "21065686301",
  appId: "1:21065686301:web:f461ea1b8aabe2fa5895f4"
};
const fireApp = getApps().length === 0 ? initializeApp(firebaseConfig) : getApp();
const auth = getAuth(fireApp);
const db = getFirestore(fireApp);

// Resolves once with the current user (or null) — every page below awaits
// this instead of guessing whether Firebase has finished loading yet.
window.__authReady = new Promise(function(resolve){
  onAuthStateChanged(auth, function(user){ resolve(user); });
});

// TODO: confirm this matches your real schema. Right now it guesses
// "employer" when the users/{uid} Firestore doc has a facilityName field
// (as seen elsewhere on the site) and "candidate" otherwise. If you store
// an explicit role/accountType field instead, swap this for that.
window.__getAccountType = async function(uid){
  try {
    const snap = await getDoc(doc(db, "users", uid));
    if (snap.exists() && snap.data().facilityName) return "employer";
  } catch(e) {}
  return "candidate";
};
`;

// ─────────────────────────────────────────────────────────────────────────
//  PAGE 1 — START
// ─────────────────────────────────────────────────────────────────────────
function pageStart() {
  const content = `
    <h1>Advertise With Us</h1>
    <p class="sub">Promote your medical facility, service, or brand to thousands of healthcare job seekers and employers.</p>

    <div class="dash-stats" id="dashStats" style="display:none;">
      <div class="dash-stat-number" id="adsCountNum">0</div>
      <div class="dash-stat-label">Ad<span id="adsCountPlural"></span> Created So Far</div>
    </div>

    <div class="error-msg" id="err">Please log in to your account before creating an ad.</div>
    <button class="btn" id="createNowBtn" disabled>Loading...</button>
    <button class="btn btn-outline" id="checkStatusBtn" style="display:none;margin-top:10px;" onclick="window.location.href='/advertise/status'">Check My Ad Status</button>
  `;
  const moduleScript = `
    ${FIREBASE_CLIENT_INIT}

    const btn = document.getElementById('createNowBtn');
    const err = document.getElementById('err');
    const dashStats = document.getElementById('dashStats');
    const adsCountNum = document.getElementById('adsCountNum');
    const adsCountPlural = document.getElementById('adsCountPlural');
    const checkStatusBtn = document.getElementById('checkStatusBtn');

    window.__authReady.then(async function(user){
      btn.disabled = false;
      btn.textContent = 'Create Now';
      if(!user) return;

      // Quietly check for an existing ad + total ad count — used to show
      // the "Ads Created So Far" dashboard stat and the "Check My Ad
      // Status" button (shows as soon as the user has submitted an ad —
      // doesn't need to have gone active yet). Doesn't block Create Now.
      try {
        const idToken = await user.getIdToken();
        const res = await fetch('/api/advertise/my-ad', { headers: { 'Authorization': 'Bearer ' + idToken } });
        const data = await res.json();

        if(data.totalCount > 0){
          adsCountNum.textContent = data.totalCount;
          adsCountPlural.textContent = data.totalCount === 1 ? '' : 's';
          dashStats.style.display = 'block';
        }

        if(data.ad){
          checkStatusBtn.style.display = 'block';
        }
      } catch(e) {}
    });

    btn.addEventListener('click', async function(){
      err.style.display = 'none';
      btn.disabled = true;
      btn.textContent = 'Checking your account...';

      const user = await window.__authReady;
      if (!user) {
        btn.disabled = false;
        btn.textContent = 'Create Now';
        err.style.display = 'block';
        setTimeout(function(){
          window.location.href = '/login.html?redirect=' + encodeURIComponent(window.location.pathname);
        }, 1200);
        return;
      }

      try {
        const idToken = await user.getIdToken();
        const res = await fetch('/api/advertise/my-ad', { headers: { 'Authorization': 'Bearer ' + idToken } });
        const data = await res.json();

        if (data.ad) {
          // Already has an ad on file — go straight to its status instead
          // of starting a brand-new campaign.
          window.location.href = '/advertise/status';
          return;
        }

        const accountType = await window.__getAccountType(user.uid);
        window.location.href = '/advertise/package?type=' + encodeURIComponent(accountType);
      } catch (e) {
        btn.disabled = false;
        btn.textContent = 'Create Now';
        err.textContent = 'Something went wrong. Please try again.';
        err.style.display = 'block';
      }
    });
  `;
  return layout({ title: "Advertise With Us", step: 1, content, moduleScript });
}

// ─────────────────────────────────────────────────────────────────────────
//  PAGE 2 — PACKAGE SELECTION
// ─────────────────────────────────────────────────────────────────────────
// Quick-pick combos — just a shortcut that ticks the matching checkboxes.
// The price is always calculated live as a simple sum of whichever
// platforms are checked, so these never go stale even if PLATFORMS prices
// change later.
const PRESET_COMBOS = [
  { label: "WhatsApp Only", ids: ["whatsapp"] },
  { label: "Facebook + WhatsApp", ids: ["facebook", "whatsapp"] },
  { label: "TikTok + WhatsApp", ids: ["tiktok", "whatsapp"] },
  { label: "TikTok + Facebook", ids: ["tiktok", "facebook"] },
  { label: "Website Only", ids: ["website"] },
  { label: "All Platforms", ids: PLATFORMS.map((p) => p.id) },
];

function pagePackage(type) {
  const checkIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="#fff" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>`;

  const rows = PLATFORMS.map(
    (p) => `
    <div class="platform" data-id="${p.id}" data-price="${p.price}" onclick="togglePlatform('${p.id}')">
      <div class="platform-icon" style="background:${p.color};">${p.icon}</div>
      <div class="platform-body">
        <div class="platform-name">${p.name}</div>
        <div class="platform-desc">${p.desc}</div>
        <div class="platform-duration">${p.duration}</div>
      </div>
      <div class="platform-price">Rs. ${p.price}</div>
      <div class="platform-check">${checkIcon}</div>
    </div>`
  ).join("");

  const chips = PRESET_COMBOS.map(
    (c, i) => `<div class="preset-chip" data-ids="${c.ids.join(",")}" onclick="applyPreset(${i})">${c.label}</div>`
  ).join("");

  const content = `
    <h1>Choose Where To Advertise</h1>
    <p class="sub">Account type: <strong>${type || "Unknown"}</strong> — tick one or more platforms, or start from a quick combo below.</p>

    <div class="presets">${chips}</div>

    ${rows}

    <div class="total-bar">
      <div class="total-bar-row">
        <span class="total-bar-label">Total</span>
        <span class="total-bar-amount" id="totalAmount">Rs. 0</span>
      </div>
      <button class="btn" id="continueBtn" disabled onclick="goNext()">Continue</button>
    </div>
  `;
  const script = `
    var accountType = ${JSON.stringify(type)};
    var PRESETS = ${JSON.stringify(PRESET_COMBOS)};
    var selected = {};

    function updateTotal(){
      var total = 0;
      document.querySelectorAll('.platform').forEach(function(el){
        var id = el.getAttribute('data-id');
        var isChecked = !!selected[id];
        el.classList.toggle('checked', isChecked);
        if(isChecked) total += Number(el.getAttribute('data-price'));
      });
      document.getElementById('totalAmount').textContent = 'Rs. ' + total;
      document.getElementById('continueBtn').disabled = total === 0;

      // Highlight a preset chip only if the current selection matches it exactly.
      var selectedIds = Object.keys(selected).filter(function(id){ return selected[id]; }).sort().join(',');
      document.querySelectorAll('.preset-chip').forEach(function(chip){
        var chipIds = chip.getAttribute('data-ids').split(',').sort().join(',');
        chip.classList.toggle('active', chipIds === selectedIds);
      });
    }

    function togglePlatform(id){
      selected[id] = !selected[id];
      updateTotal();
    }

    function applyPreset(i){
      var preset = PRESETS[i];
      selected = {};
      preset.ids.forEach(function(id){ selected[id] = true; });
      updateTotal();
    }

    function goNext(){
      var ids = Object.keys(selected).filter(function(id){ return selected[id]; });
      if(ids.length === 0) return;
      window.location.href = '/advertise/details?type=' + encodeURIComponent(accountType) + '&packages=' + encodeURIComponent(ids.join(','));
    }

    updateTotal();
  `;
  return layout({ title: "Choose a Package", step: 2, content, extraScript: script });
}

// ─────────────────────────────────────────────────────────────────────────
//  PAGE 3 — AD DETAILS
// ─────────────────────────────────────────────────────────────────────────
function pageDetails(type, packagesParam) {
  const platformIds = (packagesParam || "").split(",").filter(Boolean);
  const chosen = PLATFORMS.filter((p) => platformIds.includes(p.id));
  const total = chosen.reduce((sum, p) => sum + p.price, 0);

  const rows = chosen
    .map((p) => `<div class="summary-row"><span>${p.name} (${p.duration})</span><span>Rs. ${p.price}</span></div>`)
    .join("");
  const summaryBody = chosen.length
    ? `${rows}<div class="summary-row total"><span>Total</span><span>Rs. ${total}</span></div>`
    : `<div class="summary-row"><span>No platform selected</span><span></span></div>`;

  // If the user picked any on-site platform (currently just "Website
  // Ad"), we need a destination link — the banner has to click through
  // to somewhere. Social platforms (WhatsApp/Facebook/TikTok) don't need
  // this since they're just posted content, not a clickable banner.
  const hasOnSite = chosen.some((p) => p.onSite);

  // The ad image has to work across EVERY selected platform at once (it's
  // one image, posted everywhere) — so the accepted shapes are whichever
  // ratios ALL chosen platforms have in common, not the union of all of
  // them. E.g. TikTok + Facebook → only Square/5:4 survive, since TikTok
  // doesn't accept 4:3 or Portrait even though Facebook does.
  const allowedRatioIds = chosen.length
    ? ASPECT_RATIOS.map((r) => r.id).filter((id) => chosen.every((p) => p.allowedRatios.includes(id)))
    : ASPECT_RATIOS.map((r) => r.id);
  const allowedRatios = ASPECT_RATIOS.filter((r) => allowedRatioIds.includes(r.id));
  const ratioLabels = allowedRatios.map((r) => r.label).join(", ");

  const content = `
    <h1>Ad Details</h1>
    <p class="sub">Tell us what you'd like your ad to say.</p>

    <div class="summary">${summaryBody}</div>

    <div class="req-box open">
      <button type="button" class="req-toggle" onclick="this.parentElement.classList.toggle('open')">
        <span>Ad Requirements — please read</span>
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"></polyline></svg>
      </button>
      <div class="req-body">
        <ul>
          <li>Your ad description must not contain any links, website addresses, or phrases like "visit our website" or "visit our page" — plain text only.</li>
          <li>You're welcome to include text directly on the ad image itself (e.g. your clinic name, offer, or number).</li>
          <li>Your ad image must be one of these accepted sizes, based on the platforms you selected: <strong>${ratioLabels}</strong>.</li>
        </ul>
      </div>
    </div>

    <label>Ad Title</label>
    <input type="text" id="adTitle" placeholder="e.g. Eden Diagnostic Lab — Now Open">

    ${
      hasOnSite
        ? `<label>Ad Link <span style="font-weight:400;color:#94a3b8;">— where the website banner should open when clicked</span></label>
    <input type="text" id="adLink" placeholder="https://your-page.com or https://wa.me/92...">
    <div class="error-msg" id="linkFieldErr">Please enter a valid link for your website banner.</div>`
        : ""
    }

    <label>Ad Description</label>
    <textarea id="adDescription" placeholder="Describe what you want to advertise... (no links)"></textarea>
    <div class="error-msg" id="linkErr">Please remove any links or website mentions from the description.</div>

    <label>Ad Image <span style="font-weight:400;color:#94a3b8;">— accepted: ${ratioLabels}</span></label>
    <input type="file" id="adImage" accept="image/*">
    <div class="error-msg" id="ratioErr">That image doesn't match an accepted size (${ratioLabels}). Please choose a different image.</div>
    <div id="imagePreviewWrap" style="display:none;margin-top:10px;">
      <img id="imagePreview" style="max-width:160px;border:1px solid #e2e8f0;display:block;">
      <div id="imagePreviewLabel" style="font-size:11px;color:#16a34a;font-weight:700;margin-top:6px;"></div>
    </div>

    <label>Any Special Requirements (optional)</label>
    <textarea id="requirements" placeholder="e.g. specific timing, colors to use..."></textarea>

    <label>Contact Phone / WhatsApp Number</label>
    <input type="tel" id="contactPhone" placeholder="03XXXXXXXXX">

    <div class="error-msg" id="err">Please fill in all required fields correctly.</div>
    <button class="btn" style="margin-top:16px;" onclick="goNext()">Continue to Payment</button>
  `;
  const script = `
    var accountType = ${JSON.stringify(type)};
    var platformIds = ${JSON.stringify(platformIds)};
    var ALLOWED_RATIOS = ${JSON.stringify(allowedRatios)};
    var hasOnSite = ${JSON.stringify(hasOnSite)};
    var adImageBase64 = null;
    var adImageValid = false;
    var LINK_PATTERN = /https?:\\/\\/|www\\.[a-z0-9-]+\\.[a-z]{2,}|\\b[a-z0-9-]+\\.(com|net|org|pk|io|co|info|biz|xyz)\\b/i;

    function fileToBase64(file){
      return new Promise(function(resolve, reject){
        var reader = new FileReader();
        reader.onload = function(){ resolve(reader.result); };
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
    }

    document.getElementById('adDescription').addEventListener('input', function(){
      document.getElementById('linkErr').style.display = LINK_PATTERN.test(this.value) ? 'block' : 'none';
    });

    document.getElementById('adImage').addEventListener('change', async function(){
      var file = this.files[0];
      var ratioErr = document.getElementById('ratioErr');
      var wrap = document.getElementById('imagePreviewWrap');
      adImageValid = false;
      adImageBase64 = null;
      ratioErr.style.display = 'none';
      wrap.style.display = 'none';
      if(!file) return;

      var dataUrl = await fileToBase64(file);
      var img = new Image();
      img.onload = function(){
        var actual = img.naturalWidth / img.naturalHeight;
        var match = ALLOWED_RATIOS.find(function(r){ return Math.abs(actual - r.ratio) < 0.04; });
        if(!match){
          ratioErr.style.display = 'block';
          return;
        }
        adImageValid = true;
        adImageBase64 = dataUrl.split(',')[1]; // strip the "data:image/...;base64," prefix
        document.getElementById('imagePreview').src = dataUrl;
        document.getElementById('imagePreviewLabel').textContent = 'Matches: ' + match.label;
        wrap.style.display = 'block';
      };
      img.onerror = function(){ ratioErr.style.display = 'block'; };
      img.src = dataUrl;
    });

    function goNext(){
      var adTitle = document.getElementById('adTitle').value.trim();
      var adLinkEl = document.getElementById('adLink');
      var adLink = adLinkEl ? adLinkEl.value.trim() : '';
      var adDescription = document.getElementById('adDescription').value.trim();
      var requirements = document.getElementById('requirements').value.trim();
      var contactPhone = document.getElementById('contactPhone').value.trim();
      var err = document.getElementById('err');
      var hasLink = LINK_PATTERN.test(adDescription);
      document.getElementById('linkErr').style.display = hasLink ? 'block' : 'none';

      var linkFieldErr = document.getElementById('linkFieldErr');
      var linkFieldInvalid = hasOnSite && !adLink;
      if(linkFieldErr) linkFieldErr.style.display = linkFieldInvalid ? 'block' : 'none';

      if(!adTitle || !adDescription || !contactPhone || platformIds.length === 0 || hasLink || !adImageValid || linkFieldInvalid){
        err.style.display = 'block';
        return;
      }
      err.style.display = 'none';
      var data = { accountType: accountType, platformIds: platformIds, adTitle: adTitle, adLink: adLink, adDescription: adDescription, requirements: requirements, contactPhone: contactPhone, adImageBase64: adImageBase64 };
      sessionStorage.setItem('advertiseForm', JSON.stringify(data));
      window.location.href = '/advertise/payment';
    }
  `;
  return layout({ title: "Ad Details", step: 3, content, extraScript: script });
}

// ─────────────────────────────────────────────────────────────────────────
//  PAGE 4 — PAYMENT
// ─────────────────────────────────────────────────────────────────────────
async function pagePayment(env) {
  const paymentMethods = await getPaymentMethods(env);

  const methods = paymentMethods.length
    ? paymentMethods
        .map(
          (m) => `
    <div class="pay-method" data-id="${m.id}">
      <span>${m.name}</span><span>➜</span>
    </div>
    <div class="pay-account" id="acc-${m.id}">Send payment to: <strong>${m.account}</strong></div>`
        )
        .join("")
    : `<p class="sub">No payment methods are currently available. Please check back shortly.</p>`;

  const content = `
    <h1>Payment</h1>
    <div class="summary" id="orderSummary"></div>

    <h2 style="margin-top:20px;">Select Payment Method</h2>
    ${methods}

    <label>Transaction ID</label>
    <input type="text" id="transactionId" placeholder="Enter your transaction ID">

    <label>Payment Screenshot</label>
    <input type="file" id="screenshot" accept="image/*">

    <div class="error-msg" id="err">Please complete all payment fields.</div>
    <button class="btn" style="margin-top:16px;" id="submitBtn">Submit</button>
  `;

  const platformsJson = JSON.stringify(PLATFORMS);

  const moduleScript = `
    ${FIREBASE_CLIENT_INIT}

    var PLATFORMS = ${platformsJson};
    var formData = JSON.parse(sessionStorage.getItem('advertiseForm') || 'null');
    var selectedMethod = null;

    if(!formData || !formData.platformIds || !formData.platformIds.length){
      window.location.href = '/advertise';
    } else {
      var chosen = PLATFORMS.filter(function(p){ return formData.platformIds.indexOf(p.id) !== -1; });
      var total = chosen.reduce(function(sum, p){ return sum + p.price; }, 0);
      var rows = '<div class="summary-row"><span>Ad Title</span><span>' + formData.adTitle + '</span></div>';
      chosen.forEach(function(p){
        rows += '<div class="summary-row"><span>' + p.name + ' (' + p.duration + ')</span><span>Rs. ' + p.price + '</span></div>';
      });
      rows += '<div class="summary-row total"><span>Total</span><span>Rs. ' + total + '</span></div>';
      document.getElementById('orderSummary').innerHTML = rows;
    }

    document.querySelectorAll('.pay-method').forEach(function(el){
      el.addEventListener('click', function(){
        var id = el.getAttribute('data-id');
        selectedMethod = id;
        document.querySelectorAll('.pay-method').forEach(function(m){ m.classList.toggle('selected', m === el); });
        document.querySelectorAll('.pay-account').forEach(function(a){ a.classList.remove('show'); });
        document.getElementById('acc-' + id).classList.add('show');
      });
    });

    function fileToBase64(file){
      return new Promise(function(resolve, reject){
        var reader = new FileReader();
        reader.onload = function(){ resolve(reader.result.split(',')[1]); };
        reader.onerror = reject;
        reader.readAsDataURL(file);
      });
    }

    document.getElementById('submitBtn').addEventListener('click', async function(){
      var transactionId = document.getElementById('transactionId').value.trim();
      var fileInput = document.getElementById('screenshot');
      var err = document.getElementById('err');
      var btn = document.getElementById('submitBtn');

      if(!selectedMethod || !transactionId || !fileInput.files.length){
        err.style.display = 'block';
        return;
      }

      var user = await window.__authReady;
      if(!user){
        window.location.href = '/login.html?redirect=' + encodeURIComponent(window.location.pathname);
        return;
      }

      err.style.display = 'none';
      btn.disabled = true;
      btn.textContent = 'Submitting...';

      try {
        var base64 = await fileToBase64(fileInput.files[0]);
        var idToken = await user.getIdToken();
        var payload = Object.assign({}, formData, {
          paymentMethod: selectedMethod,
          transactionId: transactionId,
          screenshotBase64: base64
        }); // formData already carries platformIds: [...]
        var res = await fetch('/api/advertise/submit', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + idToken },
          body: JSON.stringify(payload)
        });
        var data = await res.json();

        if(data.success){
          sessionStorage.removeItem('advertiseForm');
          window.location.href = '${SITE_URL}/index.html';
        } else {
          btn.disabled = false;
          btn.textContent = 'Submit';
          err.textContent = data.error || 'Submission failed. Please try again.';
          err.style.display = 'block';
        }
      } catch (e) {
        btn.disabled = false;
        btn.textContent = 'Submit';
        err.textContent = 'Something went wrong. Please try again.';
        err.style.display = 'block';
      }
    });
  `;
  return layout({ title: "Payment", step: 4, content, moduleScript });
}

// ─────────────────────────────────────────────────────────────────────────
//  PAGE — MY AD STATUS
// ─────────────────────────────────────────────────────────────────────────
function pageStatus() {
  const content = `
    <h1>Your Ad Status</h1>
    <div id="statusBody"><p class="sub">Loading...</p></div>
  `;
  const moduleScript = `
    ${FIREBASE_CLIENT_INIT}

    var STATUS_LABELS = {
      pending_review: 'Pending Review',
      active: 'Active',
      rejected: 'Rejected',
      expired: 'Expired'
    };

    function fmtDate(iso){
      if(!iso) return '—';
      var d = new Date(iso);
      return d.toLocaleDateString() + ' ' + d.toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    }

    function daysLeft(expiresAt){
      if(!expiresAt) return null;
      var ms = new Date(expiresAt).getTime() - Date.now();
      return Math.max(0, Math.ceil(ms / 86400000));
    }

    async function loadStatus(){
      var body = document.getElementById('statusBody');
      var user = await window.__authReady;
      if(!user){
        window.location.href = '/login.html?redirect=' + encodeURIComponent(window.location.pathname);
        return;
      }

      var idToken = await user.getIdToken();
      var res = await fetch('/api/advertise/my-ad', { headers: { 'Authorization': 'Bearer ' + idToken } });
      var data = await res.json();

      if(!data.ad){
        body.innerHTML = '<p class="sub">You don\\'t have any ad on file yet.</p><a class="btn" href="/advertise">Create Your First Ad</a>';
        return;
      }

      var ad = data.ad;
      var badgeClass = 'status-' + ad.status;
      var badgeLabel = STATUS_LABELS[ad.status] || ad.status;
      var days = ad.status === 'active' ? daysLeft(ad.expiresAt) : null;

      var daysHtml = '';
      if(ad.status === 'active'){
        if(ad.expiresAt === null){
          daysHtml = '<div class="days-left">Permanent</div><div class="days-left-label">This ad never expires</div>';
        } else if(days !== null){
          daysHtml = '<div class="days-left">' + days + '</div><div class="days-left-label">Day' + (days === 1 ? '' : 's') + ' remaining</div>';
        }
      }

      body.innerHTML =
        '<span class="status-badge ' + badgeClass + '">' + badgeLabel + '</span>' +
        daysHtml +
        '<div id="adMediaWrap"></div>' +
        '<div class="summary" style="margin-top:16px;">' +
          '<div class="summary-row"><span>Ad Title</span><span>' + ad.adTitle + '</span></div>' +
          '<div class="summary-row"><span>Package</span><span>' + ad.package.name + '</span></div>' +
          '<div class="summary-row"><span>Submitted</span><span>' + fmtDate(ad.createdAt) + '</span></div>' +
          (ad.approvedAt ? '<div class="summary-row"><span>Approved</span><span>' + fmtDate(ad.approvedAt) + '</span></div>' : '') +
          (ad.rejectionReason ? '<div class="summary-row"><span>Reason</span><span>' + ad.rejectionReason + '</span></div>' : '') +
        '</div>';

      // Ad image fetched separately (not a plain <img src>) because the
      // endpoint needs the user's Firebase auth token, which <img> can't send.
      if (ad.adImageKey) {
        try {
          var imgRes = await fetch('/api/advertise/my-ad-image', { headers: { 'Authorization': 'Bearer ' + idToken } });
          if (imgRes.ok) {
            var blob = await imgRes.blob();
            var imgUrl = URL.createObjectURL(blob);
            document.getElementById('adMediaWrap').innerHTML = '<img src="' + imgUrl + '" alt="Ad creative" style="max-width:100%;border-radius:8px;margin-top:16px;display:block;" />';
          }
        } catch(e) {}
      }
    }

    loadStatus();
  `;
  return layout({ title: "Ad Status", content, moduleScript });
}

// ─────────────────────────────────────────────────────────────────────────
//  PAGE 5 — THANK YOU
// ─────────────────────────────────────────────────────────────────────────
function pageThankYou(ref) {
  const content = `
    <h1>Thank You!</h1>
    <p class="sub">Your ad request has been received and is pending review.</p>
    <div class="summary">
      <div class="summary-row"><span>Reference ID</span><span>${ref || "—"}</span></div>
    </div>
    <p class="sub">We'll verify your payment and activate your ad shortly. Please keep this reference ID for your records.</p>
    <a class="btn" href="${SITE_URL}">Back to Home</a>
  `;
  return layout({ title: "Thank You", step: 0, content });
}
