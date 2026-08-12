const SESSION_SECONDS = 60 * 60 * 24 * 7;
const LOGIN_WINDOW_SECONDS = 15 * 60;
const MAX_LOGIN_ATTEMPTS = 5;
let schemaReady;

const encoder = new TextEncoder();

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function fromB64url(value) {
  const padded = value.replaceAll("-", "+").replaceAll("_", "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), char => char.charCodeAt(0));
}

function cookies(request) {
  return Object.fromEntries((request.headers.get("Cookie") || "").split(";").map(part => {
    const index = part.indexOf("=");
    return index < 0 ? ["", ""] : [part.slice(0, index).trim(), decodeURIComponent(part.slice(index + 1))];
  }));
}

async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", encoder.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, encoder.encode(value))));
}

async function sessionToken(secret) {
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(encoder.encode(JSON.stringify({ iat: now, exp: now + SESSION_SECONDS })));
  return `${payload}.${await sign(payload, secret)}`;
}

async function validSession(request, secret) {
  const token = cookies(request).seh_session;
  if (!token || !token.includes(".")) return false;
  const [payload, supplied] = token.split(".");
  const expected = await sign(payload, secret);
  if (supplied.length !== expected.length) return false;
  let mismatch = 0;
  for (let i = 0; i < supplied.length; i++) mismatch |= supplied.charCodeAt(i) ^ expected.charCodeAt(i);
  if (mismatch) return false;
  try {
    return JSON.parse(new TextDecoder().decode(fromB64url(payload))).exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

async function passwordsMatch(supplied, expected) {
  if (typeof supplied !== "string" || typeof expected !== "string" || !expected) return false;
  const [a, b] = await Promise.all([crypto.subtle.digest("SHA-256", encoder.encode(supplied)), crypto.subtle.digest("SHA-256", encoder.encode(expected))]);
  const left = new Uint8Array(a), right = new Uint8Array(b);
  let mismatch = 0;
  for (let i = 0; i < left.length; i++) mismatch |= left[i] ^ right[i];
  return mismatch === 0;
}

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff", ...headers } });
}

function clientIp(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

function isSameOrigin(request) {
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}

function ensureSchema(db) {
  if (!schemaReady) schemaReady = (async () => {
    await db.prepare(`CREATE TABLE IF NOT EXISTS hub_state (
      id TEXT PRIMARY KEY,
      state_json TEXT NOT NULL,
      revision INTEGER NOT NULL DEFAULT 1,
      updated_at TEXT NOT NULL
    )`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS login_attempts (
      ip TEXT PRIMARY KEY,
      attempts INTEGER NOT NULL,
      window_started_at INTEGER NOT NULL
    )`).run();
    await db.prepare(`CREATE TABLE IF NOT EXISTS hub_equipment_chunks (
      state_id TEXT NOT NULL,
      chunk_index INTEGER NOT NULL,
      chunk_b64 TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      PRIMARY KEY (state_id, chunk_index)
    )`).run();
  })().catch(error => {
    schemaReady = null;
    throw error;
  });
  return schemaReady;
}

async function loginAllowed(db, ip) {
  const now = Math.floor(Date.now() / 1000);
  const row = await db.prepare("SELECT attempts, window_started_at FROM login_attempts WHERE ip = ?").bind(ip).first();
  return !row || now - row.window_started_at >= LOGIN_WINDOW_SECONDS || row.attempts < MAX_LOGIN_ATTEMPTS;
}

async function recordLoginFailure(db, ip) {
  const now = Math.floor(Date.now() / 1000);
  const row = await db.prepare("SELECT attempts, window_started_at FROM login_attempts WHERE ip = ?").bind(ip).first();
  if (!row || now - row.window_started_at >= LOGIN_WINDOW_SECONDS) {
    await db.prepare("INSERT INTO login_attempts (ip, attempts, window_started_at) VALUES (?, 1, ?) ON CONFLICT(ip) DO UPDATE SET attempts = 1, window_started_at = excluded.window_started_at").bind(ip, now).run();
  } else {
    await db.prepare("UPDATE login_attempts SET attempts = attempts + 1 WHERE ip = ?").bind(ip).run();
  }
}

async function clearLoginFailures(db, ip) {
  await db.prepare("DELETE FROM login_attempts WHERE ip = ?").bind(ip).run();
}

const EQUIPMENT_CHUNK_BYTES = 900_000;
const MAX_EQUIPMENT_SNAPSHOT_BYTES = 32_000_000;
const MAX_CORE_STATE_BYTES = 1_800_000;

function encodeEquipmentChunks(value) {
  const bytes = encoder.encode(JSON.stringify(value));
  const chunks = [];
  for (let start = 0; start < bytes.length; start += EQUIPMENT_CHUNK_BYTES) {
    chunks.push(b64url(bytes.slice(start, start + EQUIPMENT_CHUNK_BYTES)));
  }
  return { chunks, byteLength: bytes.length };
}

async function loadEquipmentSnapshot(db) {
  const result = await db.prepare("SELECT chunk_b64 FROM hub_equipment_chunks WHERE state_id = 'primary' ORDER BY chunk_index").all();
  const rows = result.results || [];
  if (!rows.length) return [];
  const decoded = rows.map(row => fromB64url(row.chunk_b64));
  const length = decoded.reduce((sum, chunk) => sum + chunk.length, 0);
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of decoded) {
    bytes.set(chunk, offset);
    offset += chunk.length;
  }
  const parsed = JSON.parse(new TextDecoder().decode(bytes));
  return Array.isArray(parsed) ? parsed : [];
}

async function saveEquipmentSnapshot(db, rows) {
  const { chunks, byteLength } = encodeEquipmentChunks(rows);
  if (byteLength > MAX_EQUIPMENT_SNAPSHOT_BYTES) throw new Error("Equipment snapshot is too large to save.");
  const now = new Date().toISOString();
  const statements = [db.prepare("DELETE FROM hub_equipment_chunks WHERE state_id = 'primary'")];
  chunks.forEach((chunk, index) => statements.push(
    db.prepare("INSERT INTO hub_equipment_chunks (state_id, chunk_index, chunk_b64, updated_at) VALUES ('primary', ?, ?, ?)").bind(index, chunk, now)
  ));
  await db.batch(statements);
  return { rows: rows.length, chunks: chunks.length, bytes: byteLength };
}

async function api(request, env, url) {
  await ensureSchema(env.DB);
  const path = url.pathname;
  const appPassword = typeof env.APP_PASSWORD === "string" ? env.APP_PASSWORD.trim() : "";
  const sessionSecret = typeof env.SESSION_SECRET === "string" ? env.SESSION_SECRET.trim() : "";
  if (!appPassword || !sessionSecret) return json({ error: "Server authentication is not configured. Check APP_PASSWORD and SESSION_SECRET in Cloudflare." }, 503);
  const secured = await validSession(request, sessionSecret);

  if (path === "/api/login" && request.method === "POST") {
    if (!isSameOrigin(request)) return json({ error: "Request origin was not accepted." }, 403);
    const ip = clientIp(request);
    if (!(await loginAllowed(env.DB, ip))) return json({ error: "Too many attempts. Try again in 15 minutes." }, 429, { "retry-after": String(LOGIN_WINDOW_SECONDS) });
    const body = await request.json().catch(() => ({}));
    const suppliedPassword = typeof body.password === "string" ? body.password.trim() : "";
    if (!suppliedPassword || !(await passwordsMatch(suppliedPassword, appPassword))) {
      await recordLoginFailure(env.DB, ip);
      return json({ error: "Password was not accepted." }, 401);
    }
    await clearLoginFailures(env.DB, ip);
    const token = await sessionToken(sessionSecret);
    return json({ authenticated: true }, 200, { "set-cookie": `seh_session=${token}; Max-Age=${SESSION_SECONDS}; Path=/; HttpOnly; Secure; SameSite=Strict` });
  }

  if (path === "/api/logout" && request.method === "POST") {
    return json({ authenticated: false }, 200, { "set-cookie": "seh_session=; Max-Age=0; Path=/; HttpOnly; Secure; SameSite=Strict" });
  }

  if (path === "/api/session" && request.method === "GET") return secured ? json({ authenticated: true }) : json({ authenticated: false }, 401);
  if (!secured) return json({ error: "Sign-in required." }, 401);

  if (path === "/api/state" && request.method === "GET") {
    const row = await env.DB.prepare("SELECT state_json, revision FROM hub_state WHERE id = 'primary'").first();
    if (!row) return json({ error: "No saved workspace yet." }, 404);
    return new Response(row.state_json, { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "etag": `\"${row.revision}\"`, "x-seh-revision": String(row.revision), "x-content-type-options": "nosniff" } });
  }

  if (path === "/api/equipment-snapshot" && request.method === "GET") {
    try {
      const rows = await loadEquipmentSnapshot(env.DB);
      return new Response(JSON.stringify(rows), { headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" } });
    } catch (error) {
      return json({ error: error?.message || "Equipment snapshot could not be loaded." }, 500);
    }
  }

  if (path === "/api/equipment-snapshot" && request.method === "PUT") {
    if (!isSameOrigin(request)) return json({ error: "Request origin was not accepted." }, 403);
    const size = Number(request.headers.get("content-length") || 0);
    if (size > MAX_EQUIPMENT_SNAPSHOT_BYTES) return json({ error: "Equipment snapshot is too large to save." }, 413);
    const body = await request.text();
    if (encoder.encode(body).length > MAX_EQUIPMENT_SNAPSHOT_BYTES) return json({ error: "Equipment snapshot is too large to save." }, 413);
    let rows;
    try {
      rows = JSON.parse(body);
      if (!Array.isArray(rows)) throw new Error("invalid");
    } catch {
      return json({ error: "Equipment snapshot data was not valid." }, 400);
    }
    try {
      const saved = await saveEquipmentSnapshot(env.DB, rows);
      return json({ saved: true, ...saved });
    } catch (error) {
      return json({ error: error?.message || "Equipment snapshot could not be saved." }, 500);
    }
  }

  if (path === "/api/state" && request.method === "PUT") {
    if (!isSameOrigin(request)) return json({ error: "Request origin was not accepted." }, 403);
    const size = Number(request.headers.get("content-length") || 0);
    if (size > MAX_CORE_STATE_BYTES) return json({ error: "Core workspace is too large to save." }, 413);
    const body = await request.text();
    if (encoder.encode(body).length > MAX_CORE_STATE_BYTES) return json({ error: "Core workspace is too large to save." }, 413);
    try { const parsed = JSON.parse(body); if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw new Error("invalid"); } catch { return json({ error: "Workspace data was not valid." }, 400); }
    const current = await env.DB.prepare("SELECT revision FROM hub_state WHERE id = 'primary'").first();
    const requestedRevision = (request.headers.get("x-seh-revision") || request.headers.get("if-match") || "").replaceAll('"', "").trim();
    const now = new Date().toISOString();
    if (!current) {
      if (requestedRevision) return json({ error: "Workspace version conflict." }, 409);
      await env.DB.prepare("INSERT INTO hub_state (id, state_json, revision, updated_at) VALUES ('primary', ?, 1, ?)").bind(body, now).run();
      return json({ saved: true }, 200, { etag: '"1"', "x-seh-revision": "1" });
    }
    if (!requestedRevision || requestedRevision !== String(current.revision)) return json({ error: "Workspace changed on another device.", currentRevision: String(current.revision), receivedRevision: requestedRevision || "missing" }, 409);
    const nextRevision = current.revision + 1;
    const result = await env.DB.prepare("UPDATE hub_state SET state_json = ?, revision = ?, updated_at = ? WHERE id = 'primary' AND revision = ?").bind(body, nextRevision, now, current.revision).run();
    if (!result.meta.changes) return json({ error: "Workspace changed on another device." }, 409);
    return json({ saved: true }, 200, { etag: `\"${nextRevision}\"`, "x-seh-revision": String(nextRevision) });
  }

  return json({ error: "Not found." }, 404);
}

function withSecurityHeaders(response) {
  const headers = new Headers(response.headers);
  headers.set("X-Content-Type-Options", "nosniff");
  headers.set("Referrer-Policy", "same-origin");
  headers.set("X-Frame-Options", "DENY");
  headers.set("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'");
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (url.pathname.startsWith("/api/")) return api(request, env, url);
    return withSecurityHeaders(await env.ASSETS.fetch(request));
  }
};
