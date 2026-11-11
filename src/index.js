const enc = new TextEncoder();

const CORS = {
  "access-control-allow-origin": "*",
  "access-control-allow-methods": "GET,POST,OPTIONS",
  "access-control-allow-headers": "content-type,x-admin-key"
};

const json = (data, status = 200) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", ...CORS }
  });

const fail = (error, status = 400) => json({ error }, status);

const b64u = (buf) =>
  btoa(String.fromCharCode(...new Uint8Array(buf)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");

const hex = (buf) =>
  [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");

const now = () => Math.floor(Date.now() / 1000);

function normPhone(raw) {
  let d = String(raw || "").replace(/\D/g, "");
  if (d.startsWith("0")) d = "251" + d.slice(1);
  if (d.length === 9) d = "251" + d;
  if (!/^251[79]\d{8}$/.test(d)) return null;
  return d;
}

function validDevice(id) {
  return typeof id === "string" && /^[A-Za-z0-9_-]{8,128}$/.test(id);
}

function newRecoveryCode() {
  const alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789";
  const bytes = crypto.getRandomValues(new Uint8Array(10));
  const chars = [...bytes].map((b) => alphabet[b % alphabet.length]);
  return chars.slice(0, 5).join("") + "-" + chars.slice(5).join("");
}

async function hashRecovery(phone, code) {
  const clean = String(code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(phone + ":" + clean));
  return hex(digest);
}

let signKeyCache = null;

async function signKey(env) {
  if (!signKeyCache) {
    signKeyCache = crypto.subtle.importKey(
      "jwk",
      JSON.parse(env.SIGN_JWK),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["sign"]
    );
  }
  return signKeyCache;
}

async function makeToken(env, phone, device, tier, ttlSeconds) {
  const iat = now();
  const ttl = ttlSeconds || Number(env.TOKEN_DAYS || 7) * 86400;
  const payload = { p: phone, d: device, t: tier, iat, exp: iat + ttl };
  const body = b64u(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign(
    { name: "ECDSA", hash: "SHA-256" },
    await signKey(env),
    enc.encode(body)
  );
  return { token: body + "." + b64u(sig), exp: payload.exp };
}

function publicJwk(env) {
  const { kty, crv, x, y } = JSON.parse(env.SIGN_JWK);
  return { kty, crv, x, y };
}

async function readBody(request) {
  try {
    return await request.json();
  } catch {
    return {};
  }
}

function sameSecret(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function getTiers(env) {
  const res = await fetch(env.TIERS_URL, { cf: { cacheTtl: 600, cacheEverything: true } });
  if (!res.ok) throw new Error("tiers_unavailable");
  return res.json();
}

async function notify(env, text) {
  if (!env.TG_BOT_TOKEN || !env.TG_CHAT_ID) return;
  try {
    await fetch("https://api.telegram.org/bot" + env.TG_BOT_TOKEN + "/sendMessage", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ chat_id: env.TG_CHAT_ID, text })
    });
  } catch {}
}

const b64uBytes = (str) => {
  const bin = atob(str.replace(/-/g, "+").replace(/_/g, "/"));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
};

let verifyKeyCache = null;

async function verifyKey(env) {
  if (!verifyKeyCache) {
    const { kty, crv, x, y } = JSON.parse(env.SIGN_JWK);
    verifyKeyCache = crypto.subtle.importKey("jwk", { kty, crv, x, y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  }
  return verifyKeyCache;
}

async function relayUser(request, env) {
  const tk = request.headers.get("x-alpha-token") || "";
  const [body, sig] = tk.split(".");
  if (!body || !sig) return null;
  try {
    const ok = await crypto.subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      await verifyKey(env),
      b64uBytes(sig),
      enc.encode(body)
    );
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(b64uBytes(body)));
    if (!p.exp || p.exp < now()) return null;
    const u = await env.DB.prepare("SELECT tier, status, device_id, expires_at FROM users WHERE phone = ?").bind(p.p).first();
    if (!u || u.status !== "active" || u.device_id !== p.d || (u.expires_at && u.expires_at <= now())) return null;
    let ours = u.tier === 5;
    try {
      const tt = await getTiers(env);
      const f = tt.tiers[String(u.tier)];
      if (f) ours = f.key_mode === "ours";
    } catch {}
    return ours ? p : null;
  } catch {
    return null;
  }
}

async function contentUser(request, env) {
  const tk = request.headers.get("x-alpha-token") || "";
  const [body, sig] = tk.split(".");
  if (!body || !sig) return null;
  try {
    const ok = await crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, await verifyKey(env), b64uBytes(sig), enc.encode(body));
    if (!ok) return null;
    const p = JSON.parse(new TextDecoder().decode(b64uBytes(body)));
    if (!p.exp || p.exp < now()) return null;
    const u = await env.DB.prepare("SELECT tier, status, device_id, expires_at FROM users WHERE phone = ?").bind(p.p).first();
    if (!u || u.status !== "active" || u.device_id !== p.d || (u.expires_at && u.expires_at <= now())) return null;
    let allowed = u.tier >= 3;
    try {
      const tt = await getTiers(env);
      const f = tt.tiers[String(u.tier)];
      if (f) allowed = f.generated === true;
    } catch {}
    return allowed ? p : null;
  } catch {
    return null;
  }
}

async function handleContent(request, env, path) {
  if (!env.HF_TOKEN) return fail("not_configured", 503);
  const p = await contentUser(request, env);
  if (!p) return fail("denied", 403);
  let rel;
  try { rel = decodeURIComponent(path.slice(9)); } catch { return fail("bad_path"); }
  if (!rel || rel.includes("..") || rel.startsWith("/") || rel.length > 300) return fail("bad_path");
  const repo = env.PAID_REPO || "Kinfemichael/Alpha-paid";
  const url = "https://huggingface.co/datasets/" + repo + "/resolve/main/" + rel.split("/").map(encodeURIComponent).join("/");
  const r = await fetch(url, { headers: { authorization: "Bearer " + env.HF_TOKEN, "user-agent": "alpha-server" } });
  if (r.status === 404) return fail("not_found", 404);
  if (!r.ok) return fail("upstream_error", 502);
  return new Response(r.body, { status: 200, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "private, no-store", ...CORS } });
}

const relayFail = (message, status) =>
  new Response(JSON.stringify({ error: { code: status, message, status: "RELAY" } }), {
    status,
    headers: { "content-type": "application/json" }
  });

let usageReady = false;

async function relayAllowed(env, phone, userTier) {
  if (!usageReady) {
    await env.DB.prepare(
      "CREATE TABLE IF NOT EXISTS relay_usage (phone TEXT NOT NULL, day INTEGER NOT NULL, n INTEGER NOT NULL, PRIMARY KEY (phone, day))"
    ).run();
    usageReady = true;
  }
  let limit = 300;
  try {
    const tt = await getTiers(env);
    const f = tt.tiers[String(userTier)];
    if (f && Number(f.relay_daily) > 0) limit = Number(f.relay_daily);
  } catch {}
  const day = Math.floor((Date.now() + 3 * 3600 * 1000) / 86400000);
  const row = await env.DB.prepare(
    "INSERT INTO relay_usage (phone, day, n) VALUES (?, ?, 1) ON CONFLICT(phone, day) DO UPDATE SET n = n + 1 WHERE n < ? RETURNING n"
  ).bind(phone, day, limit).first();
  return !!row;
}

let relayKeysCache = null;

function relayPools(env) {
  if (!relayKeysCache) {
    try { relayKeysCache = JSON.parse(env.RELAY_KEYS || "{}"); } catch { relayKeysCache = {}; }
  }
  return relayKeysCache;
}

function poolOf(env, id) {
  let v = relayPools(env)[id];
  if (!v && id === "gemini") v = env.GEMINI_KEYS;
  const list = Array.isArray(v) ? v : String(v || "").split(",");
  return list.map((k) => String(k).trim()).filter(Boolean);
}

function poolIds(env) {
  const ids = new Set(Object.keys(relayPools(env)));
  if (env.GEMINI_KEYS) ids.add("gemini");
  return [...ids].filter((id) => poolOf(env, id).length > 0);
}

async function getProviders(env) {
  const res = await fetch(env.PROVIDERS_URL, { cf: { cacheTtl: 600, cacheEverything: true } });
  if (!res.ok) throw new Error("providers_unavailable");
  const j = await res.json();
  return Array.isArray(j) ? j : [];
}

async function handleRelay(request, env, path) {
  const p = await relayUser(request, env);
  if (!p) return relayFail("relay_denied", 401);
  const m = path.match(/^\/relay\/([A-Za-z0-9_-]+)(\/.*)?$/);
  if (!m) return relayFail("not_found", 404);
  const id = m[1];
  const rest = m[2] || "";
  if (id === "_providers") return json({ ids: poolIds(env) });
  const keys = poolOf(env, id);
  if (!keys.length) return relayFail("relay_unavailable", 503);

  let base;
  let kind = "openai";
  if (id === "gemini") {
    base = "https://generativelanguage.googleapis.com/v1beta";
    kind = "gemini";
  } else {
    let pr = null;
    try { pr = (await getProviders(env)).find((x) => x && x.id === id); } catch {}
    if (!pr || !/^https:\/\//.test(String(pr.base_url || ""))) return relayFail("relay_unavailable", 503);
    base = String(pr.base_url).replace(/\/+$/, "");
    if (pr.type === "anthropic") kind = "anthropic";
  }

  const okPath = kind === "gemini"
    ? /^\/models(\/[A-Za-z0-9._-]+:(generateContent|streamGenerateContent))?$/.test(rest)
    : /^\/(chat\/completions|models|v1\/messages|v1\/models)$/.test(rest);
  if (!okPath) return relayFail("not_found", 404);

  const src = new URL(request.url).searchParams;
  const q = new URLSearchParams();
  if (kind === "gemini" && src.get("alt") === "sse") q.set("alt", "sse");
  if (/^\d{1,3}$/.test(src.get("pageSize") || "")) q.set("pageSize", src.get("pageSize"));
  if (/^\d{1,3}$/.test(src.get("limit") || "")) q.set("limit", src.get("limit"));

  let body;
  if (request.method === "POST") {
    body = await request.arrayBuffer();
    if (body.byteLength > 4000000) return relayFail("too_large", 413);
    if (!(await relayAllowed(env, p.p, p.t))) return relayFail("relay_limit", 429);
  } else if (request.method !== "GET") {
    return relayFail("not_found", 404);
  }

  const upstream = base + rest + (q.toString() ? "?" + q.toString() : "");
  const start = Math.floor(Math.random() * keys.length);
  const tries = Math.min(3, keys.length);
  let last = null;
  for (let i = 0; i < tries; i++) {
    const key = keys[(start + i) % keys.length];
    const headers = { "content-type": "application/json" };
    if (kind === "gemini") headers["x-goog-api-key"] = key;
    else if (kind === "anthropic") { headers["x-api-key"] = key; headers["anthropic-version"] = "2023-06-01"; }
    else headers["authorization"] = "Bearer " + key;
    const res = await fetch(upstream, { method: request.method, headers, body });
    last = res;
    if (res.status === 429 || res.status === 401 || res.status === 403) continue;
    break;
  }
  return new Response(last.body, {
    status: last.status,
    headers: { "content-type": last.headers.get("content-type") || "application/json" }
  });
}

let userColsReady = false;
async function ensureUserCols(env) {
  if (userColsReady) return;
  try { await env.DB.prepare("ALTER TABLE users ADD COLUMN expires_at INTEGER").run(); } catch {}
  userColsReady = true;
}

async function expiryFor(env, tier, base) {
  try {
    const cfg = ((await getTiers(env)).tiers || {})[String(tier)] || {};
    const days = Number(cfg.duration_days);
    if (days > 0) return Math.max(now(), base || 0) + Math.floor(days * 86400);
    if (typeof cfg.valid_until === "string" && /^\d{4}-\d{2}-\d{2}$/.test(cfg.valid_until)) {
      const ts = Date.parse(cfg.valid_until + "T23:59:59+03:00");
      if (ts > 0) return Math.floor(ts / 1000);
    }
  } catch {}
  return null;
}

let payColsReady = false;
async function ensurePayCols(env) {
  if (payColsReady) return;
  for (const col of ["payer_name TEXT", "payer_last4 TEXT", "amount REAL"]) {
    try { await env.DB.prepare("ALTER TABLE payments ADD COLUMN " + col).run(); } catch {}
  }
  payColsReady = true;
}

let reportReady = false;
async function handleReport(request, env, ctx) {
  const b = await readBody(request);
  if (!validDevice(b.device_id)) return fail("bad_device");
  if (!reportReady) {
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS reports (k TEXT NOT NULL, day TEXT NOT NULL, n INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (k, day))").run();
    reportReady = true;
  }
  const day = new Date(Date.now() + 3 * 3600 * 1000).toISOString().slice(0, 10);
  const ip = request.headers.get("cf-connecting-ip") || "-";
  for (const [k, max] of [["d:" + b.device_id, 10], ["ip:" + ip, 40]]) {
    const r = await env.DB.prepare(
      "INSERT INTO reports (k, day, n) VALUES (?, ?, 1) ON CONFLICT(k, day) DO UPDATE SET n = n + 1 WHERE n < ? RETURNING n"
    ).bind(k, day, max).first();
    if (!r) return fail("too_many", 429);
  }
  const clean = (v, n) => String(v || "").replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, "").slice(0, n);
  const kind = b.kind === "crash" ? "Crash" : "Problem";
  const msg = kind + " report\nApp " + clean(b.app, 20) + " | " + clean(b.model, 60) + " | Android " + clean(b.android, 20) +
    "\nState: " + clean(b.state, 20) + " level " + clean(b.tier, 4) + " | device ..." + b.device_id.slice(-6) +
    (b.contact ? "\nContact: " + clean(b.contact, 80) : "") + "\n\n" + clean(b.text, 2500);
  ctx.waitUntil(notify(env, msg.slice(0, 3800)));
  return json({ ok: true });
}

async function handleRegister(request, env, ctx) {
  await ensurePayCols(env);
  await ensureUserCols(env);
  const b = await readBody(request);
  const phone = normPhone(b.phone);
  const tier = Number(b.tier);
  let txn = String(b.txn_id || "").trim().toUpperCase();
  const method = b.method === "telebirr" ? "telebirr" : b.method === "cbe" ? "cbe" : null;
  const payerName = String(b.payer_name || "").trim().replace(/\s+/g, " ").slice(0, 60);
  const payerLast4 = String(b.payer_last4 || "").trim();
  const amount = Number(b.amount);
  if (!phone) return fail("bad_phone");
  if (!validDevice(b.device_id)) return fail("bad_device");
  if (![2, 3, 4, 5].includes(tier)) return fail("bad_tier");
  if (!method) return fail("bad_method");
  if (method === "cbe") {
    if (payerName.length < 3) return fail("bad_payer_name");
    if (!/^\d{4}$/.test(payerLast4)) return fail("bad_last4");
    if (!(amount > 0) || amount > 1000000) return fail("bad_amount");
    txn = "CBE-" + now() + "-" + payerLast4;
  } else if (!/^[A-Z0-9]{6,32}$/.test(txn)) return fail("bad_txn");

  const user = await env.DB.prepare("SELECT * FROM users WHERE phone = ?").bind(phone).first();
  if (user && user.status === "active" && user.device_id !== b.device_id) {
    return fail("already_registered", 409);
  }
  if (user && user.status === "active" && tier <= user.tier && !renewable(user, tier)) {
    return fail("not_an_upgrade", 409);
  }
  const pending = await env.DB.prepare(
    "SELECT id FROM payments WHERE phone = ? AND status = 'pending'"
  ).bind(phone).first();
  if (pending) {
    if (user && user.device_id === b.device_id) return json({ state: "pending" });
    return fail("payment_pending", 409);
  }

  const t = now();
  try {
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO users (phone, tier, status, device_id, created_at) VALUES (?, 0, 'pending', ?, ?) " +
          "ON CONFLICT(phone) DO UPDATE SET device_id = CASE WHEN users.status = 'active' THEN users.device_id ELSE excluded.device_id END"
      ).bind(phone, b.device_id, t),
      env.DB.prepare(
        "INSERT INTO payments (phone, device_id, tier, txn_id, method, created_at, payer_name, payer_last4, amount) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"
      ).bind(phone, b.device_id, tier, txn, method, t, method === "cbe" ? payerName : null, method === "cbe" ? payerLast4 : null, method === "cbe" ? amount : null),
      env.DB.prepare("DELETE FROM wipes WHERE device_id = ?").bind(b.device_id)
    ]);
  } catch (e) {
    if (String(e).includes("UNIQUE")) return fail("txn_used", 409);
    throw e;
  }
  const origin = new URL(request.url).origin;
  ctx.waitUntil(
    (async () => {
      let label = "Level " + tier;
      try {
        const tt = await getTiers(env);
        const f = tt.tiers[String(tier)];
        label += " " + f.name + " - expected " + f.price + " " + (tt.currency || "ETB");
      } catch {}
      await notify(env, "New payment\n+" + phone + "\n" + label + "\nVia " + method + (method === "cbe" ? "\nSender: " + payerName + "\nAccount ends: " + payerLast4 + "\nAmount: " + amount : "\nTxn: " + txn) + "\n" + origin + "/admin");
    })()
  );
  return json({ state: "pending" });
}

function renewable(user, tier) {
  if (!user || !user.expires_at) return false;
  const left = user.expires_at - now();
  return left <= 0 || (left < 14 * 86400 && tier === user.tier);
}

async function handleStatus(request, env) {
  await ensureUserCols(env);
  const b = await readBody(request);
  const phone = normPhone(b.phone);
  if (!phone) return fail("bad_phone");
  if (!validDevice(b.device_id)) return fail("bad_device");

  const wipe = await env.DB.prepare("SELECT 1 AS x FROM wipes WHERE device_id = ?")
    .bind(b.device_id)
    .first();
  if (wipe) return json({ state: "wipe" });

  const user = await env.DB.prepare("SELECT * FROM users WHERE phone = ?").bind(phone).first();
  if (!user) return json({ state: "none" });
  if (user.device_id !== b.device_id) return json({ state: "other_device" });
  if (user.status === "revoked") return json({ state: "none" });
  if (user.status === "pending") {
    const last = await env.DB.prepare("SELECT status FROM payments WHERE phone = ? ORDER BY id DESC LIMIT 1").bind(phone).first();
    if (last && last.status === "rejected") return json({ state: "rejected" });
    return json({ state: "pending" });
  }

  const t1 = now();
  if (user.expires_at && user.expires_at <= t1) {
    const pp = await env.DB.prepare("SELECT 1 AS x FROM payments WHERE phone = ? AND status = 'pending'").bind(phone).first();
    if (pp) return json({ state: "pending" });
    return json({ state: "expired", tier: user.tier, expires: user.expires_at });
  }

  const out = { state: "active", tier: user.tier, expires: user.expires_at || 0 };
  if (user.recovery_plain) {
    out.recovery_code = user.recovery_plain;
    await env.DB.prepare("UPDATE users SET recovery_plain = NULL WHERE phone = ?")
      .bind(phone)
      .run();
  }
  const defTtl = Number(env.TOKEN_DAYS || 7) * 86400;
  const tk = await makeToken(env, phone, b.device_id, user.tier, user.expires_at ? Math.min(defTtl, user.expires_at - t1) : defTtl);
  out.token = tk.token;
  out.exp = tk.exp;
  return json(out);
}

async function handleMove(request, env) {
  await ensureUserCols(env);
  const b = await readBody(request);
  const phone = normPhone(b.phone);
  if (!phone) return fail("bad_phone");
  if (!validDevice(b.device_id)) return fail("bad_device");

  const user = await env.DB.prepare("SELECT * FROM users WHERE phone = ?").bind(phone).first();
  if (!user || user.status !== "active" || !user.recovery_hash) return fail("not_found", 404);
  if (user.fails >= 5) return fail("locked", 429);

  const given = await hashRecovery(phone, b.recovery_code);
  if (!sameSecret(given, user.recovery_hash)) {
    await env.DB.prepare("UPDATE users SET fails = fails + 1 WHERE phone = ?").bind(phone).run();
    return fail("wrong_code", 403);
  }

  const code = newRecoveryCode();
  const newHash = await hashRecovery(phone, code);
  const t = now();
  const stmts = [
    env.DB.prepare("DELETE FROM wipes WHERE device_id = ?").bind(b.device_id),
    env.DB.prepare(
      "UPDATE users SET device_id = ?, recovery_hash = ?, recovery_plain = NULL, fails = 0 WHERE phone = ?"
    ).bind(b.device_id, newHash, phone)
  ];
  if (user.device_id && user.device_id !== b.device_id) {
    stmts.push(
      env.DB.prepare(
        "INSERT OR REPLACE INTO wipes (device_id, phone, created_at) VALUES (?, ?, ?)"
      ).bind(user.device_id, phone, t)
    );
  }
  await env.DB.batch(stmts);
  const defTtl = Number(env.TOKEN_DAYS || 7) * 86400;
  if (user.expires_at && user.expires_at <= now()) return json({ state: "expired", tier: user.tier, expires: user.expires_at, recovery_code: code });
  const tk = await makeToken(env, phone, b.device_id, user.tier, user.expires_at ? Math.min(defTtl, user.expires_at - now()) : defTtl);
  return json({ state: "active", tier: user.tier, expires: user.expires_at || 0, token: tk.token, exp: tk.exp, recovery_code: code });
}

async function handleAckWipe(request, env) {
  const b = await readBody(request);
  if (!validDevice(b.device_id)) return fail("bad_device");
  await env.DB.prepare("DELETE FROM wipes WHERE device_id = ?").bind(b.device_id).run();
  return json({ ok: true });
}

async function handleTrial(request, env) {
  const b = await readBody(request);
  const phone = normPhone(b.phone);
  if (!phone) return fail("bad_phone");
  if (!validDevice(b.device_id)) return fail("bad_device");

  const used = await env.DB.prepare("SELECT 1 AS x FROM trials WHERE phone = ? OR device_id = ?")
    .bind(phone, b.device_id)
    .first();
  if (used) return fail("trial_used", 409);
  const user = await env.DB.prepare("SELECT status FROM users WHERE phone = ?").bind(phone).first();
  if (user && user.status === "active") return fail("already_registered", 409);

  let seconds = 300;
  try {
    const tiers = await getTiers(env);
    if (Number(tiers.trial_seconds) > 0) seconds = Number(tiers.trial_seconds);
  } catch {}

  await env.DB.batch([
    env.DB.prepare("INSERT INTO trials (phone, device_id, created_at) VALUES (?, ?, ?)").bind(phone, b.device_id, now()),
    env.DB.prepare("DELETE FROM wipes WHERE device_id = ?").bind(b.device_id)
  ]);
  const tk = await makeToken(env, phone, b.device_id, 1, seconds + 60);
  return json({ state: "trial", tier: 1, seconds, token: tk.token, exp: tk.exp });
}

let extraReady = false;

async function ensureExtra(env) {
  if (extraReady) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS admin_fails (ip TEXT PRIMARY KEY, n INTEGER NOT NULL, ts INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS codes (code TEXT PRIMARY KEY, tier INTEGER NOT NULL, uses_left INTEGER NOT NULL, expires_at INTEGER, note TEXT, created_at INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS code_uses (code TEXT NOT NULL, phone TEXT NOT NULL, created_at INTEGER NOT NULL, PRIMARY KEY (code, phone))")
  ]);
  extraReady = true;
}

async function handleRedeem(request, env, ctx) {
  await ensureUserCols(env);
  await ensureExtra(env);
  const b = await readBody(request);
  const phone = normPhone(b.phone);
  const code = String(b.code || "").toUpperCase().replace(/[^A-Z0-9]/g, "");
  if (!phone) return fail("bad_phone");
  if (!validDevice(b.device_id)) return fail("bad_device");
  if (code.length < 6) return fail("bad_code", 404);

  const dashed = code.length === 8 ? code.slice(0, 4) + "-" + code.slice(4) : code;
  const row = await env.DB.prepare("SELECT * FROM codes WHERE code = ?").bind(dashed).first();
  if (!row || row.uses_left <= 0 || (row.expires_at && row.expires_at < now())) return fail("bad_code", 404);

  const user = await env.DB.prepare("SELECT * FROM users WHERE phone = ?").bind(phone).first();
  if (user && user.status === "active" && user.device_id !== b.device_id) return fail("already_registered", 409);
  if (user && user.status === "active" && user.tier >= row.tier && !renewable(user, row.tier)) return fail("not_an_upgrade", 409);
  const used = await env.DB.prepare("SELECT 1 AS x FROM code_uses WHERE code = ? AND phone = ?").bind(dashed, phone).first();
  if (used) return fail("code_used", 409);

  const dec = await env.DB.prepare("UPDATE codes SET uses_left = uses_left - 1 WHERE code = ? AND uses_left > 0").bind(dashed).run();
  if (!dec.meta || dec.meta.changes !== 1) return fail("bad_code", 404);

  const t = now();
  const expAt = await expiryFor(env, row.tier, user && user.tier === row.tier ? user.expires_at : null);
  const needsCode = !user || !user.recovery_hash;
  const rec = needsCode ? newRecoveryCode() : null;
  const hash = needsCode ? await hashRecovery(phone, rec) : null;
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO users (phone, tier, status, device_id, recovery_hash, recovery_plain, created_at, expires_at) VALUES (?, ?, 'active', ?, ?, ?, ?, ?) " +
        "ON CONFLICT(phone) DO UPDATE SET tier = excluded.tier, status = 'active', device_id = excluded.device_id, expires_at = excluded.expires_at, " +
        "recovery_hash = COALESCE(users.recovery_hash, excluded.recovery_hash), " +
        "recovery_plain = CASE WHEN users.recovery_hash IS NULL THEN excluded.recovery_plain ELSE users.recovery_plain END, fails = 0"
    ).bind(phone, row.tier, b.device_id, hash, rec, t, expAt),
    env.DB.prepare("INSERT INTO code_uses (code, phone, created_at) VALUES (?, ?, ?)").bind(dashed, phone, t),
    env.DB.prepare("DELETE FROM wipes WHERE device_id = ?").bind(b.device_id)
  ]);
  ctx.waitUntil(notify(env, "Invite code used\n+" + phone + "\nLevel " + row.tier + "\nCode: " + dashed + "\nUses left: " + (row.uses_left - 1)));
  return json({ state: "active" });
}

async function adminGate(request, env) {
  await ensureExtra(env);
  const ip = request.headers.get("cf-connecting-ip") || "unknown";
  const t = now();
  const row = await env.DB.prepare("SELECT n, ts FROM admin_fails WHERE ip = ?").bind(ip).first();
  if (row && row.n >= 5 && t - row.ts < 900) return fail("locked", 429);
  if (!sameSecret(request.headers.get("x-admin-key") || "", env.ADMIN_KEY || "")) {
    const n = row && t - row.ts < 900 ? row.n + 1 : 1;
    await env.DB.prepare("INSERT INTO admin_fails (ip, n, ts) VALUES (?, ?, ?) ON CONFLICT(ip) DO UPDATE SET n = excluded.n, ts = excluded.ts").bind(ip, n, t).run();
    return fail("unauthorized", 401);
  }
  if (row) await env.DB.prepare("DELETE FROM admin_fails WHERE ip = ?").bind(ip).run();
  return null;
}

async function handleAdmin(request, env, path) {
  const denied = await adminGate(request, env);
  if (denied) return denied;
  const b = request.method === "POST" ? await readBody(request) : {};

  await ensurePayCols(env);
  await ensureUserCols(env);

  if (path === "/admin/pending") {
    const rows = await env.DB.prepare(
      "SELECT id, phone, tier, txn_id, method, created_at, payer_name, payer_last4, amount FROM payments WHERE status = 'pending' ORDER BY id"
    ).all();
    let tiers = {};
    let currency = "ETB";
    try {
      const tt = await getTiers(env);
      tiers = tt.tiers || {};
      currency = tt.currency || currency;
    } catch {}
    const items = rows.results.map((r) => ({
      ...r,
      name: tiers[String(r.tier)] ? tiers[String(r.tier)].name : "",
      price: tiers[String(r.tier)] ? tiers[String(r.tier)].price : null,
      currency
    }));
    return json({ items, tiers });
  }

  if (path === "/admin/approve") {
    const p = await env.DB.prepare("SELECT * FROM payments WHERE id = ? AND status = 'pending'")
      .bind(Number(b.id))
      .first();
    if (!p) return fail("not_found", 404);
    const user = await env.DB.prepare("SELECT * FROM users WHERE phone = ?").bind(p.phone).first();
    const tier = [2, 3, 4, 5].includes(Number(b.tier)) ? Number(b.tier) : p.tier;
    p.tier = tier;
    const expAt = await expiryFor(env, tier, user && user.tier === tier ? user.expires_at : null);
    const stmts = [
      env.DB.prepare("UPDATE payments SET status = 'approved', tier = ?, decided_at = ? WHERE id = ?").bind(tier, now(), p.id)
    ];
    if (user && user.recovery_hash) {
      stmts.push(
        env.DB.prepare("UPDATE users SET tier = ?, status = 'active', expires_at = ? WHERE phone = ?").bind(p.tier, expAt, p.phone)
      );
    } else {
      const code = newRecoveryCode();
      const h = await hashRecovery(p.phone, code);
      stmts.push(
        env.DB.prepare(
          "UPDATE users SET tier = ?, status = 'active', expires_at = ?, recovery_hash = ?, recovery_plain = ?, fails = 0 WHERE phone = ?"
        ).bind(p.tier, expAt, h, code, p.phone)
      );
    }
    await env.DB.batch(stmts);
    return json({ ok: true });
  }

  if (path === "/admin/reject") {
    await env.DB.prepare("UPDATE payments SET status = 'rejected', decided_at = ? WHERE id = ? AND status = 'pending'")
      .bind(now(), Number(b.id))
      .run();
    return json({ ok: true });
  }

  if (path === "/admin/genkey") {
    const pair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"]);
    return json({ sign_jwk: JSON.stringify(await crypto.subtle.exportKey("jwk", pair.privateKey)) });
  }

  if (path === "/admin/user") {
    const phone = normPhone(b.phone);
    if (!phone) return fail("bad_phone");
    const u = await env.DB.prepare("SELECT phone, tier, status, device_id, created_at, expires_at FROM users WHERE phone = ?").bind(phone).first();
    if (!u) return fail("not_found", 404);
    const pays = await env.DB.prepare("SELECT tier, txn_id, method, status, created_at, payer_name, payer_last4, amount FROM payments WHERE phone = ? ORDER BY id DESC LIMIT 5").bind(phone).all();
    return json({ user: { ...u, device_id: u.device_id ? "..." + u.device_id.slice(-6) : null }, payments: pays.results });
  }

  if (path === "/admin/set_tier") {
    const phone = normPhone(b.phone);
    const tier = Number(b.tier);
    if (!phone || ![0, 2, 3, 4, 5].includes(tier)) return fail("bad_request");
    const u = await env.DB.prepare("SELECT status FROM users WHERE phone = ?").bind(phone).first();
    if (!u || u.status !== "active") return fail("not_found", 404);
    await env.DB.prepare("UPDATE users SET tier = ?, expires_at = ? WHERE phone = ?").bind(tier, tier >= 2 ? await expiryFor(env, tier, null) : null, phone).run();
    return json({ ok: true });
  }

  if (path === "/admin/extend") {
    const phone = normPhone(b.phone);
    const days = Math.floor(Number(b.days));
    if (!phone || !(days > 0 && days <= 400)) return fail("bad_request");
    const u = await env.DB.prepare("SELECT status, expires_at FROM users WHERE phone = ?").bind(phone).first();
    if (!u || u.status !== "active") return fail("not_found", 404);
    const to = Math.max(now(), u.expires_at || 0) + days * 86400;
    await env.DB.prepare("UPDATE users SET expires_at = ? WHERE phone = ?").bind(to, phone).run();
    return json({ ok: true, expires_at: to });
  }

  if (path === "/admin/revoke") {
    const phone = normPhone(b.phone);
    if (!phone) return fail("bad_phone");
    const u = await env.DB.prepare("SELECT device_id FROM users WHERE phone = ?").bind(phone).first();
    if (!u) return fail("not_found", 404);
    const stmts = [env.DB.prepare("UPDATE users SET tier = 0, status = 'revoked', recovery_plain = NULL WHERE phone = ?").bind(phone)];
    if (u.device_id) {
      stmts.push(env.DB.prepare("INSERT OR REPLACE INTO wipes (device_id, phone, created_at) VALUES (?, ?, ?)").bind(u.device_id, phone, now()));
    }
    await env.DB.batch(stmts);
    return json({ ok: true });
  }

  if (path === "/admin/code/create") {
    const tier = Number(b.tier);
    const uses = Math.min(Math.max(Math.floor(Number(b.uses) || 1), 1), 1000);
    const days = Math.floor(Number(b.days) || 0);
    if (![2, 3, 4, 5].includes(tier)) return fail("bad_tier");
    const raw = newRecoveryCode().replace("-", "");
    const code = raw.slice(0, 4) + "-" + raw.slice(4, 8);
    await env.DB.prepare("INSERT INTO codes (code, tier, uses_left, expires_at, note, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .bind(code, tier, uses, days > 0 ? now() + days * 86400 : null, String(b.note || "").slice(0, 60), now())
      .run();
    return json({ code });
  }

  if (path === "/admin/code/list") {
    const rows = await env.DB.prepare("SELECT code, tier, uses_left, expires_at, note FROM codes ORDER BY created_at DESC LIMIT 30").all();
    return json({ items: rows.results });
  }

  if (path === "/admin/code/delete") {
    await env.DB.prepare("DELETE FROM codes WHERE code = ?").bind(String(b.code || "")).run();
    return json({ ok: true });
  }

  if (path === "/admin/reset") {
    const phone = normPhone(b.phone);
    if (!phone) return fail("bad_phone");
    const user = await env.DB.prepare("SELECT status FROM users WHERE phone = ?").bind(phone).first();
    if (!user || user.status !== "active") return fail("not_found", 404);
    const code = newRecoveryCode();
    const h = await hashRecovery(phone, code);
    await env.DB.prepare("UPDATE users SET recovery_hash = ?, recovery_plain = NULL, fails = 0 WHERE phone = ?")
      .bind(h, phone)
      .run();
    return json({ recovery_code: code });
  }

  return fail("not_found", 404);
}

const ADMIN_HTML = `<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>ALPHA Admin</title>
<style>
body{font-family:sans-serif;margin:0;padding:12px;background:#f4f6fb;color:#111}
input,button{font-size:16px;padding:10px;margin:4px 0;width:100%;box-sizing:border-box}
button{background:#1565c0;color:#fff;border:0;border-radius:6px}
button.no{background:#b71c1c}
.card{background:#fff;border-radius:8px;padding:10px;margin:8px 0}
.row{display:flex;gap:8px}
</style></head><body>
<h3>ALPHA Admin</h3>
<input id="key" type="password" placeholder="Admin key">
<button onclick="load()">Load pending payments</button>
<div id="list"></div>
<h4>Find user</h4>
<input id="fu" placeholder="Phone number">
<button onclick="findUser()">Find</button>
<div id="uinfo"></div>
<h4>Invite codes</h4>
<select id="ct" style="font-size:16px;padding:10px;width:100%"><option value="2">Level 2</option><option value="3">Level 3</option><option value="4">Level 4</option><option value="5">Level 5</option></select>
<input id="cu" placeholder="How many people can use it (default 1)">
<input id="cd" placeholder="Days until it expires (empty = never)">
<input id="cn" placeholder="Note (optional)">
<button onclick="mkCode()">Create code</button>
<div id="clist"></div>
<h4>Reset recovery code</h4>
<input id="ph" placeholder="Phone number">
<button onclick="reset()">Reset</button>
<div id="out"></div>
<h4>One-time setup</h4>
<button onclick="genkey()">Generate signing key</button>
<textarea id="gk" rows="6" style="width:100%;box-sizing:border-box"></textarea>
<script>
async function genkey(){
  const d=await call('/admin/genkey');
  document.getElementById('gk').value=d.sign_jwk||d.error;
}
const k=()=>document.getElementById('key').value;
async function call(path,body){
  const r=await fetch(path,{method:'POST',headers:{'content-type':'application/json','x-admin-key':k()},body:JSON.stringify(body||{})});
  return r.json();
}
async function load(){
  const d=await call('/admin/pending');
  const el=document.getElementById('list');
  if(d.error){el.textContent=d.error;return}
  el.innerHTML='';
  d.items.forEach(p=>{
    const c=document.createElement('div');c.className='card';
    const t1=document.createElement('b');t1.textContent='+'+p.phone;
    const t2=document.createElement('div');t2.textContent='Level '+p.tier+' '+(p.name||'')+' | expected '+(p.price===null?'?':p.price)+' '+p.currency;
    const t3=document.createElement('div');t3.textContent=p.method==='cbe'?('CBE | '+p.payer_name+' | acct ends '+p.payer_last4+' | sent '+p.amount+((p.price!==null&&p.amount<p.price)?'  (LESS than price!)':'')):(p.method+' | Txn: '+p.txn_id);
    const sel=document.createElement('select');sel.style.cssText='font-size:16px;padding:10px;width:100%';
    [2,3,4,5].forEach(n=>{const o=document.createElement('option');o.value=n;const f=d.tiers&&d.tiers[n];o.textContent='Approve as Level '+n+(f?' '+f.name+' ('+f.price+')':'');if(n===p.tier)o.selected=true;sel.appendChild(o)});
    const row=document.createElement('div');row.className='row';
    const ok=document.createElement('button');ok.textContent='Approve';
    const no=document.createElement('button');no.textContent='Reject';no.className='no';
    ok.onclick=async()=>{if(!confirm('Approve +'+p.phone+' as Level '+sel.value+'?'))return;await call('/admin/approve',{id:p.id,tier:Number(sel.value)});load()};
    no.onclick=async()=>{if(!confirm('Reject this payment?'))return;await call('/admin/reject',{id:p.id});load()};
    row.append(ok,no);
    c.append(t1,t2,t3,sel,row);
    el.appendChild(c);
  });
  if(!d.items.length)el.textContent='No pending payments';
}
async function findUser(){
  const el=document.getElementById('uinfo');el.textContent='';
  const d=await call('/admin/user',{phone:document.getElementById('fu').value});
  if(d.error){el.textContent=d.error;return}
  const u=d.user;
  const c=document.createElement('div');c.className='card';
  const a=document.createElement('div');a.textContent='+'+u.phone+' | Level '+u.tier+' | '+u.status+' | device '+(u.device_id||'-')+' | expires '+(u.expires_at?new Date(u.expires_at*1000).toISOString().slice(0,10):'never');
  c.appendChild(a);
  d.payments.forEach(p=>{const x=document.createElement('div');x.textContent='Pay: Level '+p.tier+' '+p.method+' '+(p.method==='cbe'?(p.payer_name+' '+p.payer_last4+' '+p.amount):p.txn_id)+' '+p.status;c.appendChild(x)});
  const sel=document.createElement('select');sel.style.cssText='font-size:16px;padding:10px;width:100%';
  [0,2,3,4,5].forEach(n=>{const o=document.createElement('option');o.value=n;o.textContent='Set to Level '+n;if(n===u.tier)o.selected=true;sel.appendChild(o)});
  const set=document.createElement('button');set.textContent='Apply level';
  set.onclick=async()=>{if(!confirm('Set +'+u.phone+' to Level '+sel.value+'?'))return;const r=await call('/admin/set_tier',{phone:u.phone,tier:Number(sel.value)});el.textContent=r.error||'Done';};
  const rv=document.createElement('button');rv.textContent='Revoke and wipe phone';rv.className='no';
  rv.onclick=async()=>{if(!confirm('Revoke +'+u.phone+' and wipe their phone?'))return;const r=await call('/admin/revoke',{phone:u.phone});el.textContent=r.error||'Revoked';};
  const ex=document.createElement('button');ex.textContent='Extend 30 days';
  ex.onclick=async()=>{const r=await call('/admin/extend',{phone:u.phone,days:30});el.textContent=r.error||'Extended';};
  c.append(sel,set,ex,rv);
  el.appendChild(c);
}
async function mkCode(){
  const d=await call('/admin/code/create',{tier:Number(document.getElementById('ct').value),uses:Number(document.getElementById('cu').value)||1,days:Number(document.getElementById('cd').value)||0,note:document.getElementById('cn').value});
  const el=document.getElementById('clist');
  if(d.error){el.textContent=d.error;return}
  el.textContent='New code: '+d.code;
  const l=await call('/admin/code/list');
  (l.items||[]).forEach(i=>{const x=document.createElement('div');x.textContent=i.code+' | Level '+i.tier+' | left '+i.uses_left+(i.note?' | '+i.note:'');el.appendChild(x)});
}
async function reset(){
  const d=await call('/admin/reset',{phone:document.getElementById('ph').value});
  document.getElementById('out').textContent=d.recovery_code?('New code: '+d.recovery_code):d.error;
}
</script></body></html>`;

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });
    const path = new URL(request.url).pathname;
    try {
      if (path.startsWith("/gemini/")) return await handleRelay(request, env, "/relay/gemini" + path.slice(7));
      if (path.startsWith("/relay/")) return await handleRelay(request, env, path);
      if (request.method === "GET" && path.startsWith("/content/")) return await handleContent(request, env, path);
      if (request.method === "GET" && path === "/") return json({ ok: true });
      if (request.method === "GET" && path === "/pubkey") return json(publicJwk(env));
      if (request.method === "GET" && path === "/tiers") {
        try {
          return json(await getTiers(env));
        } catch {
          return fail("tiers_unavailable", 502);
        }
      }
      if (request.method === "GET" && path === "/admin") {
        return new Response(ADMIN_HTML, { headers: { "content-type": "text/html; charset=utf-8" } });
      }
      if (request.method === "POST") {
        if (path === "/register") return await handleRegister(request, env, ctx);
        if (path === "/status") return await handleStatus(request, env);
        if (path === "/move") return await handleMove(request, env);
        if (path === "/ack-wipe") return await handleAckWipe(request, env);
        if (path === "/redeem") return await handleRedeem(request, env, ctx);
        if (path === "/report") return await handleReport(request, env, ctx);
        if (path === "/trial") return await handleTrial(request, env);
        if (path.startsWith("/admin/")) return await handleAdmin(request, env, path);
      }
      return fail("not_found", 404);
    } catch (e) {
      return fail("server_error", 500);
    }
  }
};
