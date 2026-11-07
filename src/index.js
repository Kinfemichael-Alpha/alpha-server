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
    const u = await env.DB.prepare("SELECT tier, status, device_id FROM users WHERE phone = ?").bind(p.p).first();
    if (!u || u.status !== "active" || u.device_id !== p.d) return null;
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

async function handleGemini(request, env, path) {
  const p = await relayUser(request, env);
  if (!p) return fail("relay_denied", 401);
  const keys = String(env.GEMINI_KEYS || "").split(",").map((k) => k.trim()).filter(Boolean);
  if (!keys.length) return fail("relay_unavailable", 503);
  const rest = path.slice("/gemini".length);
  if (!/^\/models(\/[A-Za-z0-9._-]+:(generateContent|streamGenerateContent))?$/.test(rest)) return fail("not_found", 404);
  const src = new URL(request.url).searchParams;
  const q = new URLSearchParams();
  if (src.get("alt") === "sse") q.set("alt", "sse");
  if (/^\d{1,3}$/.test(src.get("pageSize") || "")) q.set("pageSize", src.get("pageSize"));
  const upstream = "https://generativelanguage.googleapis.com/v1beta" + rest + (q.toString() ? "?" + q.toString() : "");
  let body;
  if (request.method === "POST") {
    body = await request.arrayBuffer();
    if (body.byteLength > 2000000) return fail("too_large", 413);
  } else if (request.method !== "GET") {
    return fail("not_found", 404);
  }
  const start = Math.floor(Math.random() * keys.length);
  const tries = Math.min(3, keys.length);
  let last = null;
  for (let i = 0; i < tries; i++) {
    const key = keys[(start + i) % keys.length];
    const res = await fetch(upstream, {
      method: request.method,
      headers: { "content-type": "application/json", "x-goog-api-key": key },
      body
    });
    last = res;
    if (res.status === 429 || res.status === 401 || res.status === 403) continue;
    break;
  }
  return new Response(last.body, {
    status: last.status,
    headers: { "content-type": last.headers.get("content-type") || "application/json" }
  });
}

async function handleRegister(request, env, ctx) {
  const b = await readBody(request);
  const phone = normPhone(b.phone);
  const tier = Number(b.tier);
  const txn = String(b.txn_id || "").trim().toUpperCase();
  const method = b.method === "telebirr" ? "telebirr" : b.method === "cbe" ? "cbe" : null;
  if (!phone) return fail("bad_phone");
  if (!validDevice(b.device_id)) return fail("bad_device");
  if (![2, 3, 4, 5].includes(tier)) return fail("bad_tier");
  if (!/^[A-Z0-9]{6,32}$/.test(txn)) return fail("bad_txn");
  if (!method) return fail("bad_method");

  const user = await env.DB.prepare("SELECT * FROM users WHERE phone = ?").bind(phone).first();
  if (user && user.status === "active" && user.device_id !== b.device_id) {
    return fail("already_registered", 409);
  }
  if (user && user.status === "active" && tier <= user.tier) {
    return fail("not_an_upgrade", 409);
  }
  const pending = await env.DB.prepare(
    "SELECT id FROM payments WHERE phone = ? AND status = 'pending'"
  ).bind(phone).first();
  if (pending) return fail("payment_pending", 409);

  const t = now();
  try {
    await env.DB.batch([
      env.DB.prepare(
        "INSERT INTO users (phone, tier, status, device_id, created_at) VALUES (?, 0, 'pending', ?, ?) " +
          "ON CONFLICT(phone) DO UPDATE SET device_id = CASE WHEN users.status = 'active' THEN users.device_id ELSE excluded.device_id END"
      ).bind(phone, b.device_id, t),
      env.DB.prepare(
        "INSERT INTO payments (phone, device_id, tier, txn_id, method, created_at) VALUES (?, ?, ?, ?, ?, ?)"
      ).bind(phone, b.device_id, tier, txn, method, t),
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
      await notify(env, "New payment\n+" + phone + "\n" + label + "\nVia " + method + "\nTxn: " + txn + "\n" + origin + "/admin");
    })()
  );
  return json({ state: "pending" });
}

async function handleStatus(request, env) {
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
  if (user.status === "pending") return json({ state: "pending" });

  const out = { state: "active", tier: user.tier };
  if (user.recovery_plain) {
    out.recovery_code = user.recovery_plain;
    await env.DB.prepare("UPDATE users SET recovery_plain = NULL WHERE phone = ?")
      .bind(phone)
      .run();
  }
  const tk = await makeToken(env, phone, b.device_id, user.tier);
  out.token = tk.token;
  out.exp = tk.exp;
  return json(out);
}

async function handleMove(request, env) {
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
  const tk = await makeToken(env, phone, b.device_id, user.tier);
  return json({ state: "active", tier: user.tier, token: tk.token, exp: tk.exp, recovery_code: code });
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

async function handleAdmin(request, env, path) {
  if (!sameSecret(request.headers.get("x-admin-key") || "", env.ADMIN_KEY || "")) {
    return fail("unauthorized", 401);
  }
  const b = request.method === "POST" ? await readBody(request) : {};

  if (path === "/admin/pending") {
    const rows = await env.DB.prepare(
      "SELECT id, phone, tier, txn_id, method, created_at FROM payments WHERE status = 'pending' ORDER BY id"
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
    const stmts = [
      env.DB.prepare("UPDATE payments SET status = 'approved', tier = ?, decided_at = ? WHERE id = ?").bind(tier, now(), p.id)
    ];
    if (user && user.recovery_hash) {
      stmts.push(
        env.DB.prepare("UPDATE users SET tier = ?, status = 'active' WHERE phone = ?").bind(p.tier, p.phone)
      );
    } else {
      const code = newRecoveryCode();
      const h = await hashRecovery(p.phone, code);
      stmts.push(
        env.DB.prepare(
          "UPDATE users SET tier = ?, status = 'active', recovery_hash = ?, recovery_plain = ?, fails = 0 WHERE phone = ?"
        ).bind(p.tier, h, code, p.phone)
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
    const t3=document.createElement('div');t3.textContent=p.method+' | Txn: '+p.txn_id;
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
      if (path.startsWith("/gemini/")) return await handleGemini(request, env, path);
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
        if (path === "/trial") return await handleTrial(request, env);
        if (path.startsWith("/admin/")) return await handleAdmin(request, env, path);
      }
      return fail("not_found", 404);
    } catch (e) {
      return fail("server_error", 500);
    }
  }
};
