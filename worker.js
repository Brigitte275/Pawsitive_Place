// Pawsitive Places – live animals backend (Cloudflare Worker)
// Returns the adoptable animals (name, kind, breed, age group, gender, size, photo) for a shelter.
// Your Petfinder key and secret stay private here and are never put in the web page.
//
// Setup:
//   1. Request a free API key + secret at https://www.petfinder.com/developers/
//   2. Create a Cloudflare Worker (free), paste this file in as the worker code.
//   3. Add two secrets to the Worker: PF_KEY (your Client ID) and PF_SECRET.
//      Optional variable: ALLOWED_ORIGIN = your website address (so only your site can use it).
//   3b. For SIGN-IN: create a KV namespace (Workers > KV), bind it to the Worker with the variable name USERS,
//       and add a secret SESSION_SECRET (any long random string, 32+ characters).
//   3c. STORES PAGE (/places): needs no key. It uses free OpenStreetMap data (Overpass API) to list nearby
//       pet stores, vet clinics and feed & farm stores. Keep the credit "OpenStreetMap contributors" on the page.
//   4. Deploy, copy the Worker URL, and paste it into  const API=""  in index.html.
//   3d. REPORT A PROBLEM (/report): reports are saved in the same USERS KV (keys starting "r:", kept 90 days).
//       Optional email alerts: add secrets RESEND_KEY (free at resend.com) and variable REPORT_TO = your email.
// Notes: Petfinder gives an age GROUP (Baby, Young, Adult, Senior), not exact years.
//        Only shelters registered with Petfinder will have animals to show.

let token = null, expires = 0;

async function getToken(env) {
  if (token && Date.now() < expires) return token;
  const r = await fetch("https://api.petfinder.com/v2/oauth2/token", {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ grant_type: "client_credentials", client_id: env.PF_KEY, client_secret: env.PF_SECRET }),
  });
  if (!r.ok) throw new Error("token " + r.status);
  const j = await r.json();
  token = j.access_token;
  expires = Date.now() + (j.expires_in - 120) * 1000;
  return token;
}

const norm = (s) => String(s || "").toLowerCase().replace(/[^a-z0-9]/g, "");

// ---- accounts: PBKDF2 password hashes + signed session tokens ----
const enc = new TextEncoder();
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
async function hashPw(pw, salt) {
  const k = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return b64(await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: 100000 }, k, 256));
}
const hmacKey = (env) => crypto.subtle.importKey("raw", enc.encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
async function makeToken(env, email) {
  const p = b64(enc.encode(JSON.stringify({ e: email, x: Date.now() + 30 * 864e5 })));
  return p + "." + b64(await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(p)));
}
async function readToken(env, tok) {
  const [p, s] = String(tok || "").split(".");
  if (!p || !s) return null;
  try {
    if (!(await crypto.subtle.verify("HMAC", await hmacKey(env), unb64(s), enc.encode(p)))) return null;
    const o = JSON.parse(new TextDecoder().decode(unb64(p)));
    return o.x > Date.now() ? o.e : null;
  } catch (e) { return null; }
}
const json = (o, status, cors) => new Response(JSON.stringify(o), { status: status || 200, headers: cors });

// ---- nearby stores from OpenStreetMap ----
const KINDS = {
  pet: (r, la, lo) => `nwr["shop"="pet"](around:${r},${la},${lo});`,
  vet: (r, la, lo) => `nwr["amenity"="veterinary"](around:${r},${la},${lo});`,
  feed: (r, la, lo) => `nwr["shop"="agrarian"](around:${r},${la},${lo});nwr["shop"]["name"~"feed|tractor supply|farm (and|&) ranch|co-?op",i](around:${r},${la},${lo});`,
};
const miles = (a, b, c, d) => {
  const r = Math.PI / 180, x = (c - a) * r, y = (d - b) * r;
  const h = Math.sin(x / 2) ** 2 + Math.cos(a * r) * Math.cos(c * r) * Math.sin(y / 2) ** 2;
  return 3958.8 * 2 * Math.asin(Math.sqrt(h));
};
async function nearby(kind, la, lo) {
  for (const r of [15000, 40000, 80000]) {
    const q = "[out:json][timeout:20];(" + KINDS[kind](r, la, lo) + ");out center 80;";
    const res = await fetch("https://overpass-api.de/api/interpreter?data=" + encodeURIComponent(q), { cf: { cacheTtl: 3600, cacheEverything: true } });
    if (!res.ok) throw new Error("overpass " + res.status);
    const seen = new Set();
    const out = ((await res.json()).elements || []).map((e) => {
      const t = e.tags || {}, y = e.lat != null ? e.lat : e.center && e.center.lat, x = e.lon != null ? e.lon : e.center && e.center.lon;
      if (!t.name || y == null || x == null) return null;
      const k = norm(t.name) + y.toFixed(3) + x.toFixed(3);
      if (seen.has(k)) return null;
      seen.add(k);
      return {
        n: t.name,
        ad: [t["addr:housenumber"], t["addr:street"]].filter(Boolean).join(" "),
        c: t["addr:city"] || "", st: t["addr:state"] || "", zip: t["addr:postcode"] || "",
        ph: t.phone || t["contact:phone"] || "", web: t.website || t["contact:website"] || "",
        hrs: t.opening_hours || "", em: t.emergency === "yes", la: y, lo: x,
        d: miles(la, lo, y, x),
      };
    }).filter(Boolean).sort((p, q) => p.d - q.d).slice(0, 30);
    if (out.length >= 6 || r === 80000) return out;
  }
  return [];
}

export default {
  async fetch(req, env) {
    const cors = { "Access-Control-Allow-Origin": env.ALLOWED_ORIGIN || "*", "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Allow-Headers": "Content-Type, Authorization", "Content-Type": "application/json" };
    if (req.method === "OPTIONS") return new Response(null, { headers: cors });
    const u = new URL(req.url);
    if (u.pathname === "/locate") {
      // Rough location from the visitor's internet connection (Cloudflare provides it; nothing is stored or logged).
      const cf = req.cf || {}, h = { ...cors, "Cache-Control": "no-store" };
      if (!cf.country) return json({ error: "Location isn't available." }, 200, h);
      const la = parseFloat(cf.latitude), lo = parseFloat(cf.longitude);
      return json({ us: cf.country === "US", city: cf.city || "", region: cf.regionCode || "", la: isNaN(la) ? null : la, lo: isNaN(lo) ? null : lo }, 200, h);
    }
    if (u.pathname === "/signup" || u.pathname === "/signin") {
      if (req.method !== "POST") return json({ error: "POST only" }, 405, cors);
      if (!env.USERS || !env.SESSION_SECRET) return json({ error: "Sign-in isn't set up on the server yet." }, 503, cors);
      let b;
      try { b = await req.json(); } catch (e) { return json({ error: "Bad request." }, 400, cors); }
      const email = String(b.email || "").trim().toLowerCase(), pw = String(b.password || "");
      if (email.length > 254 || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return json({ error: "Please enter a valid email address." }, 400, cors);
      const key = "u:" + email, ex = await env.USERS.get(key, "json");
      if (u.pathname === "/signup") {
        if (pw.length < 8 || pw.length > 128) return json({ error: "Password must be 8 to 128 characters." }, 400, cors);
        if (ex) return json({ error: "An account with that email already exists. Try signing in." }, 409, cors);
        const salt = crypto.getRandomValues(new Uint8Array(16));
        const name = String(b.name || "").trim().slice(0, 40) || email.split("@")[0];
        await env.USERS.put(key, JSON.stringify({ name, salt: b64(salt), hash: await hashPw(pw, salt) }));
        return json({ token: await makeToken(env, email), name }, 200, cors);
      }
      if (!ex || (await hashPw(pw, unb64(ex.salt))) !== ex.hash) return json({ error: "Incorrect email or password." }, 401, cors);
      return json({ token: await makeToken(env, email), name: ex.name }, 200, cors);
    }
    if (u.pathname === "/me") {
      if (!env.USERS || !env.SESSION_SECRET) return json({ error: "not set up" }, 503, cors);
      const email = await readToken(env, (req.headers.get("Authorization") || "").replace(/^Bearer /, ""));
      const ex = email && (await env.USERS.get("u:" + email, "json"));
      return ex ? json({ name: ex.name, email }, 200, cors) : json({ error: "Please sign in again." }, 401, cors);
    }
    if (u.pathname === "/report") {
      if (req.method !== "POST") return json({ error: "POST only" }, 405, cors);
      let b;
      try { b = await req.json(); } catch (e) { return json({ error: "Bad request." }, 400, cors); }
      if (b.website || b.hp) return json({ ok: true }, 200, cors); // hidden field filled in = a bot; pretend success
      const clip = (v, n) => String(v || "").trim().slice(0, n);
      const r = { listing: clip(b.listing, 120), city: clip(b.city, 60), state: clip(b.state, 2), message: clip(b.message, 1500), email: clip(b.contact || b.email, 254), at: new Date().toISOString() };
      if (r.message.length < 5) return json({ error: "Please tell us what is wrong." }, 400, cors);
      if (r.email && !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(r.email)) return json({ error: "That email address doesn't look right." }, 400, cors);
      if (!env.USERS && !(env.RESEND_KEY && env.REPORT_TO)) return json({ error: "Reports aren't set up on the server yet." }, 503, cors);
      // simple limit: 5 reports per hour per visitor
      const ip = req.headers.get("CF-Connecting-IP") || "x";
      if (env.USERS) {
        const rk = "rl:" + b64(await crypto.subtle.digest("SHA-256", enc.encode(ip))).slice(0, 16), n = parseInt((await env.USERS.get(rk)) || "0", 10);
        if (n >= 5) return json({ error: "Too many reports. Please try again later." }, 429, cors);
        await env.USERS.put(rk, String(n + 1), { expirationTtl: 3600 });
        await env.USERS.put("r:" + Date.now() + "-" + b64(crypto.getRandomValues(new Uint8Array(4))), JSON.stringify(r), { expirationTtl: 90 * 864e2 });
      }
      if (env.RESEND_KEY && env.REPORT_TO) {
        try {
          await fetch("https://api.resend.com/emails", {
            method: "POST",
            headers: { Authorization: "Bearer " + env.RESEND_KEY, "Content-Type": "application/json" },
            body: JSON.stringify({ from: env.REPORT_FROM || "Pawsitive Places <onboarding@resend.dev>", to: [env.REPORT_TO], reply_to: r.email || undefined, subject: "Listing problem: " + r.listing, text: r.listing + " (" + r.city + ", " + r.state + ")\n\n" + r.message + "\n\nReply-to: " + (r.email || "not given") }),
          });
        } catch (e) { /* the report is already saved */ }
      }
      return json({ ok: true }, 200, cors);
    }
    if (u.pathname === "/places") {
      const kind = u.searchParams.get("kind"), la = parseFloat(u.searchParams.get("lat")), lo = parseFloat(u.searchParams.get("lng"));
      if (!KINDS[kind] || !isFinite(la) || !isFinite(lo)) return json({ error: "kind, lat and lng required" }, 400, cors);
      if (la < 17 || la > 72 || lo < -180 || lo > -64) return json({ places: [], error: "US locations only" }, 400, cors);
      try { return json({ places: await nearby(kind, la, lo) }, 200, cors); }
      catch (e) { return json({ places: [], error: String(e.message || e) }, 502, cors); }
    }
    if (u.pathname !== "/animals") return new Response('{"error":"not found"}', { status: 404, headers: cors });
    const name = u.searchParams.get("name") || "";
    const state = (u.searchParams.get("state") || "").slice(0, 2).toUpperCase();
    if (!name) return new Response('{"error":"name required"}', { status: 400, headers: cors });

    try {
      const t = await getToken(env);
      const pf = async (path) => {
        const r = await fetch("https://api.petfinder.com/v2" + path, { headers: { Authorization: "Bearer " + t }, cf: { cacheTtl: 300 } });
        if (!r.ok) throw new Error("petfinder " + r.status);
        return r.json();
      };
      // 1) find the shelter on Petfinder by name (and state when we have one)
      const q = "/organizations?limit=10&country=US&name=" + encodeURIComponent(name) + (state ? "&state=" + state : "");
      const orgs = (await pf(q)).organizations || [];
      const org = orgs.find((o) => norm(o.name) === norm(name)) || orgs[0];
      if (!org) return new Response(JSON.stringify({ animals: [] }), { headers: cors });
      // 2) get its adoptable animals
      const a = (await pf("/animals?status=adoptable&limit=24&organization=" + encodeURIComponent(org.id))).animals || [];
      const animals = a.map((x) => ({
        name: x.name,
        type: x.species || x.type,
        breed: ((x.breeds && x.breeds.primary) || "Unknown breed") + (x.breeds && x.breeds.mixed ? " mix" : ""),
        age: x.age,
        gender: x.gender,
        size: x.size,
        photo: x.photos && x.photos[0] ? x.photos[0].medium || x.photos[0].small : "",
      }));
      return new Response(JSON.stringify({ shelter: org.name, animals }), { headers: cors });
    } catch (e) {
      return new Response(JSON.stringify({ animals: [], error: String(e.message || e) }), { status: 502, headers: cors });
    }
  },
};
