// Guess It! server: accounts, friends, stats and challenge inbox. No dependencies. Run: node server.js
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_FILE || path.join(__dirname, "data.json");
const ORIGIN = process.env.ALLOWED_ORIGIN || "*"; // e.g. https://jaxgames47.github.io

let db = { users: {}, sessions: {}, invites: {} };
try { db = JSON.parse(fs.readFileSync(DATA, "utf8")); } catch (e) {}
let timer = null;
const flush = () => { fs.writeFileSync(DATA + ".tmp", JSON.stringify(db)); fs.renameSync(DATA + ".tmp", DATA); };
const save = () => { clearTimeout(timer); timer = setTimeout(flush, 150); };
["SIGINT", "SIGTERM"].forEach(s => process.on(s, () => { try { flush(); } catch (e) {} process.exit(0); }));

const sha = s => crypto.createHash("sha256").update(s).digest("hex");
const scrypt = (pw, salt) => crypto.scryptSync(pw, salt, 64).toString("hex");
const fail = (status, message) => Object.assign(new Error(message), { status });
const send = (res, code, obj) => { res.writeHead(code, { "Content-Type": "application/json" }); res.end(JSON.stringify(obj)); };
const profile = u => ({ username: u.username, stats: u.stats, friends: u.friends });

const hits = {};
function limit(req) {
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();
  const h = hits[ip] = hits[ip] && hits[ip].reset > Date.now() ? hits[ip] : { n: 0, reset: Date.now() + 600000 };
  if (++h.n > 15) throw fail(429, "Too many attempts. Try again in a few minutes.");
}
function readBody(req) {
  return new Promise((ok, no) => {
    let d = "";
    req.on("data", c => { d += c; if (d.length > 10000) { no(fail(413, "Request too large")); req.destroy(); } });
    req.on("end", () => { try { ok(d ? JSON.parse(d) : {}); } catch (e) { no(fail(400, "Bad request")); } });
  });
}
function authed(req) {
  const t = (req.headers.authorization || "").replace("Bearer ", "");
  const s = db.sessions[sha(t)];
  if (!s || Date.now() - s.t > 60 * 864e5 || !db.users[s.u]) throw fail(401, "Please log in");
  return db.users[s.u];
}
function newSession(u) {
  const token = crypto.randomBytes(32).toString("hex");
  db.sessions[sha(token)] = { u: u.username, t: Date.now() };
  save();
  return { token, profile: profile(u) };
}

async function api(req, res, url) {
  const route = req.method + " " + url.pathname;
  if (route === "GET /api/ping") return send(res, 200, { ok: true });

  if (route === "POST /api/signup" || route === "POST /api/login") {
    limit(req);
    const b = await readBody(req), name = String(b.username || "").trim().toLowerCase(), pw = String(b.password || "");
    if (route.endsWith("signup")) {
      if (!/^[a-z0-9_]{3,16}$/.test(name)) throw fail(400, "Username: 3–16 letters, numbers or _");
      if (pw.length < 6 || pw.length > 100) throw fail(400, "Password needs at least 6 characters");
      if (db.users[name]) throw fail(409, "That username is taken");
      const salt = crypto.randomBytes(16).toString("hex");
      db.users[name] = { username: name, salt, hash: scrypt(pw, salt), stats: { g: 0, w: 0, st: 0, best: 0, dist: Array(8).fill(0) }, friends: [], created: Date.now() };
      return send(res, 200, newSession(db.users[name]));
    }
    const u = db.users[name];
    if (!u || !crypto.timingSafeEqual(Buffer.from(scrypt(pw, u.salt)), Buffer.from(u.hash))) throw fail(401, "Wrong username or password");
    return send(res, 200, newSession(u));
  }

  const me = authed(req);

  if (route === "POST /api/logout") {
    delete db.sessions[sha((req.headers.authorization || "").replace("Bearer ", ""))]; save();
    return send(res, 200, { ok: true });
  }
  if (route === "GET /api/me") return send(res, 200, profile(me));

  if (route === "POST /api/stats") {
    const b = await readBody(req), s = me.stats;
    s.g++;
    if (b.win) {
      const n = Math.round(+b.n);
      if (!(n >= 1 && n <= 8)) throw fail(400, "Bad guess count");
      s.w++; s.st++; s.best = Math.max(s.best, s.st); s.dist[n - 1] = (s.dist[n - 1] || 0) + 1;
    } else s.st = 0;
    save();
    return send(res, 200, profile(me));
  }

  if (route === "GET /api/friends") {
    return send(res, 200, { friends: me.friends.filter(n => db.users[n]).map(n => ({ username: n, stats: db.users[n].stats })) });
  }
  if (route === "POST /api/friends") {
    const n = String((await readBody(req)).username || "").trim().toLowerCase();
    if (!db.users[n]) throw fail(404, "No one has that username");
    if (n === me.username) throw fail(400, "That’s you!");
    if (me.friends.includes(n)) throw fail(409, "Already friends");
    if (me.friends.length >= 200) throw fail(400, "Friend list is full");
    me.friends.push(n); save();
    return send(res, 200, { ok: true });
  }

  if (route === "GET /api/invites") return send(res, 200, { invites: db.invites[me.username] || [] });
  if (route === "POST /api/invites") {
    const b = await readBody(req), to = String(b.to || "").trim().toLowerCase(), code = String(b.code || "");
    if (!db.users[to]) throw fail(404, "No one has that username");
    if (!/^w[A-Za-z0-9_-]{5,24}$/.test(code)) throw fail(400, "Bad invite code");
    const list = (db.invites[to] || []).filter(i => i.from !== me.username);
    list.push({ id: crypto.randomBytes(6).toString("hex"), from: me.username, code, ts: Date.now() });
    db.invites[to] = list.slice(-50); save();
    return send(res, 200, { ok: true });
  }
  if (req.method === "DELETE" && url.pathname.startsWith("/api/invites/")) {
    const id = url.pathname.split("/").pop();
    db.invites[me.username] = (db.invites[me.username] || []).filter(i => i.id !== id); save();
    return send(res, 200, { ok: true });
  }
  throw fail(404, "Not found");
}

http.createServer(async (req, res) => {
  res.setHeader("Access-Control-Allow-Origin", ORIGIN);
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  if (req.method === "OPTIONS") { res.writeHead(204); return res.end(); }
  const url = new URL(req.url, "http://localhost");
  if (url.pathname.startsWith("/api/")) {
    try { await api(req, res, url); } catch (e) { send(res, e.status || 500, { error: e.status ? e.message : "Server error" }); }
    return;
  }
  // Everything else serves the game, so invite links like /wABC123 work too.
  fs.readFile(path.join(__dirname, "index.html"), (err, html) => {
    if (err) { res.writeHead(404); return res.end("index.html missing"); }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" }); res.end(html);
  });
}).listen(PORT, () => console.log("Guess It! running on port " + PORT));
