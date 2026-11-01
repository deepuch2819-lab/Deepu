require('dotenv').config();
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const {
  FB_APP_ID, FB_APP_SECRET, BASE_URL, APP_PASSWORD, SESSION_SECRET,
  PORT = 3000, GRAPH_VERSION = 'v21.0',
} = process.env;

for (const k of ['FB_APP_ID', 'FB_APP_SECRET', 'BASE_URL', 'APP_PASSWORD', 'SESSION_SECRET']) {
  if (!process.env[k]) { console.error(`.env mein ${k} missing hai`); process.exit(1); }
}

const GRAPH = `https://graph.facebook.com/${GRAPH_VERSION}`;
const DATA_DIR = path.join(__dirname, 'data');
const TMP_DIR = path.join(__dirname, 'tmp');
const STORE = path.join(DATA_DIR, 'pages.json');
fs.mkdirSync(DATA_DIR, { recursive: true });
fs.mkdirSync(TMP_DIR, { recursive: true });

// ---------- storage (connected pages + tokens) ----------
const loadPages = () => { try { return JSON.parse(fs.readFileSync(STORE, 'utf8')); } catch { return []; } };
const savePages = (p) => fs.writeFileSync(STORE, JSON.stringify(p, null, 2));

// ---------- app ----------
const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(session({
  secret: SESSION_SECRET, resave: false, saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: BASE_URL.startsWith('https'), maxAge: 1000 * 60 * 60 * 24 * 14 },
}));

const upload = multer({ dest: TMP_DIR, limits: { fileSize: 1024 * 1024 * 1024 } });
const auth = (req, res, next) => (req.session.ok ? next() : res.status(401).json({ error: 'Login karo' }));

// ---------- site login ----------
const attempts = new Map();
app.post('/api/login', (req, res) => {
  const ip = req.ip, a = attempts.get(ip) || { n: 0, t: Date.now() };
  if (Date.now() - a.t > 15 * 60e3) { a.n = 0; a.t = Date.now(); }
  if (a.n >= 8) return res.status(429).json({ error: 'Bahut try ho gaye, 15 min baad aana' });
  const given = Buffer.from(String(req.body.password || ''));
  const real = Buffer.from(APP_PASSWORD);
  const ok = given.length === real.length && crypto.timingSafeEqual(given, real);
  if (!ok) { a.n++; attempts.set(ip, a); return res.status(401).json({ error: 'Password galat hai' }); }
  req.session.ok = true;
  res.json({ ok: true });
});
app.post('/api/logout', (req, res) => req.session.destroy(() => res.json({ ok: true })));
app.get('/api/me', (req, res) => res.json({ loggedIn: !!req.session.ok }));

// ---------- facebook connect ----------
app.get('/auth/facebook', (req, res) => {
  if (!req.session.ok) return res.redirect('/');
  const state = crypto.randomBytes(16).toString('hex');
  req.session.fbState = state;
  const q = new URLSearchParams({
    client_id: FB_APP_ID,
    redirect_uri: `${BASE_URL}/auth/facebook/callback`,
    state,
    scope: 'pages_show_list,pages_manage_posts,pages_read_engagement',
  });
  res.redirect(`https://www.facebook.com/${GRAPH_VERSION}/dialog/oauth?${q}`);
});

async function gget(url) {
  const r = await fetch(url);
  const j = await r.json();
  if (j.error) throw new Error(j.error.message);
  return j;
}

app.get('/auth/facebook/callback', async (req, res) => {
  try {
    if (!req.session.ok) return res.redirect('/');
    if (!req.query.code || req.query.state !== req.session.fbState) throw new Error('Login cancel hua ya state match nahi hui');
    const redirect_uri = `${BASE_URL}/auth/facebook/callback`;

    const short = await gget(`${GRAPH}/oauth/access_token?` + new URLSearchParams({
      client_id: FB_APP_ID, client_secret: FB_APP_SECRET, redirect_uri, code: req.query.code,
    }));
    const long = await gget(`${GRAPH}/oauth/access_token?` + new URLSearchParams({
      grant_type: 'fb_exchange_token', client_id: FB_APP_ID, client_secret: FB_APP_SECRET,
      fb_exchange_token: short.access_token,
    }));

    // Long-lived user token se mile Page tokens expire nahi hote
    let url = `${GRAPH}/me/accounts?` + new URLSearchParams({
      fields: 'id,name,access_token,picture{url}', limit: '100', access_token: long.access_token,
    });
    const pages = [];
    while (url) {
      const j = await gget(url);
      for (const p of j.data) pages.push({ id: p.id, name: p.name, token: p.access_token, picture: p.picture?.data?.url || '' });
      url = j.paging?.next || null;
    }
    savePages(pages);
    res.redirect('/?connected=' + pages.length);
  } catch (e) {
    res.redirect('/?error=' + encodeURIComponent(e.message));
  }
});

app.get('/api/pages', auth, (req, res) => {
  res.json(loadPages().map(({ token, ...p }) => p));
});
app.post('/api/pages/clear', auth, (req, res) => { savePages([]); res.json({ ok: true }); });

// ---------- reel upload ----------
async function fjson(url, opts) {
  const r = await fetch(url, opts);
  const j = await r.json().catch(() => ({}));
  if (j.error) throw new Error(j.error.message || 'Facebook error');
  return j;
}

async function postReel(page, buf, caption) {
  // Step 1: start
  const start = await fjson(`${GRAPH}/${page.id}/video_reels`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ upload_phase: 'start', access_token: page.token }),
  });
  // Step 2: video bytes upload
  const up = await fjson(start.upload_url, {
    method: 'POST',
    headers: { Authorization: `OAuth ${page.token}`, offset: '0', file_size: String(buf.length) },
    body: buf,
  });
  if (!up.success) throw new Error('Video upload fail hua');
  // Step 3: finish + publish
  const fin = await fjson(`${GRAPH}/${page.id}/video_reels`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      upload_phase: 'finish', video_id: start.video_id, video_state: 'PUBLISHED',
      description: caption || '', access_token: page.token,
    }),
  });
  if (!fin.success) throw new Error('Publish fail hua');
  return start.video_id;
}

const jobs = new Map();
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

app.post('/api/upload', auth, upload.single('video'), (req, res) => {
  const file = req.file;
  try {
    if (!file) return res.status(400).json({ error: 'Video select karo' });
    const ids = JSON.parse(req.body.pages || '[]');
    const all = loadPages();
    const chosen = all.filter((p) => ids.includes(p.id));
    if (!chosen.length) { fs.unlink(file.path, () => {}); return res.status(400).json({ error: 'Kam se kam ek Page chuno' }); }

    const caption = req.body.caption || '';
    const delay = Math.max(0, Math.min(600, Number(req.body.delay) || 0)) * 1000;
    const id = crypto.randomBytes(8).toString('hex');
    const job = { id, done: false, items: chosen.map((p) => ({ id: p.id, name: p.name, status: 'waiting', message: '' })) };
    jobs.set(id, job);
    res.json({ jobId: id });

    (async () => {
      const buf = await fs.promises.readFile(file.path);
      for (let i = 0; i < chosen.length; i++) {
        const it = job.items[i];
        it.status = 'uploading';
        try {
          const vid = await postReel(chosen[i], buf, caption);
          it.status = 'done'; it.message = 'Video ID: ' + vid;
        } catch (e) {
          it.status = 'failed'; it.message = e.message;
        }
        if (delay && i < chosen.length - 1) await sleep(delay);
      }
      job.done = true;
      fs.unlink(file.path, () => {});
      setTimeout(() => jobs.delete(id), 60 * 60e3);
    })();
  } catch (e) {
    if (file) fs.unlink(file.path, () => {});
    res.status(400).json({ error: e.message });
  }
});

app.get('/api/jobs/:id', auth, (req, res) => {
  const j = jobs.get(req.params.id);
  j ? res.json(j) : res.status(404).json({ error: 'Job nahi mila' });
});

app.get('/', (req, res) => res.type('html').send(HTML));
app.listen(PORT, () => console.log(`Chal raha hai: ${BASE_URL} (port ${PORT})`));


const HTML = `<!DOCTYPE html>
<html lang="hi">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reel Poster</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@500;700&family=Hanken+Grotesk:wght@400;500;600&display=swap" rel="stylesheet">
<style>
:root{
  --bg:#f3f5f1; --card:#ffffff; --ink:#16231c; --muted:#5d6b63; --line:#dbe2dc;
  --accent:#0e6b4f; --accent-ink:#ffffff; --warn:#b3261e; --ok:#17794f; --soft:#e5efe9;
}
@media (prefers-color-scheme:dark){
  :root{--bg:#101712; --card:#18211b; --ink:#e8efe9; --muted:#97a69c; --line:#2a372d; --accent:#4cc79a; --accent-ink:#0b1a13; --warn:#ff8a80; --ok:#5fd6a0; --soft:#1f2d24;}
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.5 "Hanken Grotesk",system-ui,sans-serif}
h1,h2{font-family:"Bricolage Grotesque",system-ui,sans-serif;margin:0;letter-spacing:-.01em}
h1{font-size:1.6rem} h2{font-size:1.15rem}
.wrap{max-width:760px;margin:0 auto;padding:20px 16px 60px}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px}
.card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:18px;margin-bottom:16px}
.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.sp{justify-content:space-between}
button,.btn{font:inherit;font-weight:600;border:0;border-radius:10px;padding:10px 16px;cursor:pointer;background:var(--accent);color:var(--accent-ink);text-decoration:none;display:inline-block}
button.ghost,.btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}
button:disabled{opacity:.5;cursor:not-allowed}
:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
input[type=text],input[type=password],input[type=number],textarea{width:100%;font:inherit;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background:var(--bg);color:var(--ink)}
textarea{min-height:90px;resize:vertical}
label.f{display:block;font-weight:600;margin:14px 0 6px}
.muted{color:var(--muted);font-size:.92rem}
.drop{border:2px dashed var(--line);border-radius:12px;padding:22px;text-align:center;cursor:pointer;background:var(--bg)}
.drop.has{border-style:solid;border-color:var(--accent);background:var(--soft)}
.pages{display:grid;grid-template-columns:repeat(auto-fill,minmax(210px,1fr));gap:8px;margin-top:12px}
.pg{display:flex;gap:10px;align-items:center;border:1px solid var(--line);border-radius:10px;padding:8px 10px;cursor:pointer;background:var(--bg)}
.pg:has(input:checked){border-color:var(--accent);background:var(--soft)}
.pg img{width:34px;height:34px;border-radius:50%;object-fit:cover;background:var(--line)}
.pg span{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;flex:1}
.pg input{width:18px;height:18px;accent-color:var(--accent)}
.err{color:var(--warn);font-weight:500;margin-top:10px}
.res{display:flex;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid var(--line)}
.res:last-child{border:0}
.st{font-weight:600;white-space:nowrap}
.st.done{color:var(--ok)} .st.failed{color:var(--warn)} .st.uploading{color:var(--accent)}
.bar{height:6px;background:var(--line);border-radius:6px;overflow:hidden;margin-top:12px}
.bar i{display:block;height:100%;background:var(--accent);width:0;transition:width .3s}
.hide{display:none!important}
</style>
</head>
<body>
<div class="wrap">

<!-- Login -->
<div id="loginView" class="hide">
  <div class="card" style="max-width:380px;margin:12vh auto 0">
    <h1>Reel Poster</h1>
    <p class="muted">Apna password daalo.</p>
    <input type="password" id="pw" placeholder="Password" autocomplete="current-password">
    <div class="row" style="margin-top:12px"><button id="loginBtn">Login</button></div>
    <div class="err" id="loginErr"></div>
  </div>
</div>

<!-- App -->
<div id="appView" class="hide">
  <header>
    <h1>Reel Poster</h1>
    <button class="ghost" id="logoutBtn">Logout</button>
  </header>

  <div id="notice" class="card hide"></div>

  <div class="card">
    <div class="row sp">
      <div>
        <h2>1. Facebook Pages</h2>
        <div class="muted" id="pageCount">Koi Page connected nahi hai</div>
      </div>
      <a class="btn" href="/auth/facebook" id="connectBtn">Facebook se connect karo</a>
    </div>
  </div>

  <div class="card">
    <h2>2. Reel</h2>
    <label class="drop" id="drop" for="file" style="display:block;margin-top:12px">
      <div id="dropText">Video chuno (MP4, vertical 9:16, 3 se 90 sec)</div>
    </label>
    <input type="file" id="file" accept="video/mp4,video/quicktime" class="hide">
    <label class="f" for="caption">Caption</label>
    <textarea id="caption" placeholder="Reel ka caption aur hashtags"></textarea>
  </div>

  <div class="card">
    <div class="row sp">
      <h2>3. Kin Pages par daalna hai</h2>
      <div class="row">
        <button class="ghost" id="allBtn">Sab chuno</button>
        <button class="ghost" id="noneBtn">Sab hatao</button>
      </div>
    </div>
    <div class="pages" id="pages"></div>
    <label class="f" for="delay">Do Pages ke beech gap (seconds)</label>
    <input type="number" id="delay" value="30" min="0" max="600" style="max-width:140px">
    <div class="muted" style="margin-top:6px">Gap rakhna safe rehta hai, Facebook ek saath bahut posts ko spam maan sakta hai.</div>
  </div>

  <div class="card">
    <button id="goBtn">Upload karo</button>
    <span class="muted" id="selCount" style="margin-left:10px"></span>
    <div class="bar hide" id="bar"><i id="barFill"></i></div>
    <div class="err" id="err"></div>
    <div id="results" style="margin-top:8px"></div>
  </div>
</div>
</div>

<script>
const $ = (id) => document.getElementById(id);
let pages = [], file = null;

async function api(url, opts) {
  const r = await fetch(url, opts);
  const j = await r.json().catch(() => ({}));
  if (r.status === 401 && url !== '/api/login') { show(false); throw new Error(j.error || 'Login karo'); }
  if (!r.ok) throw new Error(j.error || 'Kuch gadbad hui');
  return j;
}
function show(loggedIn) {
  $('loginView').classList.toggle('hide', loggedIn);
  $('appView').classList.toggle('hide', !loggedIn);
}

$('loginBtn').onclick = async () => {
  $('loginErr').textContent = '';
  try { await api('/api/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: $('pw').value }) }); init(); }
  catch (e) { $('loginErr').textContent = e.message; }
};
$('pw').addEventListener('keydown', (e) => e.key === 'Enter' && $('loginBtn').click());
$('logoutBtn').onclick = async () => { await api('/api/logout', { method: 'POST' }); show(false); };

function renderPages() {
  $('pageCount').textContent = pages.length ? \`\${pages.length} Pages connected\` : 'Koi Page connected nahi hai';
  $('connectBtn').textContent = pages.length ? 'Pages dobara sync karo' : 'Facebook se connect karo';
  $('pages').innerHTML = pages.map((p) =>
    \`<label class="pg"><input type="checkbox" value="\${p.id}"><img src="\${p.picture}" alt=""><span></span></label>\`).join('');
  [...$('pages').children].forEach((el, i) => { el.querySelector('span').textContent = pages[i].name; el.querySelector('input').onchange = updateSel; });
  updateSel();
}
const boxes = () => [...$('pages').querySelectorAll('input')];
function updateSel() {
  const n = boxes().filter((b) => b.checked).length;
  $('selCount').textContent = n ? \`\${n} Pages chune hain\` : '';
}
$('allBtn').onclick = () => { boxes().forEach((b) => (b.checked = true)); updateSel(); };
$('noneBtn').onclick = () => { boxes().forEach((b) => (b.checked = false)); updateSel(); };

$('file').onchange = (e) => {
  file = e.target.files[0] || null;
  $('drop').classList.toggle('has', !!file);
  $('dropText').textContent = file ? \`\${file.name} (\${(file.size / 1048576).toFixed(1)} MB)\` : 'Video chuno (MP4, vertical 9:16, 3 se 90 sec)';
};

$('goBtn').onclick = async () => {
  $('err').textContent = ''; $('results').innerHTML = '';
  const ids = boxes().filter((b) => b.checked).map((b) => b.value);
  if (!file) return ($('err').textContent = 'Pehle video chuno');
  if (!ids.length) return ($('err').textContent = 'Kam se kam ek Page chuno');
  const fd = new FormData();
  fd.append('video', file); fd.append('caption', $('caption').value);
  fd.append('pages', JSON.stringify(ids)); fd.append('delay', $('delay').value);
  $('goBtn').disabled = true; $('bar').classList.remove('hide'); $('barFill').style.width = '0';
  try {
    $('results').innerHTML = '<div class="muted">Video server par upload ho raha hai...</div>';
    const { jobId } = await api('/api/upload', { method: 'POST', body: fd });
    poll(jobId);
  } catch (e) { $('err').textContent = e.message; $('goBtn').disabled = false; $('bar').classList.add('hide'); }
};

const LABEL = { waiting: 'Intezaar', uploading: 'Upload ho raha hai', done: 'Ho gaya', failed: 'Fail' };
async function poll(id) {
  try {
    const j = await api('/api/jobs/' + id);
    const finished = j.items.filter((i) => i.status === 'done' || i.status === 'failed').length;
    $('barFill').style.width = (finished / j.items.length) * 100 + '%';
    $('results').innerHTML = '';
    j.items.forEach((i) => {
      const d = document.createElement('div'); d.className = 'res';
      const l = document.createElement('div'); const n = document.createElement('div'); n.textContent = i.name;
      const m = document.createElement('div'); m.className = 'muted'; m.textContent = i.message;
      l.append(n, m);
      const s = document.createElement('div'); s.className = 'st ' + i.status; s.textContent = LABEL[i.status];
      d.append(l, s); $('results').append(d);
    });
    if (j.done) { $('goBtn').disabled = false; return; }
    setTimeout(() => poll(id), 2000);
  } catch (e) { $('err').textContent = e.message; $('goBtn').disabled = false; }
}

async function init() {
  const { loggedIn } = await api('/api/me');
  show(loggedIn);
  if (!loggedIn) return;
  const q = new URLSearchParams(location.search);
  if (q.get('connected')) { $('notice').textContent = \`\${q.get('connected')} Pages connect ho gaye.\`; $('notice').classList.remove('hide'); }
  if (q.get('error')) { $('notice').textContent = 'Connect nahi hua: ' + q.get('error'); $('notice').classList.remove('hide'); }
  history.replaceState(null, '', '/');
  pages = await api('/api/pages'); renderPages();
}
init();
</script>
</body>
</html>
`;
