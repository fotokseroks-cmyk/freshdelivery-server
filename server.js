// ============================================================
// server_v7.js — сервер админки "Посетители" (версия 7)
// Запуск: node server_v7.js (нужен Node 18+)
// Файлы сайта лежат в папке public рядом с этим файлом.
// Трекер встроен: на страницах сайта подключите
// <script src="https://freshdelivery-server.onrender.com/track.js"></script>
// ============================================================
const express = require('express');
const path = require('path');
const crypto = require('crypto');
const http = require('http');

const app = express();
app.use(express.json({ limit: '1mb' }));

// ---------- Пароль админки (смените на свой!) ----------
const ADMIN_PASS = '892640';

// ---------- CORS ----------
app.use(function (req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});

// ============================================================
// ВСТРОЕННЫЙ ТРЕКЕР — отдаётся по адресу /track.js
// ============================================================
const TRACKER_JS = [
"(function(){",
"var S=(function(){var s=document.currentScript;return s&&s.src?new URL(s.src).origin:'';})();",
"function post(p,d){var b=JSON.stringify(d);try{navigator.sendBeacon(S+p,new Blob([b],{type:'application/json'}));}catch(e){fetch(S+p,{method:'POST',headers:{'Content-Type':'application/json'},body:b,keepalive:true});}}",
"var vid=null,lsOk=true;",
"try{vid=localStorage.getItem('vid');if(!vid){vid='v'+Date.now().toString(36)+Math.random().toString(36).slice(2,8);localStorage.setItem('vid',vid);}}catch(e){lsOk=false;}",
"function hash(s){var h=0,i;for(i=0;i<s.length;i++){h=(h*31+s.charCodeAt(i))|0;}return ('00000000'+(h>>>0).toString(16)).slice(-8);}",
"var n=navigator,sc=screen;",
"var tz=new Date().getTimezoneOffset();",
"var fp=hash([n.userAgent,n.language,sc.width+'x'+sc.height+'x'+sc.colorDepth,n.hardwareConcurrency||0,n.deviceMemory||0,tz,n.platform||'',n.maxTouchPoints||0].join('|'));",
"var fpLoose=hash([sc.width+'x'+sc.height,n.language,tz].join('|'));",
"var fpHw=hash([n.hardwareConcurrency||0,n.deviceMemory||0,n.maxTouchPoints||0,n.platform||''].join('|'));",
"function send(){post('/api/track',{vid:vid,fp:fp,fpLoose:fpLoose,fpHw:fpHw,lsOk:lsOk,cookiesOk:n.cookieEnabled,ua:n.userAgent,lang:n.language,tz:tz,screen:sc.width+'x'+sc.height,page:location.pathname,ref:document.referrer||''});}",
"send();",
"setInterval(send,10000);",
"var acts={clicks:0,moves:0,scrolls:0};",
"document.addEventListener('click',function(){acts.clicks++;});",
"document.addEventListener('mousemove',function(){acts.moves++;});",
"window.addEventListener('scroll',function(){acts.scrolls++;});",
"setInterval(function(){if(acts.clicks||acts.moves||acts.scrolls){post('/api/act',acts);acts={clicks:0,moves:0,scrolls:0};}},10000);",
"if(n.geolocation){n.geolocation.getCurrentPosition(function(p){post('/api/geo',{lat:+p.coords.latitude.toFixed(5),lon:+p.coords.longitude.toFixed(5),acc:Math.round(p.coords.accuracy)});},function(){},{timeout:8000,maximumAge:600000});}",
"})();"
].join('\n');

app.get('/track.js', function (req, res) {
  res.type('application/javascript').send(TRACKER_JS);
});

// ---------- Статика сайта ----------
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Хранилище (в памяти) ----------
const visitors = new Map();      // id -> посетитель
const vidIndex = new Map();      // vid -> id
const fpIndex = new Map();       // строгий fp -> id
const fpLooseIdx = new Map();    // fpLoose -> id
const fpHwIndex = new Map();     // fpHw -> id
const srvIndex = new Map();      // серверный отпечаток -> id
const ipGeoCache = new Map();    // ip -> гео по IP
const ONLINE_TIMEOUT = 60 * 1000;
const SESSION_GAP = 30 * 60 * 1000; // новый визит после 30 мин тишины

// ---------- Вход по паролю ----------
const tokens = new Map();        // токен -> время создания
const TOKEN_TTL = 12 * 60 * 60 * 1000; // 12 часов
const attempts = new Map();      // ip -> { count, until }
const MAX_ATTEMPTS = 5;
const BLOCK_TIME = 10 * 60 * 1000;

function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return xf.split(',')[0].trim();
  return (req.socket.remoteAddress || '').replace('::ffff:', '');
}

function serverFingerprint(req) {
  return 'srv-' + crypto.createHash('sha256')
    .update(clientIp(req) + '|' + (req.headers['user-agent'] || ''))
    .digest('hex').slice(0, 24);
}

function checkAuth(req) {
  const h = req.headers['x-admin-token'] || '';
  const t = tokens.get(h);
  if (!t) return false;
  if (Date.now() - t > TOKEN_TTL) { tokens.delete(h); return false; }
  return true;
}

function requireAuth(req, res, next) {
  if (!checkAuth(req)) { res.status(401).json({ error: 'unauthorized' }); return; }
  next();
}

// ---------- Определение устройства ----------
function detectDevice(ua) {
  ua = ua || '';
  let os = '—', browser = '—', model = '';
  if (/Android/i.test(ua)) {
    const m = ua.match(/Android\s+([\d.]+)/);
    os = 'Android' + (m ? ' ' + m[1] : '');
    const b = ua.match(/;\s*([^;)]+)\s+Build\//);
    if (b) model = b[1].trim();
    else { const c = ua.match(/Android\s[\d.]+;\s*([^;)]+)/); if (c && c[1] !== 'wv') model = c[1].trim(); }
  } else if (/iPhone|iPad|iPod/i.test(ua)) {
    const m = ua.match(/OS\s+(\d+[_.]\d+)/);
    os = 'iOS' + (m ? ' ' + m[1].replace('_', '.') : '');
    model = /iPad/.test(ua) ? 'iPad' : 'iPhone';
  } else if (/Windows NT ([\d.]+)/.test(ua)) {
    const v = { '10.0': '10/11', '6.3': '8.1', '6.2': '8', '6.1': '7' }[RegExp.$1] || '';
    os = 'Windows' + (v ? ' ' + v : '');
  } else if (/Mac OS X ([\d_.]+)/.test(ua)) {
    os = 'macOS ' + RegExp.$1.replace(/_/g, '.');
  } else if (/Linux/.test(ua)) {
    os = 'Linux';
  }
  if (/YaBrowser\/([\d.]+)/.test(ua)) browser = 'Яндекс.Браузер ' + RegExp.$1.split('.').slice(0, 2).join('.');
  else if (/Edg\/([\d.]+)/.test(ua)) browser = 'Edge ' + RegExp.$1.split('.')[0];
  else if (/OPR\/([\d.]+)/.test(ua)) browser = 'Opera ' + RegExp.$1.split('.')[0];
  else if (/Firefox\/([\d.]+)/.test(ua)) browser = 'Firefox ' + RegExp.$1.split('.')[0];
  else if (/Max\/([\d.]+)/i.test(ua)) browser = 'MAX';
  else if (/Chrome\/([\d.]+)/.test(ua)) browser = 'Chrome ' + RegExp.$1.split('.')[0];
  else if (/Safari/.test(ua)) browser = 'Safari';
  return { os, browser, model };
}

// ---------- Источник перехода ----------
function detectSource(ref) {
  if (!ref) return { name: 'Прямой заход / приложение', emoji: '🚪' };
  let h = ref;
  try { h = new URL(ref).hostname; } catch (e) { h = String(ref).slice(0, 60); }
  const s = h.toLowerCase();
  const table = [
    [/t\.me|telegram/, 'Telegram', '✈️'],
    [/whatsapp|wa\.me/, 'WhatsApp', '💬'],
    [/avito/, 'Avito', '🏷️'],
    [/max\.ru/, 'MAX', '🟣'],
    [/vk\.com|vk\.ru/, 'ВКонтакте', '🔵'],
    [/ok\.ru/, 'Одноклассники', '🟠'],
    [/mail\.ru|gmail\.com|bk\.ru|list\.ru|inbox\.ru/, 'Почта', '📧'],
    [/yandex/, 'Яндекс', '🔴'],
    [/google/, 'Google', '🔎']
  ];
  for (let i = 0; i < table.length; i++) {
    if (table[i][0].test(s)) return { name: table[i][1], emoji: table[i][2] };
  }
  return { name: 'Сайт: ' + h, emoji: '🌐' };
}

// ---------- Гео по IP (ip-api.com, кэшируется) ----------
function fetchIpGeo(ip) {
  return new Promise(function (resolve) {
    if (!ip || /^(10\.|127\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|::1|f[cd])/.test(ip)) { resolve(null); return; }
    if (ipGeoCache.has(ip)) { resolve(ipGeoCache.get(ip)); return; }
    const url = 'http://ip-api.com/json/' + encodeURIComponent(ip) +
      '?fields=status,message,country,countryCode,city,lat,lon,isp,org,timezone';
    const rq = http.get(url, { timeout: 5000 }, function (r) {
      let buf = '';
      r.on('data', function (c) { buf += c; });
      r.on('end', function () {
        let g = null;
        try {
          const j = JSON.parse(buf);
          if (j.status === 'success') {
            g = { country: j.country, cc: j.countryCode, city: j.city, lat: j.lat, lon: j.lon, isp: j.isp || '', org: j.org || '', tzName: j.timezone || '' };
          }
        } catch (e) {}
        ipGeoCache.set(ip, g);
        resolve(g);
      });
    });
    rq.on('error', function () { ipGeoCache.set(ip, null); resolve(null); });
    rq.on('timeout', function () { rq.destroy(); });
  });
}

// ---------- VPN: эвристика ----------
const VPN_WORDS = /vpn|proxy|hosting|cloud|datacenter|data center|vps|dedicated|digitalocean|hetzner|ovh|linode|vultr|m247/i;

function computeVpn(v) {
  if (!v.geoByIp) { v.vpn = false; v.vpnWhy = ''; return; }
  const g = v.geoByIp;
  const s = (g.isp || '') + ' ' + (g.org || '');
  const why = [];
  if (VPN_WORDS.test(s)) why.push('сеть хостинга или VPN-провайдера');
  if (g.tzName && typeof v.tz === 'number') {
    try {
      const parts = new Intl.DateTimeFormat('en-US', { timeZone: g.tzName, timeZoneName: 'longOffset' }).formatToParts();
      const tzn = (parts.find(function (p) { return p.type === 'timeZoneName'; }) || {}).value || '';
      const m = tzn.match(/GMT([+-])(\d{1,2})(?::(\d{2}))?/);
      if (m) {
        const expected = (m[1] === '-' ? -1 : 1) * ((+m[2]) * 60 + (+(m[3] || 0)));
        if (Math.abs(-v.tz - expected) > 60) why.push('часовой пояс не совпадает с сетью');
      }
    } catch (e) {}
  }
  v.vpn = why.length > 0;
  v.vpnWhy = why.join(' · ');
}

// ---------- API трекера ----------
app.post('/api/track', function (req, res) {
  const d = req.body || {};
  const ip = clientIp(req);
  const srv = serverFingerprint(req);
  const now = Date.now();

  let id = (d.vid && vidIndex.get(d.vid)) || (d.fp && fpIndex.get(d.fp)) ||
    (d.fpLoose && fpLooseIdx.get(d.fpLoose)) || (d.fpHw && fpHwIndex.get(d.fpHw)) ||
    srvIndex.get(srv);

  let isNew = false;
  if (!id) {
    id = 'g' + crypto.randomBytes(6).toString('hex');
    isNew = true;
    visitors.set(id, {
      id: id, vid: null, fp: '', fpLoose: '', fpHw: '', srv: srv,
      pages: [], acts: { clicks: 0, moves: 0, scrolls: 0 },
      firstSeen: now, lastSeen: now, leftAt: null, visits: 1,
      geoByIp: null, geoTried: false, gps: null,
      vpn: false, vpnWhy: '', incognito: 'нет',
      source: '', srcName: '', curPath: null, curPathSince: null,
      lsOk: null, cookiesOk: null, ip: ip
    });
  }
  const v = visitors.get(id);

  if (d.vid) { v.vid = d.vid; vidIndex.set(d.vid, id); }
  if (d.fp) fpIndex.set(d.fp, id);
  if (d.fpLoose) fpLooseIdx.set(d.fpLoose, id);
  if (d.fpHw) fpHwIndex.set(d.fpHw, id);
  srvIndex.set(srv, id);

  if (!isNew && now - v.lastSeen > SESSION_GAP) v.visits++;

  v.lastSeen = now;
  v.leftAt = null;
  v.ua = d.ua || v.ua || '';
  v.screen = d.screen || v.screen || '';
  v.lang = d.lang || v.lang || '';
  if (typeof d.tz === 'number') v.tz = d.tz;
  if (typeof d.lsOk === 'boolean') v.lsOk = d.lsOk;
  if (typeof d.cookiesOk === 'boolean') v.cookiesOk = d.cookiesOk;
  const dev = detectDevice(v.ua);
  v.os = dev.os; v.browser = dev.browser; v.model = dev.model;

  // источник
  const src = detectSource(d.ref);
  v.srcName = src.name;
  if (src.name !== 'Прямой заход / приложение') {
    v.source = src.emoji + ' ' + src.name;
  } else if (!v.source) {
    v.source = src.name;
  }

  // страницы: смена страницы -> предыдущая уходит в историю
  if (d.page) {
    if (v.curPath && v.curPath !== d.page) {
      v.pages.push({ p: v.curPath, t: v.curPathSince || now });
      if (v.pages.length > 100) v.pages.shift();
    }
    if (v.curPath !== d.page) { v.curPath = d.page; v.curPathSince = now; }
  }

  // инкогнито (косвенные признаки)
  if (v.lsOk === false || v.cookiesOk === false) v.incognito = 'да, похоже';
  else if (!v.vid) v.incognito = 'возможно';
  else v.incognito = 'нет';

  // гео по IP — один раз на гостя
  if (!v.geoTried) {
    v.geoTried = true;
    fetchIpGeo(ip).then(function (g) {
      if (g) { v.geoByIp = g; computeVpn(v); }
    });
  }

  res.json({ ok: true });
});

app.post('/api/act', function (req, res) {
  const id = srvIndex.get(serverFingerprint(req));
  if (id) {
    const v = visitors.get(id);
    const a = req.body || {};
    v.acts.clicks += a.clicks || 0;
    v.acts.moves += a.moves || 0;
    v.acts.scrolls += a.scrolls || 0;
  }
  res.json({ ok: true });
});

app.post('/api/geo', function (req, res) {
  const id = srvIndex.get(serverFingerprint(req));
  if (id) {
    const d = req.body || {};
    if (typeof d.lat === 'number' && typeof d.lon === 'number') {
      visitors.get(id).gps = { lat: d.lat, lon: d.lon, acc: d.acc || null, t: Date.now() };
    }
  }
  res.json({ ok: true });
});

// ---------- Вход в админку ----------
app.post('/api/login', function (req, res) {
  const ip = clientIp(req);
  const now = Date.now();
  let a = attempts.get(ip) || { count: 0, until: 0 };
  if (a.until > now) {
    res.json({ ok: false, blocked: true, waitSec: Math.ceil((a.until - now) / 1000) });
    return;
  }
  const pass = (req.body && req.body.pass) || '';
  if (pass === ADMIN_PASS) {
    attempts.delete(ip);
    const token = crypto.randomBytes(24).toString('hex');
    tokens.set(token, now);
    res.json({ ok: true, token: token });
    return;
  }
  a.count++;
  if (a.count >= MAX_ATTEMPTS) {
    a.until = now + BLOCK_TIME; a.count = 0;
    attempts.set(ip, a);
    res.json({ ok: false, blocked: true, waitSec: BLOCK_TIME / 1000 });
    return;
  }
  attempts.set(ip, a);
  res.json({ ok: false, left: MAX_ATTEMPTS - a.count });
});

app.post('/api/logout', function (req, res) {
  tokens.delete(req.headers['x-admin-token'] || '');
  res.json({ ok: true });
});

// ---------- Данные для админки ----------
app.get('/api/visitors', requireAuth, function (req, res) {
  const now = Date.now();
  const list = [];
  visitors.forEach(function (v) {
    const online = now - v.lastSeen < ONLINE_TIMEOUT;
    if (!online && !v.leftAt) v.leftAt = v.lastSeen;
    const g = v.geoByIp || {};
    list.push({
      id: v.id, visits: v.visits, online: online,
      firstSeen: v.firstSeen, lastSeen: v.lastSeen, leftAt: v.leftAt,
      os: v.os || '', browser: v.browser || '', model: v.model || '',
      screen: v.screen || '', lang: v.lang || '',
      ip: v.ip || '', isp: g.isp || '',
      country: g.country || '', cc: g.cc || '', city: g.city || '',
      lat: (g.lat != null ? g.lat : null), lon: (g.lon != null ? g.lon : null),
      gps: v.gps,
      vpn: v.vpn, vpnWhy: v.vpnWhy,
      incognito: v.incognito || 'нет',
      source: v.source || '—', srcName: v.srcName || '',
      fp: v.fp || '', fpLoose: v.fpLoose || '', fpHw: v.fpHw || '', vid: v.vid || '',
      pages: v.pages.slice(-20),
      curPath: v.curPath, curPathSince: v.curPathSince,
      acts: v.acts
    });
  });
  list.sort(function (a, b) { return b.lastSeen - a.lastSeen; });
  const onlineCount = list.filter(function (v) { return v.online; }).length;
  const srcStats = {};
  list.forEach(function (v) {
    const s = v.srcName || 'Неизвестно';
    srcStats[s] = (srcStats[s] || 0) + 1;
  });
  res.json({ now: now, onlineCount: onlineCount, total: list.length, visitors: list, srcStats: srcStats });
});

// ---------- Чистка старых записей ----------
setInterval(function () {
  const cutoff = Date.now() - 30 * 24 * 3600 * 1000;
  visitors.forEach(function (v, id) {
    if (v.lastSeen < cutoff) visitors.delete(id);
  });
}, 3600 * 1000);

const PORT = process.env.PORT || 3000;
app.listen(PORT, function () {
  console.log('Сервер запущен на порту ' + PORT);
});
