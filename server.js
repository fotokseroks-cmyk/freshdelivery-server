// server.js — сервер сайта "Посетители" (полная версия)
// Запуск: node server.js  (нужен Node 18+)

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const app = express();

app.use(express.json({ limit: '1mb' }));

// ---------- Пароль админки (смените на свой!) ----------
const ADMIN_PASS = 'fresh2026';

// ---------- CORS: разрешаем запросы с сайта на Netlify ----------
app.use(function (req, res, next) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') { res.status(204).end(); return; }
  next();
});

// Раздаём статичные файлы: index.html, admin.html, visitor.js, bg.jpg
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Хранилище посетителей (в памяти) ----------
const visitors = new Map();   // id -> посетитель
const fpIndex  = new Map();   // фингерпринт -> id посетителя
const ONLINE_TIMEOUT = 60 * 1000; // 60 сек без пингов = офлайн

function getVisitor(id) {
  if (!visitors.has(id)) {
    visitors.set(id, {
      id,
      fp: null,                 // отпечаток (клиентский или серверный)
      device: '',
      deviceInfo: null,         // модель, ОС, браузер, экран
      source: null,               // заполнится из пинга клиента
      landing: '/',
      lat: null, lng: null, accuracy: null,
      ip: null, country: null, countryCode: null, city: null,
      region: null, isp: null, flag: null,
      vpnSuspect: false,        // похоже на VPN/прокси
      geoFrom: null,            // 'ip' или 'coords' — откуда взята геолокация
      joinedAt: null, leftAt: null, lastSeen: null
    });
  }
  return visitors.get(id);
}

// ---------- Серверный отпечаток: IP + User-Agent ----------
function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (xf) return xf.split(',')[0].trim();
  return (req.socket.remoteAddress || '').replace('::ffff:', '');
}

function serverFingerprint(req) {
  const ip = clientIp(req);
  const ua = req.headers['user-agent'] || '';
  return 'srv-' + crypto.createHash('sha256').update(ip + '|' + ua).digest('hex').slice(0, 24);
}

function linkFp(id, fp) {
  if (!fp) return;
  const v = visitors.get(id);
  if (v && !v.fp) v.fp = fp;
  if (!fpIndex.has(fp)) fpIndex.set(fp, id);
}

// Кому записать этот пинг?
function resolveVisitor(b, req) {
  const fp = b.fp || serverFingerprint(req);

  // 1) клиент пришёл со своим знакомым id
  if (b.id && visitors.has(b.id)) {
    linkFp(b.id, fp);
    return visitors.get(b.id);
  }

  // 2) инкогнито: id незнаком, но отпечаток уже встречали
  if (fp && fpIndex.has(fp)) return visitors.get(fpIndex.get(fp));

  // 3) совсем новый
  const id = b.id || fp || ('anon-' + Date.now().toString(36) + Math.random().toString(36).slice(2, 8));
  const v = getVisitor(id);
  linkFp(id, fp);
  return v;
}

// ---------- Геолокация по IP (ip-api.com, с кэшем) ----------
const geoCache = new Map(); // ip -> данные гео
const FLAGS = {
  RU: '🇷🇺', US: '🇺🇸', DE: '🇩🇪', FR: '🇫🇷', GB: '🇬🇧', UA: '🇺🇦',
  KZ: '🇰🇿', BY: '🇧🇾', TR: '🇹🇷', CN: '🇨🇳', NL: '🇳🇱', PL: '🇵🇱',
  IL: '🇮🇱', AE: '🇦🇪', AM: '🇦🇲', GE: '🇬🇪', KG: '🇰🇬', UZ: '🇺🇿'
};

async function geoByIp(ip) {
  if (!ip || ip === '127.0.0.1' || ip === '::1' || ip.startsWith('192.168.') || ip.startsWith('10.')) return null;
  if (geoCache.has(ip)) return geoCache.get(ip);
  try {
    const url = 'http://ip-api.com/json/' + encodeURIComponent(ip) +
      '?fields=status,country,countryCode,city,regionName,isp,proxy,hosting&lang=ru';
    const res = await fetch(url, { signal: AbortSignal.timeout(4000) });
    const d = await res.json();
    if (d.status !== 'success') return null;
    const geo = {
      country: d.country, countryCode: d.countryCode, city: d.city,
      region: d.regionName, isp: d.isp,
      vpnSuspect: !!(d.proxy || d.hosting),
      flag: FLAGS[d.countryCode] || '🌍',
      geoFrom: 'ip'
    };
    geoCache.set(ip, geo);
    return geo;
  } catch (e) { return null; }
}

// ---------- Город по координатам (запасной путь, Nominatim) ----------
const nominatimCache = new Map();
async function cityByCoords(lat, lng) {
  const key = lat.toFixed(2) + ',' + lng.toFixed(2);
  if (nominatimCache.has(key)) return nominatimCache.get(key);
  try {
    const url = 'https://nominatim.openstreetmap.org/reverse?format=json&zoom=10&accept-language=ru' +
      '&lat=' + lat + '&lon=' + lng;
    const res = await fetch(url, {
      headers: { 'User-Agent': 'FreshDelivery/1.0' },
      signal: AbortSignal.timeout(5000)
    });
    const d = await res.json();
    const addr = d.address || {};
    const city = addr.city || addr.town || addr.village || addr.county || null;
    const country = addr.country || null;
    const cc = (addr.country_code || '').toUpperCase();
    const geo = city ? {
      country, countryCode: cc || null,
      city, region: addr.state || null, isp: null,
      vpnSuspect: false, flag: FLAGS[cc] || '🌍', geoFrom: 'coords'
    } : null;
    nominatimCache.set(key, geo);
    return geo;
  } catch (e) { return null; }
}

// ---------- Пинг от клиента ----------
app.post('/api/ping', async (req, res) => {
  const b = req.body || {};
  const v = resolveVisitor(b, req);

  if (b.device) v.device = b.device;
  if (b.deviceInfo && typeof b.deviceInfo === 'object') v.deviceInfo = b.deviceInfo;
  v.source = b.source || v.source || 'неизвестно';   // источник от клиента приоритетнее
  if (!v.landing) v.landing = b.landing || '/';
  if (!v.joinedAt) v.joinedAt = b.joinedAt || new Date().toISOString();

  v.leftAt = null; // снова на сайте

  if (typeof b.lat === 'number' && typeof b.lng === 'number') {
    v.lat = b.lat;
    v.lng = b.lng;
    v.accuracy = typeof b.accuracy === 'number' ? b.accuracy : null;
  }

  // IP и геолокация: сначала по IP, если не вышло — по координатам
  const ip = clientIp(req);
  if (ip) v.ip = ip;
  if (ip && v.geoFrom !== 'ip') {
    const geo = await geoByIp(ip);
    if (geo) Object.assign(v, geo);
  }
  if (!v.country && v.lat != null) {
    const geo = await cityByCoords(v.lat, v.lng);
    if (geo) Object.assign(v, geo);
  }

  v.lastSeen = new Date().toISOString();
  res.json({ ok: true, id: v.id }); // отдаём клиенту его настоящий id
});

// ---------- Уход с сайта ----------
app.post('/api/leave', (req, res) => {
  const b = req.body || {};
  if (b.id && visitors.has(b.id)) {
    visitors.get(b.id).leftAt = b.leftAt || new Date().toISOString();
  }
  res.json({ ok: true });
});

// ---------- Список для админки ----------
app.get('/api/visitors', (req, res) => {
  if (req.query.key !== ADMIN_PASS) { res.status(401).json({ error: 'Неверный ключ админки' }); return; }

  const now = Date.now();
  const list = [];
  for (const v of visitors.values()) {
    const online =
      !v.leftAt &&
      v.lastSeen &&
      now - new Date(v.lastSeen).getTime() < ONLINE_TIMEOUT;

    list.push({
      id: v.id,
      fp: v.fp,
      device: v.device,
      deviceInfo: v.deviceInfo,
      source: v.source,
      landing: v.landing,
      lat: v.lat, lng: v.lng, accuracy: v.accuracy,
      ip: v.ip, country: v.country, city: v.city,
      region: v.region, isp: v.isp, flag: v.flag,
      vpnSuspect: v.vpnSuspect, geoFrom: v.geoFrom,
      joinedAt: v.joinedAt, leftAt: v.leftAt, lastSeen: v.lastSeen,
      online
    });
  }
  // Свежие сверху
  list.sort((a, b) => new Date(b.lastSeen || 0) - new Date(a.lastSeen || 0));
  res.json(list);
});

// ---------- Запуск ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () =>
  console.log('Сервер запущен на порту ' + PORT));
