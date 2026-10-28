'use strict';
// Collects honest, aggregated data from open sources into data/live-stats.json.
// Run by .github/workflows/live-stats.yml; secrets stay in GitHub Secrets and never reach the app.
const fs = require('node:fs');
const path = require('node:path');
const { fetchRadarData } = require('../cloudflare-threats');
const { loadNews } = require('../news-feed');

const OUT = path.join(__dirname, '..', 'data', 'live-stats.json');
const safe = (e) => String((e && e.message) || e).slice(0, 160);

async function radar() {
  const token = process.env.CLOUDFLARE_RADAR_API_TOKEN;
  if (!token) return { ok: false, error: 'Нет токена CLOUDFLARE_RADAR_API_TOKEN' };
  const r = await fetchRadarData({ token, force: true });
  if (!['ok', 'partial'].includes(r.status)) return { ok: false, error: r.message || r.status };
  const pick = (a) => (a || []).slice(0, 10).map((x) => ({ code: x.code, name: x.name, value: Number(x.value.toFixed(2)) }));
  return { ok: true, period: '24h', sourceUpdatedAt: r.sourceUpdatedAt, origins: pick(r.topOrigins), targets: pick(r.topTargets), vectors: (r.vectors || []).slice(0, 6), uzbekistan: { asTarget: (r.topTargets || []).find((x) => x.code === 'UZ') || null, asOrigin: (r.topOrigins || []).find((x) => x.code === 'UZ') || null } };
}

async function feodo() {
  const res = await fetch('https://feodotracker.abuse.ch/downloads/ipblocklist.json', { signal: AbortSignal.timeout(20000) });
  if (!res.ok) throw new Error('Feodo HTTP ' + res.status);
  const list = await res.json();
  if (!Array.isArray(list)) throw new Error('Feodo: неожиданный формат');
  const online = list.filter((x) => String(x.status).toLowerCase() === 'online');
  const count = (arr, key) => Object.entries(arr.reduce((m, x) => { const k = x[key] || '—'; m[k] = (m[k] || 0) + 1; return m; }, {})).sort((a, b) => b[1] - a[1]).slice(0, 6).map(([name, n]) => ({ name, count: n }));
  return { ok: true, total: list.length, online: online.length, byMalware: count(online, 'malware'), byCountry: count(online, 'country') };
}

async function uzcert() {
  const d = await loadNews(true);
  const items = d.items.filter((i) => i.official).slice(0, 6).map((i) => ({ title: i.title, url: i.url, date: i.date }));
  return { ok: items.length > 0, items, error: items.length ? undefined : 'Лента UZCERT пуста' };
}

(async () => {
  const run = async (fn) => { try { return await fn(); } catch (e) { return { ok: false, error: safe(e) }; } };
  const [r, f, u] = await Promise.all([run(radar), run(feodo), run(uzcert)]);
  const out = { generatedAt: new Date().toISOString(), cloudflareRadar: r, feodoTracker: f, uzcert: u };
  if (![r, f, u].some((x) => x.ok)) { console.error('Все источники недоступны:', JSON.stringify(out)); process.exit(1); }
  fs.mkdirSync(path.dirname(OUT), { recursive: true });
  fs.writeFileSync(OUT, JSON.stringify(out, null, 1) + '\n');
  console.log('live-stats.json written:', { radar: r.ok, feodo: f.ok, uzcert: u.ok });
})();
