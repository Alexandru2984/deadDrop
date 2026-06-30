/**
 * Dead Drop service worker — makes the app installable and usable offline.
 *
 * Network-first by design: when online the freshest assets are always fetched, so
 * there is never a stale crypto.js / handshake mismatch after a deploy. The cache
 * is only an offline fallback. API and WebSocket traffic is never touched.
 */

const CACHE = 'deaddrop-shell-v1';

self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  if (req.method !== 'GET') return; // never cache POSTs (auth, TURN, etc.)
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;        // only our own assets
  if (url.pathname.startsWith('/api') || url.pathname === '/ws') return; // never API/WS

  e.respondWith((async () => {
    try {
      const res = await fetch(req);
      if (res && res.ok) {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
      }
      return res;
    } catch {
      const cached = await caches.match(req);
      return cached || caches.match('/');
    }
  })());
});
