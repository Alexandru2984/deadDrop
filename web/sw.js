/** One-release tombstone for the former offline service worker. */
self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((key) => key.startsWith('deaddrop-')).map((key) => caches.delete(key)));
    await self.clients.claim();
    await self.registration.unregister();
  })());
});
