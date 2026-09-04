/**
 * Tombstone for the offline service worker this app used to install.
 *
 * That worker cached the bundle, which is exactly the failure the embedded,
 * no-store delivery exists to prevent: a cached cryptographic client can outlive
 * the deployment that fixed it. It was removed, but a browser that loaded the app
 * while it existed still holds the registration, and only fetching this path
 * clears it.
 *
 * Retire it when no browser can still be holding one — a year after 0.3.0, or
 * once the origin has moved, whichever comes first. app.js unregisters the same
 * worker on load, so this is the belt rather than the braces; both stay until
 * then because the cost of being wrong is the stale client.
 */
self.addEventListener('install', () => self.skipWaiting());

self.addEventListener('activate', (e) => {
  e.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((key) => key.startsWith('deaddrop-')).map((key) => caches.delete(key)));
    await self.clients.claim();
    await self.registration.unregister();
  })());
});
