// Juss Protect Me checkup app — service worker.
// Caches the app shell so the checkup opens offline after first visit.
const CACHE = 'jpm-app-v1';
const SHELL = ['/app.html', '/app.js', '/manifest.webmanifest', '/icon.svg', '/fonts/playfair-var.woff2'];
self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});
self.addEventListener('activate', (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener('fetch', (e) => {
  const { pathname } = new URL(e.request.url);
  if (SHELL.includes(pathname)) {
    e.respondWith(caches.match(e.request).then((hit) => hit || fetch(e.request)));
  }
});
