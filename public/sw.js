const CACHE_NAME = 'byte-back-v2';
const CACHE_PREFIX = 'byte-back-';
const APP_SHELL = [
  '/',
  '/index.html',
  '/manifest.webmanifest',
  '/icons/icon-192.png',
  '/icons/icon-512.png',
  '/auth-controller.mjs',
  '/auth-browser.mjs',
];
const CACHEABLE_URLS = new Set(APP_SHELL.map(path => new URL(path, self.location.origin).href));

self.addEventListener('install', event => {
  event.waitUntil(caches.open(CACHE_NAME).then(cache => cache.addAll(APP_SHELL)));
  self.skipWaiting();
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys().then(keys => Promise.all(
      keys.filter(key => key.startsWith(CACHE_PREFIX) && key !== CACHE_NAME)
        .map(key => caches.delete(key)),
    )),
  );
  self.clients.claim();
});

self.addEventListener('fetch', event => {
  const request = event.request;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || request.method !== 'GET'
      || url.pathname === '/api' || url.pathname.startsWith('/api/')) return;
  if (!CACHEABLE_URLS.has(url.href)) return;

  event.respondWith(
    fetch(request)
      .then(response => {
        if (response.ok && response.type === 'basic') {
          const copy = response.clone();
          void caches.open(CACHE_NAME).then(cache => cache.put(request, copy));
        }
        return response;
      })
      .catch(async () => {
        const cached = await caches.open(CACHE_NAME).then(cache => cache.match(request));
        if (cached) return cached;
        if (request.mode === 'navigate') {
          return caches.open(CACHE_NAME).then(cache => cache.match('/index.html'));
        }
        return Response.error();
      }),
  );
});
