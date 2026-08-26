/* NearInstant service worker — enables installability + offline app shell.
   The app is a single self-contained page; RPC/oracle calls are cross-origin
   and are never cached (passed straight through). Same-origin shell assets are
   cached so the app opens offline and installs as a PWA. */
const VERSION = "nearinstant-v1";
const SHELL = [
  "/", "/index.html", "/manifest.webmanifest",
  "/favicon.svg", "/favicon-32.png", "/apple-touch-icon.png",
  "/icon-192.png", "/icon-512.png", "/icon-maskable-512.png"
];
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()).catch(() => {}));
});
self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((ks) => Promise.all(ks.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});
self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;            // RPC/oracles: never intercept
  if (req.mode === "navigate") {                              // app updates land: network-first
    e.respondWith(fetch(req).then((r) => { const cp = r.clone(); caches.open(VERSION).then((c) => c.put("/", cp)); return r; }).catch(() => caches.match("/").then((m) => m || caches.match("/index.html"))));
    return;
  }
  e.respondWith(caches.match(req).then((cached) => {          // static: stale-while-revalidate
    const net = fetch(req).then((r) => { if (r && r.status === 200) { const cp = r.clone(); caches.open(VERSION).then((c) => c.put(req, cp)); } return r; }).catch(() => cached);
    return cached || net;
  }));
});
