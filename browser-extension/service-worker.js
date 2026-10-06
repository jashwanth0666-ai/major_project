const API_URLS = new Set([
  "http://localhost:8080/api/v1/analyze",
  "http://127.0.0.1:8080/api/v1/analyze"
]);
const recentUrls = new Map();
const DEBOUNCE_MS = 60_000;

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (!chrome.runtime.lastError && tab?.url) analyzeActiveUrl(tab.url);
  });
});

chrome.tabs.onUpdated.addListener((_tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.active && tab.url) {
    analyzeActiveUrl(tab.url);
  }
});

function sanitizeUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    url.username = "";
    url.password = "";
    url.hash = "";
    const pathSegments = url.pathname.split("/").filter(Boolean);
    const hasSensitivePath = pathSegments.some((segment) => {
      let decoded = segment;
      try { decoded = decodeURIComponent(segment); } catch { /* Treat malformed segments as opaque. */ }
      return /(?:token|session|password|secret|credential|access[_-]?key|auth[_-]?code)/i.test(decoded)
        || /^[A-Za-z0-9_-]{32,}$/.test(decoded);
    });
    if (hasSensitivePath) url.pathname = "/";
    // Query strings frequently contain authentication codes, tracking IDs, or personal data.
    // The URL engine receives origin and a path only when it appears non-secret.
    url.search = "";
    return url.toString();
  } catch {
    return null;
  }
}

async function analyzeActiveUrl(rawUrl) {
  const sanitizedUrl = sanitizeUrl(rawUrl);
  if (!sanitizedUrl || recentUrls.has(sanitizedUrl)) return;
  const now = Date.now();
  for (const [url, timestamp] of recentUrls) {
    if (now - timestamp > DEBOUNCE_MS) recentUrls.delete(url);
  }
  recentUrls.set(sanitizedUrl, now);
  while (recentUrls.size > 512) recentUrls.delete(recentUrls.keys().next().value);

  for (const endpoint of API_URLS) {
    try {
      await fetch(endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: sanitizedUrl })
      });
      return;
    } catch {
      // Try the loopback alias; do not send browsing data to any remote service.
    }
  }
  recentUrls.delete(sanitizedUrl);
}
