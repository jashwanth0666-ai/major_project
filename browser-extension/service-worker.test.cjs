const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function loadWorker(fetchImpl) {
  const listeners = {};
  const context = {
    URL,
    Map,
    Date,
    fetch: fetchImpl,
    chrome: {
      tabs: {
        onActivated: { addListener: (handler) => { listeners.activated = handler; } },
        onUpdated: { addListener: (handler) => { listeners.updated = handler; } },
        get: () => {}
      },
      runtime: { lastError: null }
    }
  };
  vm.createContext(context);
  const source = fs.readFileSync(path.join(__dirname, "service-worker.js"), "utf8");
  vm.runInContext(`${source}\nglobalThis.workerTest = { sanitizeUrl, analyzeActiveUrl };`, context);
  return context.workerTest;
}

test("sanitizes credentials, query, and fragment and ignores non-web schemes", () => {
  const worker = loadWorker(async () => ({ ok: true }));
  assert.equal(worker.sanitizeUrl("https://user:pass@example.test/a?token=secret&x=1#fragment"),
    "https://example.test/a");
  assert.equal(worker.sanitizeUrl("file:///C:/private.txt"), null);
  assert.equal(worker.sanitizeUrl("chrome://settings"), null);
  assert.equal(worker.sanitizeUrl("https://example.test/session/secret-value"), "https://example.test/");
  assert.equal(worker.sanitizeUrl("https://example.test/1234567890abcdef1234567890abcdef"), "https://example.test/");
});

test("sends only once for a repeated normalized URL and only to loopback", async () => {
  const requests = [];
  const worker = loadWorker(async (endpoint, options) => {
    requests.push({ endpoint, body: JSON.parse(options.body) });
    return { ok: true };
  });
  await worker.analyzeActiveUrl("https://example.test/login?token=one");
  await worker.analyzeActiveUrl("https://example.test/login?token=two");
  assert.equal(requests.length, 1);
  assert.ok(requests[0].endpoint.startsWith("http://localhost:8080/")
    || requests[0].endpoint.startsWith("http://127.0.0.1:8080/"));
  assert.deepEqual(requests[0].body, { url: "https://example.test/login" });
});
