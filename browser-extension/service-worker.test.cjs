const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");

function loadWorker(fetchImpl = async () => { throw new Error("unexpected request"); }) {
  const listeners = {};
  const local = { localApiToken: "a".repeat(64) };
  const session = {};
  let dynamicRules = [];
  const requests = [];
  const storageArea = (data) => ({
    get: (key, callback) => {
      const result = typeof key === "string" ? { [key]: data[key] } : { ...data };
      if (callback) { callback(result); return undefined; }
      return Promise.resolve(result);
    },
    set: async (values) => Object.assign(data, values),
    remove: async (key) => { delete data[key]; }
  });
  const context = {
    URL, Map, Set, Date, AbortController, setTimeout, clearTimeout,
    fetch: async (endpoint, options) => { requests.push({ endpoint, options }); return fetchImpl(endpoint, options); },
    chrome: {
      storage: { local: storageArea(local), session: storageArea(session) },
      tabs: {
        onActivated: { addListener: (handler) => { listeners.activated = handler; } },
        onUpdated: { addListener: (handler) => { listeners.updated = handler; } },
        onRemoved: { addListener: (handler) => { listeners.removed = handler; } },
        get: (_id, callback) => callback({ id: 1, url: "https://danger.example/path" }), update: () => {}, create: () => {}
      },
      action: { setBadgeText: () => {}, setBadgeBackgroundColor: () => {} },
      runtime: { lastError: null, onMessage: { addListener: (handler) => { listeners.message = handler; } }, getURL: (url) => `chrome-extension://id/${url}` },
      declarativeNetRequest: {
        getDynamicRules: async () => dynamicRules,
        updateDynamicRules: async ({ removeRuleIds = [], addRules = [] }) => {
          dynamicRules = dynamicRules.filter((rule) => !removeRuleIds.includes(rule.id)).concat(addRules);
        }
      }
    }
  };
  vm.createContext(context);
  const source = fs.readFileSync(path.join(__dirname, "service-worker.js"), "utf8");
  vm.runInContext(`${source}\nglobalThis.workerTest = { sanitizeUrl, isSearchResultsPage, normalizeAssessment, isDangerous, previewResults, installWarningRule, getBackendHealth };`, context);
  return { worker: context.workerTest, requests, get rules() { return dynamicRules; }, local, session };
}

test("sanitizes credentials, queries, fragments, and sensitive paths; ignores non-web schemes", () => {
  const { worker } = loadWorker();
  assert.equal(worker.sanitizeUrl("https://user:pass@example.test/a?token=secret&x=1#fragment"), "https://example.test/a");
  assert.equal(worker.sanitizeUrl("file:///C:/private.txt"), null);
  assert.equal(worker.sanitizeUrl("chrome://settings"), null);
  assert.equal(worker.sanitizeUrl("https://example.test/session/secret-value"), "https://example.test/");
  assert.equal(worker.sanitizeUrl("https://example.test/1234567890abcdef1234567890abcdef"), "https://example.test/");
});

test("search pages are distinguished from navigation and ordinary query text is not a destination", () => {
  const { worker } = loadWorker();
  assert.equal(worker.isSearchResultsPage("https://www.google.com/search?q=hello"), true);
  assert.equal(worker.isSearchResultsPage("https://www.bing.com/search?q=hi"), true);
  assert.equal(worker.isSearchResultsPage("https://duckduckgo.com/?q=hello"), true);
  assert.equal(worker.isSearchResultsPage("https://example.com/hello"), false);
  assert.equal(worker.sanitizeUrl("hello"), null);
});

test("every policy BLOCK is enforceable; non-block verdicts do not install warning rules", () => {
  const { worker } = loadWorker();
  assert.equal(worker.isDangerous({ decision: "BLOCK", riskLevel: "HIGH_RISK" }), true);
  assert.equal(worker.isDangerous({ decision: "BLOCK", riskLevel: "LOW_RISK" }), true);
  assert.equal(worker.isDangerous({ decision: "ALLOW", riskLevel: "SAFE", probability: 0.01 }), false);
  const rating = worker.normalizeAssessment({ decision: "ALLOW", risk_level: "SAFE", phishing_probability: 0.01 }, "https://example.com/", "ASSESSED");
  assert.equal(rating.decision, "ALLOW");
  assert.equal(rating.riskLevel, "SAFE");
});

test("search preview uses the non-persisting endpoint, strips queries, and caps each request batch", async () => {
  const response = { decision: "ALLOW", risk_level: "SAFE", prediction: "BENIGN", phishing_probability: 0.02, risk_score: 2, threshold: 0.15, reasons: [] };
  const harness = loadWorker(async (_endpoint, options) => ({ ok: true, json: async () => response }));
  const urls = Array.from({ length: 10 }, (_, index) => `https://site${index}.example/path?token=synthetic`);
  const results = await harness.worker.previewResults(urls);
  assert.equal(results.length, 8);
  assert.equal(harness.requests.length, 8);
  assert.ok(harness.requests.every((request) => request.endpoint.endsWith("/api/v1/threat-assessments/url/preview")));
  assert.ok(harness.requests.every((request) => request.options.headers.Authorization === `Bearer ${"a".repeat(64)}`));
  assert.ok(harness.requests.every((request) => !JSON.parse(request.options.body).url.includes("?")));
});

test("dynamic navigation rule is limited to confirmed high-risk BLOCK results", async () => {
  const harness = loadWorker();
  const confirmed = { decision: "BLOCK", riskLevel: "HIGH_RISK", reasons: ["controlled test signal"] };
  assert.equal(await harness.worker.installWarningRule(1, "https://danger.example/path", confirmed), true);
  assert.equal(harness.rules.length, 1);
  assert.equal(harness.rules[0].action.type, "redirect");
  assert.equal(harness.rules[0].condition.resourceTypes[0], "main_frame");
  assert.equal(await harness.worker.installWarningRule(1, "https://review.example/", { decision: "REVIEW", riskLevel: "SUSPICIOUS" }), false);
});

test("backend outage leaves result unknown and health keeps Spring and ML states distinct", async () => {
  const unavailable = loadWorker(async () => { throw new Error("offline"); });
  const result = await unavailable.worker.previewResults(["https://unknown.example/"]);
  assert.equal(result[0].state, "UNAVAILABLE");
  assert.equal(unavailable.requests.length, 2);
  assert.ok(unavailable.requests.every((request) => request.endpoint.startsWith("http://127.0.0.1:8080/") || request.endpoint.startsWith("http://localhost:8080/")));

  const degraded = loadWorker(async () => ({ ok: false, json: async () => ({ spring_boot: "UP", ml_service: "DOWN", status: "DEGRADED" }) }));
  const health = await degraded.worker.getBackendHealth();
  assert.equal(health.spring_boot, "UP");
  assert.equal(health.ml_service, "DOWN");
  assert.equal(health.ok, false);
});
