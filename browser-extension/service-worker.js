const API_BASES = ["http://127.0.0.1:8080", "http://localhost:8080"];
const NAVIGATION_ENDPOINT = "/api/v1/threat-assessments/url";
const PREVIEW_ENDPOINT = "/api/v1/threat-assessments/url/preview";
const RESULT_LIMIT = 8;
const CACHE_TTL_MS = 5 * 60_000;
const inFlightNavigation = new Map();
const recentlyAssessedNavigation = new Map();
const navigationPending = new Set();
const previewCache = new Map();
const pageSignalsCache = new Map();
const protectionStateKey = "browserProtectionEnabled";
const assessmentStorageKey = "tabAssessments";
const blockedAssessmentStorageKey = "blockedAssessments";
let protectionEnabled = true;
const protectionReady = new Promise((resolve) => chrome.storage.local.get(protectionStateKey, (value) => {
  protectionEnabled = value[protectionStateKey] !== false;
  void reconcileWarningRules().then(resolve).catch(resolve);
}));

chrome.tabs.onActivated.addListener(({ tabId }) => {
  chrome.tabs.get(tabId, (tab) => {
    if (!chrome.runtime.lastError && tab?.status === "complete" && tab?.url) void analyzeNavigation(tab);
  });
});

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "loading") navigationPending.add(tabId);
  if (changeInfo.status === "complete" && tab.active && tab.url) {
    const isNewNavigation = navigationPending.delete(tabId);
    void analyzeNavigation(tab, isNewNavigation);
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  navigationPending.delete(tabId);
  for (const key of recentlyAssessedNavigation.keys()) if (key.startsWith(`${tabId}:`)) recentlyAssessedNavigation.delete(key);
  void chrome.storage.session.get(assessmentStorageKey).then((stored) => {
    const assessments = stored[assessmentStorageKey] || {};
    delete assessments[String(tabId)];
    return chrome.storage.session.set({ [assessmentStorageKey]: assessments });
  });
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message.type !== "string") return false;
  const extensionPage = sender.id === chrome.runtime.id && typeof sender.url === "string"
    && sender.url.startsWith(chrome.runtime.getURL(""));
  if (message.type === "PREVIEW_RESULTS") {
    void protectionReady.then(async () => {
      if (!protectionEnabled || sender.id !== chrome.runtime.id || !sender.tab?.id || !isSearchResultsPage(sender.tab.url)) return { ok: false, error: "unsupported_sender" };
      return { ok: true, results: await previewResults(message.urls) };
    }).then(sendResponse).catch(() => sendResponse({ ok: false, error: "preview_unavailable" }));
    return true;
  }
  if (message.type === "PAGE_SIGNALS") {
    if (!Number.isInteger(sender.tab?.id) || sender.id !== chrome.runtime.id) return false;
    void receivePageSignals(sender.tab, message.signals).then(() => sendResponse({ ok: true }))
      .catch(() => sendResponse({ ok: false }));
    return true;
  }
  if (message.type === "SUBMIT_FEEDBACK") {
    if (!extensionPage) { sendResponse({ ok: false, error: "unsupported_sender" }); return false; }
    void submitFeedback(message.tabId, message.ruleId, message.assessmentId, message.label)
      .then(sendResponse).catch(() => sendResponse({ ok: false, error: "feedback_unavailable" }));
    return true;
  }
  if (message.type === "GET_CURRENT_ASSESSMENT") {
    if (!extensionPage) { sendResponse({ state: "UNKNOWN" }); return false; }
    void (Number.isInteger(message.ruleId) ? getBlockedAssessment(message.ruleId) : getCurrentAssessment(message.tabId ?? sender.tab?.id)).then(sendResponse);
    return true;
  }
  if (message.type === "RECHECK_CURRENT") {
    if (!extensionPage) { sendResponse({ ok: false }); return false; }
    chrome.tabs.get(message.tabId, (tab) => {
      if (chrome.runtime.lastError || !tab?.url) { sendResponse({ ok: false }); return; }
      void analyzeNavigation(tab, true).then(() => sendResponse({ ok: true })).catch(() => sendResponse({ ok: false }));
    });
    return true;
  }
  if (message.type === "GET_HEALTH") {
    if (!extensionPage) { sendResponse({ ok: false, state: "unsupported_sender" }); return false; }
    void getBackendHealth().then(sendResponse);
    return true;
  }
  if (message.type === "GET_PROTECTION_STATE") {
    if (!extensionPage) { sendResponse({ enabled: false }); return false; }
    void protectionReady.then(() => sendResponse({ enabled: protectionEnabled }));
    return true;
  }
  if (message.type === "SET_PROTECTION") {
    if (!extensionPage) { sendResponse({ ok: false, enabled: protectionEnabled }); return false; }
    void setProtection(message.enabled === true).then(sendResponse);
    return true;
  }
  if (message.type === "OPEN_REPORT") {
    if (!extensionPage) { sendResponse({ ok: false }); return false; }
    const tabId = sender.tab?.id ?? message.tabId;
    void getCurrentAssessment(tabId).then((assessment) => {
      const target = chrome.runtime.getURL(`report.html?tabId=${encodeURIComponent(String(tabId ?? ""))}`);
      chrome.tabs.create({ url: target });
    });
    sendResponse({ ok: true });
    return false;
  }
  return false;
});

function sanitizeUrl(rawUrl) {
  try {
    const url = new URL(rawUrl);
    if (url.protocol !== "http:" && url.protocol !== "https:") return null;
    url.username = "";
    url.password = "";
    url.hash = "";
    const segments = url.pathname.split("/").filter(Boolean);
    if (segments.some((part) => {
      let decoded = part;
      try { decoded = decodeURIComponent(part); } catch { /* Keep malformed segments opaque. */ }
      return /(?:token|session|password|secret|credential|access[_-]?key|auth[_-]?code)/i.test(decoded)
        || /^[A-Za-z0-9_-]{32,}$/.test(decoded);
    })) url.pathname = "/";
    url.search = "";
    return url.toString();
  } catch { return null; }
}

function isSearchResultsPage(rawUrl) {
  try {
    const url = new URL(rawUrl);
    const host = url.hostname.toLowerCase();
    if (/^(?:www\.)?google\.[a-z.]+$/.test(host) && url.pathname === "/search") return true;
    if ((host === "bing.com" || host.endsWith(".bing.com")) && url.pathname === "/search") return true;
    if ((host === "duckduckgo.com" || host.endsWith(".duckduckgo.com")) && (url.pathname === "/" || url.pathname === "/html/")) return !!url.searchParams.get("q");
  } catch { /* Ignore malformed and browser-internal locations. */ }
  return false;
}

async function callApi(path, payload) {
  let lastError = "backend_unavailable";
  const credential = await chrome.storage.local.get("localApiToken");
  const token = credential.localApiToken;
  if (typeof token !== "string" || !/^[a-f0-9]{64,}$/i.test(token.trim())) {
    throw new Error("credentials_not_configured");
  }
  for (const base of API_BASES) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12_000);
    try {
      const response = await fetch(`${base}${path}`, {
        method: payload ? "POST" : "GET",
        headers: payload ? { "Content-Type": "application/json", "Authorization": `Bearer ${token.trim()}` } : undefined,
        body: payload ? JSON.stringify(payload) : undefined,
        signal: controller.signal
      });
      if (!response.ok) { lastError = `http_${response.status}`; continue; }
      return await response.json();
    } catch (error) {
      lastError = error?.name === "AbortError" ? "timeout" : "backend_unavailable";
    } finally { clearTimeout(timer); }
  }
  throw new Error(lastError);
}

async function analyzeNavigation(tab, force = false) {
  await protectionReady;
  if (!Number.isInteger(tab?.id) || !tab.url) return;
  if (tab.url.startsWith(chrome.runtime.getURL(""))) return;
  if (!protectionEnabled) {
    await saveAssessment(tab.id, { state: "PAUSED", url: sanitizeUrl(tab.url), timestamp: Date.now() });
    return;
  }
  if (isSearchResultsPage(tab.url)) {
    await saveAssessment(tab.id, { state: "SEARCH_PAGE", url: sanitizeUrl(tab.url), timestamp: Date.now() });
    return;
  }
  const url = sanitizeUrl(tab.url);
  if (!url) {
    await saveAssessment(tab.id, { state: "UNKNOWN", timestamp: Date.now() });
    return;
  }
  const key = `${tab.id}:${url}`;
  const pageSignals = getPageSignals(tab.id, url);
  const previous = await getCurrentAssessment(tab.id);
  if (!force && ["ASSESSED", "UNAVAILABLE"].includes(previous?.state) && previous.url === url && Date.now() - previous.timestamp < 10_000) return;
  const last = recentlyAssessedNavigation.get(key);
  if (!force && last && Date.now() - last < 10_000) return;
  if (inFlightNavigation.has(key)) return inFlightNavigation.get(key);
  const work = (async () => {
    let assessment;
    try {
      const response = await callApi(NAVIGATION_ENDPOINT, { url, ...(pageSignals ? { pageSignals } : {}) });
      assessment = normalizeAssessment(response, url, "ASSESSED");
      recentlyAssessedNavigation.set(key, Date.now());
      while (recentlyAssessedNavigation.size > 512) recentlyAssessedNavigation.delete(recentlyAssessedNavigation.keys().next().value);
      await saveAssessment(tab.id, assessment);
      if (isDangerous(assessment) && protectionEnabled) {
        try { assessment.enforcement = await installWarningRule(tab.id, tab.url, assessment) ? "RULE_APPLIED" : "UNAVAILABLE"; }
        catch { assessment.enforcement = "UNAVAILABLE"; }
        await saveAssessment(tab.id, assessment);
      }
    } catch (error) {
      assessment = { state: "UNAVAILABLE", url, error: error.message, timestamp: Date.now() };
      recentlyAssessedNavigation.set(key, Date.now());
      await saveAssessment(tab.id, assessment);
    }
  })().finally(() => inFlightNavigation.delete(key));
  inFlightNavigation.set(key, work);
  return work;
}

function normalizeAssessment(response, url, state) {
  if (!response || typeof (response.policyVerdict || response.decision) !== "string") {
    throw new Error("invalid_response");
  }
  const model = response.sources?.urlModel || response;
  const decision = response.policyVerdict || response.decision;
  const riskLevel = typeof model.risk_level === "string" ? model.risk_level : "UNKNOWN";
  const modelReasons = Array.isArray(model.reasons) ? model.reasons.map((item) => `URL indicator: ${item}`) : [];
  const evidenceReasons = Array.isArray(response.explanation) ? response.explanation.map((item) => `Assessment: ${item}`) : [];
  return {
    state,
    assessmentId: typeof response.assessmentId === "string" ? response.assessmentId : null,
    correlationId: typeof response.correlationId === "string" ? response.correlationId : null,
    url: sanitizeUrl(model.url || response.url || response.subjectId) || url,
    decision,
    riskLevel,
    prediction: typeof model.prediction === "string" ? model.prediction : "UNKNOWN",
    probability: Number.isFinite(model.phishing_probability) ? model.phishing_probability : null,
    riskScore: Number.isFinite(model.risk_score) ? model.risk_score : null,
    threshold: Number.isFinite(model.threshold) ? model.threshold : null,
    reasons: [...evidenceReasons, ...modelReasons].filter((item) => typeof item === "string").slice(0, 12),
    evidence: response.sources && typeof response.sources === "object" ? response.sources : null,
    domainDenied: response.sources?.localDomainRule?.action === "DENY",
    hostnameConcern: ["KNOWN_MALICIOUS", "SUSPICIOUS"].includes(response.sources?.urlReputation?.status)
      || (Array.isArray(response.sources?.urlHostSignals?.signals)
        && response.sources.urlHostSignals.signals.some((signal) => signal?.severity === "HIGH")),
    assessmentStatus: typeof response.status === "string" ? response.status : "COMPLETE",
    enforcement: "NOT_APPLICABLE",
    timestamp: Date.now()
  };
}

function sanitizePageSignals(raw) {
  if (!raw || typeof raw !== "object") return null;
  const names = ["passwordFormCount", "crossOriginPasswordFormCount", "insecurePasswordFormCount", "hiddenFrameCount", "crossOriginFrameCount"];
  const safe = {};
  for (const name of names) {
    const value = raw[name];
    if (!Number.isInteger(value) || value < 0 || value > 50) return null;
    safe[name] = value;
  }
  return safe;
}

function getPageSignals(tabId, url) {
  const key = `${tabId}:${url}`;
  const entry = pageSignalsCache.get(key);
  if (!entry || Date.now() - entry.timestamp > 60_000) {
    pageSignalsCache.delete(key);
    return null;
  }
  return entry.signals;
}

async function receivePageSignals(tab, rawSignals) {
  await protectionReady;
  if (!protectionEnabled || !tab?.url || isSearchResultsPage(tab.url)) return;
  const signals = sanitizePageSignals(rawSignals);
  const url = sanitizeUrl(tab.url);
  if (!signals || !url) return;
  const tabNow = await chrome.tabs.get(tab.id);
  if (!tabNow?.url || sanitizeUrl(tabNow.url) !== url) return;
  const key = `${tab.id}:${url}`;
  pageSignalsCache.set(key, { signals, timestamp: Date.now() });
  while (pageSignalsCache.size > 256) pageSignalsCache.delete(pageSignalsCache.keys().next().value);

  const inFlight = inFlightNavigation.get(key);
  if (inFlight) await inFlight;
  const current = await getCurrentAssessment(tab.id);
  if (current?.state !== "ASSESSED" || current.url !== url) return;
  const response = await callApi(NAVIGATION_ENDPOINT + "/preview", { url, pageSignals: signals });
  const assessment = normalizeAssessment(response, url, "ASSESSED");
  await saveAssessment(tab.id, assessment);
  if (isDangerous(assessment) && protectionEnabled) {
    try { assessment.enforcement = await installWarningRule(tab.id, tabNow.url, assessment) ? "RULE_APPLIED" : "UNAVAILABLE"; }
    catch { assessment.enforcement = "UNAVAILABLE"; }
    await saveAssessment(tab.id, assessment);
  }
}

async function submitFeedback(tabId, ruleId, assessmentId, label) {
  if (!Number.isInteger(tabId) || !["FALSE_POSITIVE", "FALSE_NEGATIVE", "CORRECT"].includes(label)) {
    return { ok: false, error: "invalid_feedback" };
  }
  const assessment = Number.isInteger(ruleId) ? await getBlockedAssessment(ruleId) : await getCurrentAssessment(tabId);
  if (assessment?.state !== "ASSESSED" || assessment.assessmentId !== assessmentId) {
    return { ok: false, error: "assessment_not_found" };
  }
  const response = await callApi("/api/v1/threat-assessments/feedback", {
    assessmentId,
    correlationId: assessment.correlationId,
    label
  });
  return { ok: response?.accepted === true };
}

function isDangerous(item) {
  return item?.decision === "BLOCK" && (item?.riskLevel === "HIGH_RISK" || item?.domainDenied === true);
}

async function previewResults(rawUrls) {
  if (!Array.isArray(rawUrls)) return [];
  const urls = [...new Set(rawUrls.slice(0, RESULT_LIMIT * 2).map(sanitizeUrl).filter(Boolean))].slice(0, RESULT_LIMIT);
  const now = Date.now();
  for (const [url, entry] of previewCache) if (now - entry.timestamp > CACHE_TTL_MS) previewCache.delete(url);
  const results = new Array(urls.length);
  let cursor = 0;
  const workers = Array.from({ length: Math.min(3, urls.length) }, async () => {
    while (cursor < urls.length) {
      const index = cursor++;
      const url = urls[index];
      const cached = previewCache.get(url);
      if (cached) { results[index] = cached.result; continue; }
      try {
        const response = await callApi(PREVIEW_ENDPOINT, { url });
        const result = normalizeAssessment(response, url, "ASSESSED");
        previewCache.set(url, { timestamp: Date.now(), result });
        results[index] = result;
      } catch { results[index] = { state: "UNAVAILABLE", url }; }
    }
  });
  await Promise.all(workers);
  while (previewCache.size > 256) previewCache.delete(previewCache.keys().next().value);
  return results;
}

async function saveAssessment(tabId, assessment) {
  const values = await chrome.storage.session.get(assessmentStorageKey);
  const all = values[assessmentStorageKey] || {};
  all[String(tabId)] = assessment;
  const keys = Object.keys(all);
  for (const old of keys.slice(0, Math.max(0, keys.length - 100))) delete all[old];
  await chrome.storage.session.set({ [assessmentStorageKey]: all });
  chrome.action.setBadgeText({ tabId, text: assessment.state === "UNAVAILABLE" ? "?" : isDangerous(assessment) ? "!" : "" });
  chrome.action.setBadgeBackgroundColor({ tabId, color: assessment.state === "UNAVAILABLE" ? "#687386" : "#bd2936" });
}

async function getCurrentAssessment(tabId) {
  if (!Number.isInteger(tabId)) return { state: "UNKNOWN" };
  const stored = await chrome.storage.session.get(assessmentStorageKey);
  return stored[assessmentStorageKey]?.[String(tabId)] || { state: "UNKNOWN" };
}

async function getBlockedAssessment(ruleId) {
  const rules = await chrome.declarativeNetRequest.getDynamicRules();
  if (!rules.some((rule) => rule.id === ruleId)) return { state: "UNKNOWN" };
  const stored = await chrome.storage.local.get(blockedAssessmentStorageKey);
  return stored[blockedAssessmentStorageKey]?.[String(ruleId)] || { state: "UNKNOWN" };
}

async function reconcileWarningRules() {
  const rules = await chrome.declarativeNetRequest.getDynamicRules();
  const owned = rules.filter((rule) => rule.id >= 50_000 && rule.id < 60_000);
  if (!protectionEnabled) {
    if (owned.length) await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: owned.map((rule) => rule.id) });
    await chrome.storage.local.remove(blockedAssessmentStorageKey);
    return;
  }
  const stored = await chrome.storage.local.get(blockedAssessmentStorageKey);
  const blocked = stored[blockedAssessmentStorageKey] || {};
  const activeIds = new Set(owned.map((rule) => String(rule.id)));
  const orphanRules = owned.filter((rule) => !blocked[String(rule.id)]);
  const orphanDetails = Object.keys(blocked).filter((id) => !activeIds.has(id));
  if (orphanRules.length) await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: orphanRules.map((rule) => rule.id) });
  for (const id of orphanDetails) delete blocked[id];
  if (orphanDetails.length) await chrome.storage.local.set({ [blockedAssessmentStorageKey]: blocked });
}

async function getBackendHealth() {
  let lastError = "backend_unavailable";
  for (const base of API_BASES) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 4_000);
    try {
      const response = await fetch(`${base}/api/v1/health`, { signal: controller.signal });
      const body = await response.json();
      return { ok: response.ok, ...body, state: response.ok ? "connected" : "degraded" };
    } catch (error) { lastError = error?.name === "AbortError" ? "timeout" : "backend_unavailable"; }
    finally { clearTimeout(timer); }
  }
  return { ok: false, state: lastError };
}

async function setProtection(enabled) {
  await protectionReady;
  protectionEnabled = enabled;
  await chrome.storage.local.set({ [protectionStateKey]: enabled });
  if (!enabled) {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const ours = existing.filter((rule) => rule.id >= 50_000 && rule.id < 60_000).map((rule) => rule.id);
    if (ours.length) await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: ours });
    await chrome.storage.local.remove(blockedAssessmentStorageKey);
    const stored = await chrome.storage.session.get(assessmentStorageKey);
    const assessments = stored[assessmentStorageKey] || {};
    for (const item of Object.values(assessments)) {
      if (isDangerous(item)) item.enforcement = "DISABLED";
    }
    await chrome.storage.session.set({ [assessmentStorageKey]: assessments });
  }
  chrome.tabs.query({}, (tabs) => {
    for (const tab of tabs || []) {
      if (Number.isInteger(tab.id)) chrome.tabs.sendMessage(tab.id, { type: "PROTECTION_STATE_CHANGED", enabled }, () => void chrome.runtime.lastError);
    }
  });
  return { ok: true, enabled };
}

async function installWarningRule(tabId, rawUrl, assessment) {
  const url = sanitizeUrl(rawUrl);
  if (!url || !isDangerous(assessment)) return false;
  let ruleExpression;
  try {
    const original = new URL(rawUrl);
    const target = new URL(url);
    if (assessment.domainDenied) {
      const ruleHost = target.hostname.toLowerCase().replace(/\.$/, "");
      const escapedHost = ruleHost.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      ruleExpression = `^https?://${escapedHost}(:[0-9]+)?(/.*)?$`;
    } else {
      // Do not persist a dynamic rule containing a path segment deliberately removed as sensitive.
      if (original.pathname !== target.pathname) return false;
      const escapedUrl = url.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      ruleExpression = `^${escapedUrl}([?#].*)?$`;
    }
  } catch { return false; }
  const existing = await chrome.declarativeNetRequest.getDynamicRules();
  const existingMatch = existing.find((rule) => rule.condition?.regexFilter === ruleExpression);
  const usedIds = new Set(existing.filter((rule) => rule.id >= 50_000 && rule.id < 60_000).map((rule) => rule.id));
  let ruleId = existingMatch?.id;
  if (ruleId === undefined) {
    for (let candidate = 50_000; candidate < 60_000; candidate++) {
      if (!usedIds.has(candidate)) { ruleId = candidate; break; }
    }
  }
  if (ruleId === undefined) return false;
  const redirect = chrome.runtime.getURL(`warning.html?ruleId=${ruleId}`);
  const replaceIds = existingMatch ? [ruleId] : [];
  const saved = await chrome.storage.local.get(blockedAssessmentStorageKey);
  const blocked = saved[blockedAssessmentStorageKey] || {};
  if (!existingMatch && Object.keys(blocked).length >= 128) {
    const evictIds = Object.entries(blocked)
      .sort((left, right) => (left[1]?.timestamp || 0) - (right[1]?.timestamp || 0))
      .slice(0, Object.keys(blocked).length - 127)
      .map(([id]) => id);
    const numericIds = evictIds.map(Number).filter((id) => usedIds.has(id));
    if (numericIds.length) await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: numericIds });
    for (const id of evictIds) delete blocked[id];
  }
  const previousAssessment = blocked[String(ruleId)];
  blocked[String(ruleId)] = { ...assessment, enforcement: "RULE_APPLIED" };
  const ids = Object.keys(blocked);
  for (const old of ids.slice(0, Math.max(0, ids.length - 128))) delete blocked[old];
  await chrome.storage.local.set({ [blockedAssessmentStorageKey]: blocked });
  try {
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: replaceIds,
      addRules: [{
        id: ruleId,
        priority: assessment.domainDenied ? 2 : 1,
        action: { type: "redirect", redirect: { url: redirect } },
        condition: { regexFilter: ruleExpression, resourceTypes: ["main_frame"] }
      }]
    });
  } catch (error) {
    if (previousAssessment) blocked[String(ruleId)] = previousAssessment;
    else delete blocked[String(ruleId)];
    await chrome.storage.local.set({ [blockedAssessmentStorageKey]: blocked });
    throw error;
  }
  // The first request may have completed before asynchronous analysis. Re-navigate through DNR
  // only after installing a real browser rule, so policy BLOCK produces an actual interstitial.
  chrome.tabs.get(tabId, (tab) => {
    if (!chrome.runtime.lastError && tab?.url && sanitizeUrl(tab.url) === url) chrome.tabs.update(tabId, { url: tab.url });
  });
  return true;
}

