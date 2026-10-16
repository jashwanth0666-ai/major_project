const hostnameNode = document.getElementById("hostname");
const ratingNode = document.getElementById("rating");
const summaryNode = document.getElementById("summary");
const timestampNode = document.getElementById("timestamp");
const reasonsNode = document.getElementById("reasons");
const searchNote = document.getElementById("search-note");
const protection = document.getElementById("protection");
let activeTab;

async function send(message) { return chrome.runtime.sendMessage(message); }
function classify(item) {
  if (item.state === "UNAVAILABLE") return ["gray", "Temporarily unavailable"];
  if (item.state === "PAUSED") return ["gray", "Protection paused"];
  if (item.state === "SEARCH_PAGE") return ["gray", "Search results page"];
  if (item.state !== "ASSESSED") return ["gray", "Unknown / not assessed"];
  if (item.decision === "BLOCK" && item.riskLevel === "HIGH_RISK") return ["red", item.enforcement === "DISABLED" ? "Dangerous — protection paused" : item.enforcement === "RULE_APPLIED" ? "Dangerous — browser warning active" : "Dangerous — warning unavailable"];
  if (["WARN", "REVIEW"].includes(item.decision) || item.riskLevel === "SUSPICIOUS") return ["yellow", "Caution advised"];
  if (item.decision === "ALLOW" && item.riskLevel === "SAFE") return ["green", "Low risk from available checks"];
  return ["gray", "Unknown / not assessed"];
}
function hostFor(raw) { try { return new URL(raw).hostname; } catch { return "This page cannot be assessed"; } }
function timestamp(value) { return Number.isFinite(value) ? `Received by extension: ${new Date(value).toLocaleString()}` : ""; }

async function refresh() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  activeTab = tab;
  const item = await send({ type: "GET_CURRENT_ASSESSMENT", tabId: tab?.id });
  hostnameNode.textContent = hostFor(item?.url || tab?.url || "");
  const [color, label] = classify(item || { state: "UNKNOWN" });
  ratingNode.className = `status ${color}`;
  ratingNode.textContent = label;
  reasonsNode.replaceChildren();
  summaryNode.textContent = item?.state === "SEARCH_PAGE" ? "Search result destinations receive separate, on-demand checks." : item?.state === "PAUSED" ? "Browser checks are paused for this tab." : item?.state === "UNAVAILABLE" ? "The local AI WatchDog backend did not return an assessment." : item?.state === "ASSESSED" ? `${item.riskLevel} · policy ${item.decision}` : "No assessment is available for this tab.";
  for (const reason of (item?.reasons || []).slice(0, 8)) { const li = document.createElement("li"); li.textContent = reason; reasonsNode.append(li); }
  timestampNode.textContent = timestamp(item?.timestamp);
  searchNote.hidden = item?.state !== "SEARCH_PAGE";
  const state = await send({ type: "GET_PROTECTION_STATE" });
  protection.checked = state?.enabled !== false;
  document.getElementById("protection-description").textContent = protection.checked ? "Navigation checks and supported search ratings are on." : "Checks and browser warning rules are paused.";
  const health = await send({ type: "GET_HEALTH" });
  document.getElementById("backend").textContent = health?.spring_boot ? `Spring Boot: ${health.spring_boot} · ML service: ${health.ml_service || "status unavailable"}` : `Local backend unavailable (${health?.state || "connection error"}).`;
}

protection.addEventListener("change", async () => {
  protection.disabled = true;
  const result = await send({ type: "SET_PROTECTION", enabled: protection.checked });
  protection.disabled = false;
  if (!result?.ok) await refresh(); else await refresh();
});
document.getElementById("report").addEventListener("click", () => { if (activeTab?.id !== undefined) void send({ type: "OPEN_REPORT", tabId: activeTab.id }); });
document.getElementById("recheck").addEventListener("click", async (event) => {
  const button = event.currentTarget;
  button.disabled = true;
  try {
    await send({ type: "RECHECK_CURRENT", tabId: activeTab?.id });
    await refresh();
  } catch {
    document.getElementById("backend").textContent = "Could not refresh the assessment. Check that the extension service worker and local backend are available.";
  } finally {
    button.disabled = false;
  }
});
void refresh();
