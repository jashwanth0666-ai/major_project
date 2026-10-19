const query = new URLSearchParams(location.search);
const tabId = Number(query.get("tabId"));
const ruleId = Number(query.get("ruleId"));
function safeHost(raw) { try { return new URL(raw).hostname; } catch { return "No website assessment available"; } }
function displayUrl(raw) { try { const url = new URL(raw); url.username = ""; url.password = ""; url.search = ""; url.hash = ""; return url.href; } catch { return ""; } }
function rating(item) {
  if (item.state === "UNAVAILABLE") return ["gray", "Temporarily unavailable"];
  if (item.state === "PAUSED") return ["gray", "Protection paused"];
  if (item.state === "SEARCH_PAGE") return ["gray", "Search results page — destinations checked separately"];
  if (item.state !== "ASSESSED") return ["gray", "Unknown / not assessed"];
  if (item.domainDenied && item.decision === "BLOCK") return ["red", item.enforcement === "DISABLED" ? "Denied by local domain rule — protection paused" : item.enforcement === "RULE_APPLIED" ? "Denied by local domain rule — warning rule applied" : "Denied by local domain rule — warning unavailable"];
  if (item.decision === "BLOCK" && item.riskLevel === "HIGH_RISK") return ["red", item.enforcement === "DISABLED" ? "High risk — protection paused" : item.enforcement === "RULE_APPLIED" ? "High risk — browser warning rule applied" : "High risk — browser warning unavailable"];
  if (item.hostnameConcern) return ["yellow", "Caution advised — hostname evidence"];
  if (["WARN", "REVIEW"].includes(item.decision) || item.riskLevel === "SUSPICIOUS") return ["yellow", "Caution advised"];
  if (item.decision === "ALLOW" && item.riskLevel === "SAFE") return ["green", "Low risk from available checks"];
  return ["gray", "Unknown / not assessed"];
}
function enforcementSummary(item) {
  if (item?.domainDenied && item?.decision === "BLOCK") {
    if (item.enforcement === "RULE_APPLIED") return "Browser enforcement: a host-wide redirect rule was installed for this exact hostname. The first visit may begin loading before assessment completes.";
    if (item.enforcement === "DISABLED") return "Browser enforcement: protection was paused and its dynamic warning rules were removed.";
    return "Browser enforcement: the local domain deny rule returned BLOCK, but a browser warning rule could not be installed.";
  }
  if (item?.decision === "BLOCK" && item?.riskLevel === "HIGH_RISK" && item.enforcement === "RULE_APPLIED") return "Browser enforcement: a dynamic navigation redirect rule was installed for the assessed URL path. The first visit may begin loading before assessment completes.";
  if (item?.decision === "BLOCK" && item?.riskLevel === "HIGH_RISK" && item.enforcement === "DISABLED") return "Browser enforcement: protection was paused and its dynamic navigation rules were removed.";
  if (item?.decision === "BLOCK" && item?.riskLevel === "HIGH_RISK") return "Browser enforcement: the policy returned BLOCK, but a navigation rule could not be installed for this URL.";
  return "Browser enforcement: no navigation block is active for this result.";
}
async function render() {
  const [item, health] = await Promise.all([
    chrome.runtime.sendMessage({ type: "GET_CURRENT_ASSESSMENT", tabId: Number.isInteger(tabId) ? tabId : undefined, ruleId: Number.isInteger(ruleId) && ruleId > 0 ? ruleId : undefined }),
    chrome.runtime.sendMessage({ type: "GET_HEALTH" })
  ]);
  document.getElementById("host").textContent = safeHost(item?.url);
  document.getElementById("url").textContent = displayUrl(item?.url);
  const [color, label] = rating(item || { state: "UNKNOWN" });
  const pill = document.getElementById("rating"); pill.className = `status ${color}`; pill.textContent = label;
  document.getElementById("decision").textContent = item?.state === "ASSESSED" ? `Risk level: ${item.riskLevel} · Policy: ${item.decision} · Model prediction: ${item.prediction}` : "No URL assessment is available.";
  document.getElementById("timestamp").textContent = Number.isFinite(item?.timestamp) ? `Received by extension: ${new Date(item.timestamp).toLocaleString()}` : "Assessment time unavailable";
  const uncorroborated = item?.decision === "REVIEW" && item?.prediction === "PHISHING";
  const ml = item?.state === "ASSESSED" && Number.isFinite(item.probability)
    ? `${uncorroborated ? "Uncorroborated model probability" : "Model phishing probability"}: ${(item.probability * 100).toFixed(1)}% · Model risk score: ${item.riskScore ?? "unavailable"} · Label threshold: ${item.threshold ?? "unavailable"}`
    : "Model assessment: unavailable or not yet completed.";
  document.getElementById("ml").textContent = ml;
  const reputation = item?.evidence?.urlReputation;
  document.getElementById("intel").textContent = reputation
    ? `Threat intelligence: ${reputation.status || "unknown"} · provider ${reputation.provider || "unknown"}`
    : "Threat intelligence: unavailable.";
  const pageSignals = item?.evidence?.browserPageSignals;
  document.getElementById("page-signals").textContent = pageSignals
    ? `Local page structure: ${pageSignals.passwordFormCount} password forms · ${pageSignals.crossOriginPasswordFormCount} cross-site password forms · ${pageSignals.insecurePasswordFormCount} insecure password forms · ${pageSignals.hiddenFrameCount} hidden frames · ${pageSignals.crossOriginFrameCount} cross-site frames. No form values or page text were sent.`
    : "Local page structure: no page signal payload was available.";
  document.getElementById("backend").textContent = health?.spring_boot ? `Backend: Spring Boot ${health.spring_boot} · ML service ${health.ml_service || "status unavailable"}` : `Backend unavailable (${health?.state || "connection error"}).`;
  document.getElementById("enforcement").textContent = enforcementSummary(item);
  const list = document.getElementById("reasons"); list.replaceChildren();
  const reasons = Array.isArray(item?.reasons) ? item.reasons.slice(0, 12) : [];
  if (!reasons.length) reasons.push(item?.state === "UNAVAILABLE" ? "The local backend could not provide an assessment." : "No assessment reasons are available.");
  for (const reason of reasons) { const li = document.createElement("li"); li.textContent = reason; list.append(li); }
  const feedbackButtons = [...document.querySelectorAll("[data-feedback]")];
  const feedbackReady = item?.state === "ASSESSED" && typeof item.assessmentId === "string";
  for (const button of feedbackButtons) {
    button.disabled = !feedbackReady;
    button.addEventListener("click", async () => {
      feedbackButtons.forEach((entry) => { entry.disabled = true; });
      const result = await chrome.runtime.sendMessage({
        type: "SUBMIT_FEEDBACK",
        tabId,
        ruleId: Number.isInteger(ruleId) && ruleId > 0 ? ruleId : undefined,
        assessmentId: item.assessmentId,
        label: button.dataset.feedback
      });
      document.getElementById("feedback-status").textContent = result?.ok
        ? "Feedback saved locally for later review. It does not retrain the model."
        : "Feedback could not be saved. Check that the local backend is available.";
      if (!result?.ok) feedbackButtons.forEach((entry) => { entry.disabled = false; });
    }, { once: true });
  }
}
void render();
