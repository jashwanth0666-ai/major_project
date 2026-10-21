const query = new URLSearchParams(location.search);
const tabId = Number(query.get("tabId"));
const ruleId = Number(query.get("ruleId"));
let currentItem = null;
function safeHost(raw) { try { return new URL(raw).hostname; } catch { return "No website assessment available"; } }
function displayUrl(raw) { try { const url = new URL(raw); url.username = ""; url.password = ""; url.search = ""; url.hash = ""; return url.href; } catch { return ""; } }
function rating(item) {
  if (item.state === "UNAVAILABLE") return ["gray", "Temporarily unavailable"];
  if (item.state === "PAUSED") return ["gray", "Protection paused"];
  if (item.state === "SEARCH_PAGE") return ["gray", "Search results page — destinations checked separately"];
  if (item.state !== "ASSESSED") return ["gray", "Unknown / not assessed"];
  if (item.decision === "BLOCK") return ["red", item.domainDenied ? (item.enforcement === "DISABLED" ? "Denied by local domain rule — protection paused" : item.enforcement === "RULE_APPLIED" ? "Denied by local domain rule — warning rule applied" : "Denied by local domain rule — warning unavailable") : item.enforcement === "DISABLED" ? "Blocked — protection paused" : item.enforcement === "RULE_APPLIED" ? "Blocked — browser warning rule applied" : "Blocked — browser warning unavailable"];
  if (item.domainAllowlisted && item.decision === "ALLOW") return ["green", "Domain exception — URL model skipped"];
  if (item.hostnameConcern) return ["yellow", "Caution advised — hostname evidence"];
  if (["WARN", "REVIEW"].includes(item.decision) || item.riskLevel === "SUSPICIOUS") return ["yellow", "Caution advised"];
  if (item.decision === "ALLOW" && item.riskLevel === "SAFE") return ["green", "Low risk from available checks"];
  return ["gray", "Unknown / not assessed"];
}
function enforcementSummary(item) {
  if (item?.domainDenied && item?.decision === "BLOCK") {
    if (item.enforcement === "RULE_APPLIED") return "A host-wide redirect rule was installed for this exact hostname. The first visit may begin loading before assessment completes.";
    if (item.enforcement === "DISABLED") return "Protection was paused and its dynamic warning rules were removed.";
    return "The local domain deny rule returned BLOCK, but a browser warning rule could not be installed.";
  }
  if (item?.decision === "BLOCK" && item.enforcement === "RULE_APPLIED") return "A dynamic navigation redirect rule was installed for the assessed URL. The first visit may begin loading before assessment completes.";
  if (item?.decision === "BLOCK" && item.enforcement === "DISABLED") return "Protection was paused and its dynamic navigation rules were removed.";
  if (item?.decision === "BLOCK") return "The policy returned BLOCK, but a navigation rule could not be installed for this URL.";
  return "No navigation block is active for this result.";
}
async function render() {
  let [item, health] = await Promise.all([
    chrome.runtime.sendMessage({ type: "GET_CURRENT_ASSESSMENT", tabId: Number.isInteger(tabId) ? tabId : undefined, ruleId: Number.isInteger(ruleId) && ruleId > 0 ? ruleId : undefined }),
    chrome.runtime.sendMessage({ type: "GET_HEALTH" })
  ]);
  if (item?.state === "ASSESSED" && typeof item.assessmentId === "string") {
    const storedAssessment = await chrome.runtime.sendMessage({
      type: "GET_BACKEND_ASSESSMENT",
      tabId: Number.isInteger(tabId) ? tabId : undefined,
      ruleId: Number.isInteger(ruleId) && ruleId > 0 ? ruleId : undefined,
      assessmentId: item.assessmentId
    }).catch(() => null);
    if (storedAssessment?.state === "ASSESSED") item = storedAssessment;
  }
  document.getElementById("host").textContent = safeHost(item?.url);
  currentItem = item;
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
    ? `${reputation.status || "Unknown"} · Provider ${reputation.provider || "unknown"}`
    : "Unavailable.";
  const pageSignals = item?.evidence?.browserPageSignals;
  document.getElementById("page-signals").textContent = pageSignals
    ? `${pageSignals.passwordFormCount} password forms · ${pageSignals.crossOriginPasswordFormCount} cross-site password forms · ${pageSignals.insecurePasswordFormCount} insecure password forms · ${pageSignals.hiddenFrameCount} hidden frames · ${pageSignals.crossOriginFrameCount} cross-site frames. No form values or page text were sent.`
    : "No page signal payload was available.";
  const redirectHosts = Array.isArray(pageSignals?.redirectHosts) ? pageSignals.redirectHosts.slice(0, 6) : [];
  document.getElementById("redirect-chain").textContent = redirectHosts.length > 1
    ? `${redirectHosts.join(" → ")}. Paths, queries, and fragments were not sent.`
    : "No cross-host redirect was observed.";
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
    button.onclick = async () => {
      feedbackButtons.forEach((entry) => { entry.disabled = true; });
      button.classList.add("is-loading");
      button.setAttribute("aria-busy", "true");
      const feedbackStatus = document.getElementById("feedback-status");
      feedbackStatus.dataset.state = "pending";
      feedbackStatus.textContent = "Submitting feedback…";
      let feedbackSaved = false;
      try {
        const result = await chrome.runtime.sendMessage({
          type: "SUBMIT_FEEDBACK",
          tabId,
          ruleId: Number.isInteger(ruleId) && ruleId > 0 ? ruleId : undefined,
          assessmentId: item.assessmentId,
          label: button.dataset.feedback
        });
        feedbackSaved = Boolean(result?.ok);
      } catch { /* Show the same local-backend message for connection failures. */ }
      feedbackStatus.dataset.state = feedbackSaved ? "success" : "error";
      feedbackStatus.textContent = feedbackSaved
        ? "Feedback saved locally for later review. It does not retrain the model."
        : "Feedback could not be saved. Check that the local backend is available.";
      button.classList.remove("is-loading");
      button.removeAttribute("aria-busy");
      if (!feedbackSaved) feedbackButtons.forEach((entry) => { entry.disabled = false; });
    };
  }
}
async function renderUntilAssessmentArrives() {
  await render();
  if (currentItem?.state !== "UNKNOWN") return;
  // Navigation analysis completes asynchronously after the page finishes loading.
  // Keep the report connected to that result when it opens during inference.
  const deadline = Date.now() + 15_000;
  while (Date.now() < deadline && currentItem?.state === "UNKNOWN") {
    await new Promise((resolve) => setTimeout(resolve, 500));
    const item = await chrome.runtime.sendMessage({
      type: "GET_CURRENT_ASSESSMENT",
      tabId: Number.isInteger(tabId) ? tabId : undefined,
      ruleId: Number.isInteger(ruleId) && ruleId > 0 ? ruleId : undefined
    });
    if (item?.state !== "UNKNOWN") {
      await render();
      break;
    }
  }
}
const refreshButton = document.getElementById("refresh-assessment");
refreshButton.hidden = !Number.isInteger(tabId) || tabId <= 0 || (Number.isInteger(ruleId) && ruleId > 0);
refreshButton.addEventListener("click", async () => {
  const label = refreshButton.textContent;
  refreshButton.disabled = true;
  refreshButton.classList.add("is-loading");
  refreshButton.setAttribute("aria-busy", "true");
  refreshButton.textContent = "Checking";
  try {
    const result = await chrome.runtime.sendMessage({ type: "RECHECK_CURRENT", tabId });
    if (result?.ok) await render();
    else document.getElementById("backend").textContent = "Could not request a fresh assessment for this tab.";
  } catch {
    document.getElementById("backend").textContent = "Could not reach the extension service worker. Reopen the report and try again.";
  } finally {
    refreshButton.disabled = false;
    refreshButton.classList.remove("is-loading");
    refreshButton.removeAttribute("aria-busy");
    refreshButton.textContent = label;
  }
});
void renderUntilAssessmentArrives();
