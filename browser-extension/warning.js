let blockedUrl = "";
chrome.tabs.getCurrent((tab) => {
  const ruleId = Number(new URLSearchParams(location.search).get("ruleId"));
  chrome.runtime.sendMessage({ type: "GET_CURRENT_ASSESSMENT", tabId: tab?.id, ruleId }).then((item) => {
    const enforcedBlock = item?.decision === "BLOCK" && (item?.riskLevel === "HIGH_RISK" || item?.domainDenied);
    if (item?.state !== "ASSESSED" || !enforcedBlock || item?.enforcement !== "RULE_APPLIED") {
      document.querySelector("h1").textContent = "This warning link is unavailable";
      document.getElementById("host").textContent = "No matching active AI WatchDog warning rule was found.";
      document.getElementById("warning").hidden = false;
      return;
    }
    let host = "Destination unavailable";
    try { host = new URL(item?.url).hostname; } catch { /* Keep safe fallback. */ }
    blockedUrl = item?.url || "";
    document.getElementById("host").textContent = host;
    const reasons = document.getElementById("reasons");
    const reasonList = Array.isArray(item?.reasons) ? item.reasons.slice(0, 12) : [];
    if (reasonList.length) for (const reason of reasonList) { const li = document.createElement("li"); li.textContent = reason; reasons.append(li); }
    else { const li = document.createElement("li"); li.textContent = "The policy marked this destination as high risk."; reasons.append(li); }
    document.getElementById("warning").hidden = false;
  }).catch(() => {
    document.querySelector("h1").textContent = "Warning details are unavailable";
    document.getElementById("host").textContent = "The local assessment details could not be loaded.";
    document.getElementById("warning").hidden = false;
  });
});
document.getElementById("back").addEventListener("click", () => {
  try {
    const referrer = new URL(document.referrer);
    referrer.search = ""; referrer.hash = ""; referrer.username = ""; referrer.password = "";
    if (/^https?:$/.test(referrer.protocol) && referrer.href === blockedUrl) {
      location.replace("about:blank");
      return;
    }
  } catch { /* Use the browser history fallback. */ }
  history.back();
  setTimeout(() => { if (location.href.includes("warning.html")) location.replace("about:blank"); }, 400);
});
document.getElementById("details").addEventListener("click", () => {
  const ruleId = Number(new URLSearchParams(location.search).get("ruleId"));
  chrome.tabs.getCurrent((tab) => {
    const tabId = tab?.id;
    chrome.tabs.create({ url: chrome.runtime.getURL(`report.html?tabId=${encodeURIComponent(String(tabId ?? ""))}&ruleId=${Number.isInteger(ruleId) ? ruleId : ""}`) });
  });
});
