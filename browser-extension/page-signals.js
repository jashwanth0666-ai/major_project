// Collect bounded structural counters only. Never read or transmit page text,
// input values, credentials, cookies, or form contents.
(() => {
  function collectPageSignals() {
    let passwordFormCount = 0;
    let crossOriginPasswordFormCount = 0;
    let insecurePasswordFormCount = 0;

    let formsScanned = 0;
    for (const form of document.forms) {
      if (formsScanned++ >= 50) break;
      const hasPassword = form.querySelector('input[type="password"]') !== null;
      if (!hasPassword) continue;
      passwordFormCount++;
      let action;
      try { action = new URL(form.getAttribute("action") || location.href, location.href); }
      catch { continue; }
      if (action.origin !== location.origin) crossOriginPasswordFormCount++;
      if (location.protocol === "https:" && action.protocol === "http:") insecurePasswordFormCount++;
    }

    let hiddenFrameCount = 0;
    let crossOriginFrameCount = 0;
    let framesScanned = 0;
    for (const frame of document.querySelectorAll("iframe")) {
      if (framesScanned++ >= 50) break;
      let frameUrl;
      try { frameUrl = new URL(frame.getAttribute("src") || location.href, location.href); }
      catch { continue; }
      if (frameUrl.origin !== location.origin) crossOriginFrameCount++;
      const style = getComputedStyle(frame);
      const bounds = frame.getBoundingClientRect();
      if (style.display === "none" || style.visibility === "hidden"
          || bounds.width === 0 || bounds.height === 0) hiddenFrameCount++;
    }

    return {
      passwordFormCount,
      crossOriginPasswordFormCount,
      insecurePasswordFormCount,
      hiddenFrameCount,
      crossOriginFrameCount
    };
  }

  let lastSnapshot = "";
  let queued;
  let updates = 0;
  function publishIfChanged() {
    const signals = collectPageSignals();
    const snapshot = JSON.stringify(signals);
    if (snapshot === lastSnapshot || updates >= 4) return;
    lastSnapshot = snapshot;
    updates++;
    try { chrome.runtime.sendMessage({ type: "PAGE_SIGNALS", signals }).catch(() => {}); }
    catch { /* The extension may be unavailable or disabled for this page. */ }
  }

  publishIfChanged();
  const observer = new MutationObserver(() => {
    clearTimeout(queued);
    queued = setTimeout(publishIfChanged, 500);
  });
  observer.observe(document.documentElement, {
    subtree: true,
    childList: true,
    attributes: true,
    attributeFilter: ["action", "src", "type", "style", "hidden"]
  });
  window.addEventListener("pagehide", () => { observer.disconnect(); clearTimeout(queued); }, { once: true });
})();
