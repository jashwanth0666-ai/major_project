(() => {
  console.log("[AI WatchDog] search-results.js v1.1.3 active");
  const badgeClass = "ai-watchdog-rating";
  let timer;
  let requestActive = false;
  let pending = false;
  const resultSelectors = [
    "#search a:has(h3)",
    "li.b_algo h2 a",
    "a[data-testid='result-title-a']",
    ".result__a"
  ];

  chrome.runtime.onMessage.addListener((message) => {
    if (message?.type !== "PROTECTION_STATE_CHANGED") return;
    if (message.enabled) requestRatings();
    else {
      document.querySelectorAll(`.${badgeClass}`).forEach((badge) => badge.remove());
      document.querySelectorAll("[data-awd-rated-url]").forEach((anchor) => delete anchor.dataset.awdRatedUrl);
    }
  });

  function resultUrl(anchor) {
    try {
      const link = new URL(anchor.href, location.href);
      if (link.hostname === location.hostname) {
        let redirect = null;
        if (/google\./i.test(location.hostname) && link.pathname === "/url") redirect = link.searchParams.get("q") || link.searchParams.get("url");
        if (/duckduckgo\.com$/i.test(location.hostname) && link.pathname.startsWith("/l/")) redirect = link.searchParams.get("uddg");
        if (/bing\.com$/i.test(location.hostname) && link.pathname === "/ck/a") {
          const encoded = link.searchParams.get("u") || "";
          if (encoded.startsWith("a1")) {
            try {
              let base64 = encoded.slice(2).replace(/-/g, "+").replace(/_/g, "/");
              base64 += "=".repeat((4 - base64.length % 4) % 4);
              redirect = atob(base64);
            } catch { return null; }
          }
        }
        if (redirect) return normalizeDestination(redirect);
        if (link.hostname === location.hostname) return null;
      }
      return normalizeDestination(link.href);
    } catch { return null; }
  }

  function normalizeDestination(raw) {
    try {
      const url = new URL(raw);
      if (!/^https?:$/.test(url.protocol)) return null;
      if (url.hostname === location.hostname) return null;
      url.username = ""; url.password = ""; url.hash = ""; url.search = "";
      const pathParts = url.pathname.split("/").filter(Boolean);
      if (pathParts.some((part) => {
        let decoded = part;
        try { decoded = decodeURIComponent(part); } catch { /* Treat invalid encoding as opaque. */ }
        return /(?:token|session|password|secret|credential|access[_-]?key|auth[_-]?code)/i.test(decoded)
          || /^[A-Za-z0-9_-]{32,}$/.test(decoded);
      })) url.pathname = "/";
      return url.href;
    } catch { return null; }
  }

  function collect() {
    const found = [];
    const seen = new Set();
    for (const selector of resultSelectors) {
      for (const anchor of document.querySelectorAll(selector)) {
        if (!(anchor instanceof HTMLAnchorElement)) continue;
        const url = resultUrl(anchor);
        if (!url || seen.has(url)) continue;
        if (anchor.dataset.awdRatedUrl === url) continue;
        anchor.querySelectorAll(`.${badgeClass}`).forEach((b) => b.remove());
        if (anchor.nextElementSibling?.classList.contains(badgeClass)) anchor.nextElementSibling.remove();
        seen.add(url);
        found.push({ anchor, url });
        if (found.length >= 8) return found;
      }
    }
    return found;
  }

  function requestRatings() {
    clearTimeout(timer);
    timer = setTimeout(async () => {
      if (requestActive) { pending = true; return; }
      const entries = collect();
      if (!entries.length) return;
      requestActive = true;
      try {
        const reply = await chrome.runtime.sendMessage({ type: "PREVIEW_RESULTS", urls: entries.map((entry) => entry.url) });
        if (reply?.ok && Array.isArray(reply.results)) {
          const byUrl = new Map(reply.results.map((result) => [result.url, result]));
          for (const entry of entries) addBadge(entry.anchor, byUrl.get(entry.url));
        }
      } catch { /* Extension may be reloaded or disabled during the page lifetime. */ }
      requestActive = false;
      if (pending) { pending = false; requestRatings(); }
    }, 400);
  }

  function addBadge(anchor, assessment) {
    if (!assessment) return;
    const url = resultUrl(anchor);
    if (!url) return;
    anchor.dataset.awdRatedUrl = url;

    // Clean up any existing badge associated with this anchor
    anchor.querySelectorAll(`.${badgeClass}`).forEach((b) => b.remove());
    if (anchor.nextElementSibling?.classList.contains(badgeClass)) anchor.nextElementSibling.remove();

    const badge = document.createElement("span");
    badge.className = `${badgeClass} ${ratingClass(assessment)}`;
    badge.setAttribute("role", "img");
    badge.setAttribute("aria-label", ratingLabel(assessment));
    badge.setAttribute("dir", "ltr");

    // Explicitly reset rotation, transformation, orientation, and layout properties
    badge.style.setProperty("display", "inline-flex", "important");
    badge.style.setProperty("flex-direction", "row", "important");
    badge.style.setProperty("align-items", "center", "important");
    badge.style.setProperty("vertical-align", "middle", "important");
    badge.style.setProperty("margin", "0 0 0 8px", "important");
    badge.style.setProperty("direction", "ltr", "important");
    badge.style.setProperty("writing-mode", "horizontal-tb", "important");
    badge.style.setProperty("text-orientation", "mixed", "important");
    badge.style.setProperty("transform", "none", "important");
    badge.style.setProperty("rotate", "0deg", "important");
    badge.style.setProperty("scale", "1", "important");
    badge.style.setProperty("cursor", "default", "important");

    badge.addEventListener("click", (e) => {
      e.stopPropagation();
    });

    const shadow = badge.attachShadow({ mode: "open" });
    const style = document.createElement("style");
    style.textContent = `
      :host {
        all: initial !important;
        direction: ltr !important;
        display: inline-flex !important;
        flex-direction: row !important;
        align-items: center !important;
        vertical-align: middle !important;
        margin: 0 0 0 8px !important;
        padding: 2px 7px !important;
        border: 1px solid !important;
        border-radius: 999px !important;
        white-space: nowrap !important;
        font: 600 11px/1.5 system-ui, -apple-system, sans-serif !important;
        writing-mode: horizontal-tb !important;
        transform: none !important;
        rotate: 0deg !important;
        scale: 1 !important;
        cursor: default !important;
      }
      .content {
        display: inline-flex !important;
        flex-direction: row !important;
        align-items: center !important;
        gap: 4px !important;
        direction: ltr !important;
        writing-mode: horizontal-tb !important;
        transform: none !important;
        rotate: 0deg !important;
        scale: 1 !important;
      }
      .content span {
        direction: ltr !important;
        writing-mode: horizontal-tb !important;
        transform: none !important;
        rotate: 0deg !important;
        scale: 1 !important;
        font-family: system-ui, -apple-system, sans-serif !important;
        font-size: 11px !important;
        font-weight: 600 !important;
      }
      img { display: block; flex: 0 0 13px; width: 13px; height: 13px; transform: none !important; rotate: 0deg !important; }
      :host(.awd-safe) { color: #176b3a !important; background: #e7f6ec !important; border-color: currentColor !important; }
      :host(.awd-caution) { color: #855600 !important; background: #fff3cd !important; border-color: currentColor !important; }
      :host(.awd-danger) { color: #a21c28 !important; background: #fde8e9 !important; border-color: currentColor !important; }
      :host(.awd-unknown) { color: #586273 !important; background: #edf0f4 !important; border-color: currentColor !important; }
    `;
    const icon = document.createElement("img");
    icon.src = chrome.runtime.getURL(`assets/${ratingIcon(assessment)}`);
    icon.alt = "";
    icon.setAttribute("aria-hidden", "true");
    const content = document.createElement("span");
    content.className = "content";
    const label = document.createElement("span");
    label.setAttribute("dir", "ltr");
    label.textContent = ratingText(assessment);
    content.append(icon, label);
    shadow.append(style, content);

    // Target the heading inside anchor (for Google), or anchor itself (Bing / DuckDuckGo)
    // to keep the badge beside the title text and avoid Google's rotated breadcrumb/3-dots slot
    const targetHeading = anchor.querySelector("h3, h2") || anchor;
    const appendTarget = targetHeading.querySelector(":scope > div, :scope > span") || targetHeading;
    appendTarget.appendChild(badge);
  }

  function ratingIcon(item) {
    const cls = ratingClass(item);
    return cls === "awd-danger" ? "circle-x.svg"
      : cls === "awd-caution" ? "triangle-alert.svg"
      : cls === "awd-safe" ? "circle-check.svg"
      : "circle-help.svg";
  }

  function ratingClass(item) {
    if (item.state !== "ASSESSED") return "awd-unknown";
    if (item.decision === "BLOCK" && item.riskLevel === "HIGH_RISK") return "awd-danger";
    if (item.decision === "WARN" || item.decision === "REVIEW" || item.riskLevel === "SUSPICIOUS") return "awd-caution";
    if (item.decision === "ALLOW" && item.riskLevel === "SAFE") return "awd-safe";
    return "awd-unknown";
  }

  function ratingText(item) {
    const cls = ratingClass(item);
    return cls === "awd-danger" ? "WatchDog: dangerous" : cls === "awd-caution" ? "WatchDog: caution" : cls === "awd-safe" ? "WatchDog: low risk" : "WatchDog: unknown";
  }
  function ratingLabel(item) { return `${ratingText(item)}. Based on available AI WatchDog checks; not a guarantee.`; }

  const observer = new MutationObserver(requestRatings);
  observer.observe(document.documentElement, { childList: true, subtree: true });
  window.addEventListener("popstate", requestRatings);
  window.addEventListener("hashchange", requestRatings);
  requestRatings();
})();
