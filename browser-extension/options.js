const tokenInput = document.getElementById("token");
const statusNode = document.getElementById("status");
const tokenKey = "localApiToken";

chrome.storage.local.get(tokenKey).then((stored) => {
  tokenInput.value = typeof stored[tokenKey] === "string" ? stored[tokenKey] : "";
});

document.getElementById("save").addEventListener("click", async () => {
  const token = tokenInput.value.trim();
  if (!/^[a-f0-9]{64,}$/i.test(token)) {
    statusNode.textContent = "Enter the full hexadecimal extension token (at least 64 characters).";
    return;
  }
  await chrome.storage.local.set({ [tokenKey]: token });
  statusNode.textContent = "Token saved. Browser URL checks are ready.";
});

document.getElementById("clear").addEventListener("click", async () => {
  await chrome.storage.local.remove(tokenKey);
  tokenInput.value = "";
  statusNode.textContent = "Token cleared. Browser URL checks will remain unavailable until configured.";
});
