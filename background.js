const API_BASE = "https://ip2whois.ru/api";
const DEFAULT_ICON = "images/icon128.png";
const CHROME_FALLBACK_ICON = "ip2whois.png";
const CACHE_TTL_SECONDS = 1200;

chrome.tabs.onActivated.addListener((activeInfo) => {
  chrome.tabs.get(activeInfo.tabId, (tab) => {
    if (chrome.runtime.lastError || !tab?.url) return;
    changeIco(tab.url);
  });
});

chrome.tabs.onUpdated.addListener((tabId, change, tab) => {
  if (tab.active && (change.url || change.status === "complete")) {
    const targetUrl = change.url || tab.url;
    if (targetUrl) {
      changeIco(targetUrl);
    }
  }
});

chrome.tabs.onReplaced.addListener((addedTabId) => {
  chrome.tabs.get(addedTabId, (tab) => {
    if (chrome.runtime.lastError || !tab?.active || !tab?.url) return;
    changeIco(tab.url);
  });
});

function isNewerVersion(remoteVersion, currentVersion) {
  if (!remoteVersion || !currentVersion) return false;
  const remoteParts = String(remoteVersion).replace(/^v/i, "").trim().split(".").map(Number);
  const currentParts = String(currentVersion).replace(/^v/i, "").trim().split(".").map(Number);
  const maxLength = Math.max(remoteParts.length, currentParts.length);

  for (let i = 0; i < maxLength; i++) {
    const r = Number.isNaN(remoteParts[i]) ? 0 : (remoteParts[i] || 0);
    const c = Number.isNaN(currentParts[i]) ? 0 : (currentParts[i] || 0);
    if (r > c) return true;
    if (r < c) return false;
  }
  return false;
}

function updater() {
  const manifest = chrome.runtime.getManifest();
  const cacheKey = "ip2whois-updated";

  chrome.storage.local.get(cacheKey, (data2) => {
    const item = data2[cacheKey];

    if (item && item.expired && item.expired > Date.now()) {
      const hasUpdate = isNewerVersion(item.version, manifest.version);
      chrome.action.setBadgeText({ text: hasUpdate ? "!" : "" });
      return;
    }

    fetch(`${API_BASE}/latest`)
      .then((res) => res.json())
      .then((data) => {
        if (data?.success) {
          const hasUpdate = isNewerVersion(data.version, manifest.version);
          chrome.action.setBadgeText({ text: hasUpdate ? "!" : "" });
          storage_set(cacheKey, data, 1800);
        }
      })
      .catch((err) => console.warn("Update check failed:", err));
  });
}

updater();

if (chrome.alarms) {
  chrome.alarms.create("updater", { periodInMinutes: 30 });
  chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "updater") updater();
  });
}

function storage_set(key, data, expired = CACHE_TTL_SECONDS) {
  const payload = { ...data, expired: Date.now() + expired * 1000 };
  chrome.storage.local.set({ [key]: payload });
}

function changeIco(link, tries = 0) {
  if (!link) return;

  let parsed;
  try {
    parsed = new URL(link);
  } catch {
    chrome.action.setIcon({ path: { "128": DEFAULT_ICON } });
    return;
  }

  if (parsed.protocol === "http:" || parsed.protocol === "https:") {
    const host = parsed.hostname.toLowerCase();
    const targetType = detectTargetType(host);

    if (!targetType) {
      chrome.action.setIcon({ path: { "128": DEFAULT_ICON } });
      return;
    }

    const c_key = "ip2whois-" + host.replace(/[.:]/g, "_");

    chrome.storage.local.get(c_key, (data) => {
      const cache = data[c_key];

      if (cache && cache.img && (!cache.expired || cache.expired > Date.now())) {
        chrome.action.setIcon({ path: { "128": cache.img } });
        return;
      }

      if (cache && cache.expired <= Date.now()) {
        chrome.storage.local.remove([c_key]);
      }

      fetch(`${API_BASE}/whoisinfo/${targetType}/${encodeURIComponent(host)}`)
        .then((response) => response.text())
        .then((text) => {
          try {
            return JSON.parse(text);
          } catch {
            if (tries < 3) {
              setTimeout(() => changeIco(link, tries + 1), 1000);
            }
            return null;
          }
        })
        .then((resData) => {
          if (!resData) return;
          if (resData.success && resData.img) {
            storage_set(c_key, resData);
            chrome.action.setIcon({ path: { "128": resData.img } });
          } else {
            chrome.action.setIcon({ path: { "128": DEFAULT_ICON } });
          }
        })
        .catch(() => {
          if (tries < 3) {
            setTimeout(() => changeIco(link, tries + 1), 1000);
          } else {
            chrome.action.setIcon({ path: { "128": DEFAULT_ICON } });
          }
        });
    });
    return;
  }

  if (parsed.protocol === "chrome:") {
    const c_key = "ip2whois-chrome";

    chrome.storage.local.get(c_key, (data) => {
      const cache = data[c_key];

      if (cache && cache.img && (!cache.expired || cache.expired > Date.now())) {
        chrome.action.setIcon({ path: { "512": cache.img } });
        return;
      }

      if (cache && cache.expired <= Date.now()) {
        chrome.storage.local.remove([c_key]);
      }

      fetch(`${API_BASE}/whoisinfo/ip/my`)
        .then((response) => response.json())
        .then((resData) => {
          if (resData?.success && resData.img) {
            storage_set(c_key, resData);
            chrome.action.setIcon({ path: { "512": resData.img } });
          } else {
            chrome.action.setIcon({ path: { "512": CHROME_FALLBACK_ICON } });
          }
        })
        .catch(() => {
          chrome.action.setIcon({ path: { "512": CHROME_FALLBACK_ICON } });
        });
    });
    return;
  }

  chrome.action.setIcon({ path: { "128": DEFAULT_ICON } });
}

function detectTargetType(host) {
  if (validateIP(host) || isIPv6(host)) return "ip";
  const domainRegex = /^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$/;
  return domainRegex.test(host) ? "domain" : null;
}

function validateIP(ip) {
  const parts = ip.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isIPv6(value) {
  const components = value.split(":");
  if (components.length < 2 || components.length > 8) return false;
  if (components[0] !== "" || components[1] !== "") {
    if (!components[0].match(/^[\da-f]{1,4}/i)) return false;
  }
  let zeroCompressions = 0;
  for (let i = 1; i < components.length; ++i) {
    if (components[i] === "") {
      if (++zeroCompressions > 1) return false;
      continue;
    }
    if (!components[i].match(/^[\da-f]{1,4}/i)) return false;
  }
  return true;
}
