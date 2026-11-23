const API_BASE = "https://ip2whois.ru/api";
const SITE_URL = "https://ip2whois.ru";
const SPEEDTEST_BASE = `${SITE_URL}/testbandwidth/`;
const CACHE_TTL_SECONDS = 1200;
const COUNT_TRY = 4;

let currentLoadedHost = null;
let dynamicCdnOrigin = "https://cdn.ninja";
let speedStarted = false;
let pingDiff = 0;
let totalPercent = 0;
let startSpeedtestTime = 0;

const delay = (ms) => new Promise((res) => setTimeout(res, ms));

document.addEventListener("DOMContentLoaded", async () => {
  const manifest = chrome.runtime.getManifest();
  $("#version").text(manifest.version);
  $("#year_holder").text(new Date().getFullYear());

  $("#speedtestbutton").on("click", runSpeedTest);

  await checkPopupUpdateBanner(manifest.version);

  try {
    const [tab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (tab?.url) {
      await loadTabWhois(tab.url);
    } else {
      showErrorState("No active tab URL");
    }
  } catch (err) {
    console.error("Ошибка получения вкладки:", err);
    showErrorState("Tab access error");
  }
});

chrome.tabs.onActivated.addListener(async (activeInfo) => {
  try {
    const tab = await chrome.tabs.get(activeInfo.tabId);
    if (tab?.url) {
      currentLoadedHost = null;
      await loadTabWhois(tab.url);
    }
  } catch (e) {
    console.warn(e);
  }
});

chrome.tabs.onUpdated.addListener(async (tabId, change, tab) => {
  if (tab.active && change.url) {
    await loadTabWhois(change.url);
  }
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

async function checkPopupUpdateBanner(currentVersion) {
  const cache = await getCache("ip2whois-updated");
  if (cache && cache.version && isNewerVersion(cache.version, currentVersion)) {
    $("#update_list-tab").show();
    $("#update").html(
      `New version is available v ${escapeHtml(cache.version)}: ` +
      `<a href="${escapeURI(cache.href)}" target="_blank">` +
      `<button type="button" class="uk-button uk-button-primary">Download</button></a>`
    );
  }
}

async function getCache(key) {
  try {
    const res = await chrome.storage.local.get(key);
    const item = res[key];
    if (!item) return null;

    const parsed = typeof item === "string" ? JSON.parse(item) : item;
    if (parsed.expired && parsed.expired < Date.now()) {
      await chrome.storage.local.remove(key);
      return null;
    }
    return parsed;
  } catch (err) {
    console.warn("Ошибка чтения кэша:", err);
    return null;
  }
}

async function setCache(key, data, ttlSeconds = CACHE_TTL_SECONDS) {
  try {
    const payload = { ...data, expired: Date.now() + ttlSeconds * 1000 };
    await chrome.storage.local.set({ [key]: payload });
  } catch (err) {
    console.warn("Ошибка записи кэша:", err);
  }
}

async function loadTabWhois(rawUrl) {
  let parsedUrl;
  try {
    parsedUrl = new URL(rawUrl);
  } catch {
    showErrorState("Invalid URL");
    return;
  }

  if (parsedUrl.protocol === "chrome:") {
    if (currentLoadedHost === "chrome://") return;
    currentLoadedHost = "chrome://";
    $("#search").html("<div class='uk-text-center'><div uk-spinner></div></div>");

    try {
      const response = await fetch(`${API_BASE}/whoisinfo/ip/my`);
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      const data = await response.json();

      if (data?.success) {
        const myIp = data.IPv4 || data.IPv6 || "my";
        renderWhoisData(data, "ip", myIp, true);
      } else {
        showErrorState(data?.message || "no connection");
      }
    } catch (err) {
      console.error("Ошибка загрузки IP:", err);
      showErrorState("no connection");
    }
    return;
  }

  if (parsedUrl.protocol === "http:" || parsedUrl.protocol === "https:") {
    const host = parsedUrl.hostname.toLowerCase();
    const proto = parsedUrl.protocol.replace(":", "");

    $("#http-tab").attr("host-name", host);
    $("#http-tab").attr("host-proto", proto);

    if (currentLoadedHost === host) return;
    currentLoadedHost = host;

    $("#search").html("<div class='uk-text-center'><div uk-spinner></div></div>");

    const targetType = detectTargetType(host);
    if (!targetType) {
      const displayHost = decodePunycodeSafe(host);
      $("#search").html(`<a href="${SITE_URL}/domain/${encodeURIComponent(host)}" target="_blank">${escapeHtml(displayHost)}</a>`);
      showErrorState("invalid domain name");
      return;
    }

    const cacheKey = `ip2whois-${host.replace(/[.:]/g, "_")}`;

    try {
      let data = await getCache(cacheKey);
      if (!data) {
        const response = await fetch(`${API_BASE}/whoisinfo/${targetType}/${encodeURIComponent(host)}`);
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        data = await response.json();
        if (data?.success) {
          await setCache(cacheKey, data);
        }
      }

      if (data?.success) {
        renderWhoisData(data, targetType, host, false);
      } else {
        $("#search").html(`<a href="${SITE_URL}/${targetType}/${encodeURIComponent(host)}" target="_blank">${escapeHtml(decodePunycodeSafe(host))}</a>`);
        showErrorState(data?.message || "no connection");
      }
    } catch (err) {
      console.error("Ошибка получения whois:", err);
      $("#search").html(`<a href="${SITE_URL}/${targetType}/${encodeURIComponent(host)}" target="_blank">${escapeHtml(decodePunycodeSafe(host))}</a>`);
      showErrorState("no connection");
    }
    return;
  }

  showErrorState("Unsupported protocol");
}

function updateDynamicCdnFromUrl(imgUrl) {
  if (!imgUrl) return;
  try {
    const parsed = new URL(imgUrl);
    if (parsed.protocol === "https:" || parsed.protocol === "http:") {
      dynamicCdnOrigin = parsed.origin;
    }
  } catch {}
}

function renderWhoisData(data, type, host, isChromePage) {
  updateDynamicCdnFromUrl(data.img || data.ASNimg);

  const linkType = type === "ip" ? "ip" : "domain";
  const displayTitle = type === "domain"
    ? (data.domain_utf8 || decodePunycodeSafe(host))
    : host;

  $("#search").html(`<a href="${SITE_URL}/${linkType}/${encodeURIComponent(host)}" target="_blank">${escapeHtml(displayTitle)}</a>`);

  if (data.IPv4) {
    const v4List = Array.isArray(data.IP_list)
      ? data.IP_list.filter((item) => Number(item.type) === 4).map((item) => escapeHtml(item.value))
      : [];
    $("#IPv4").html(v4List.length > 0 ? v4List.join("<br>") : escapeHtml(data.IPv4));
    $(".IPv4").show();
    if (type === "ip" && (!data.IPv6 || data.IPv6 === "::")) $(".IPv6").hide();
  } else {
    $("#IPv4").text("no info");
    if (isChromePage) $(".IPv4").hide();
  }

  if (data.IPv6 && data.IPv6 !== "::") {
    const v6List = Array.isArray(data.IP_list)
      ? data.IP_list.filter((item) => Number(item.type) === 6).map((item) => escapeHtml(item.value))
      : [];
    $("#IPv6").html(v6List.length > 0 ? v6List.join("<br>") : escapeHtml(data.IPv6));
    $(".IPv6").show();
    if (type === "ip" && !data.IPv4) $(".IPv4").hide();
  } else {
    $("#IPv6").text("no info");
    if (data.IPv6 === "::" || isChromePage) $(".IPv6").hide();
  }

  if (type === "ip" || isChromePage) {
    $(".dns").hide();
  } else if (Array.isArray(data.dns) && data.dns.length > 0) {
    $(".dns").show();
    const dnsHtml = data.dns.map((v) => `${escapeHtml(v.name)} (${escapeHtml(v.ip)})`).join("<br/>");
    $("#dns").html(dnsHtml);
  } else {
    $(".dns").hide();
  }

  if (data.rank) {
    $(".rank").show();
    $("#rank").text(data.rank);
  } else {
    $(".rank").hide();
  }

  let ownerHtml = `<a href="${SITE_URL}/asn/${encodeURIComponent(data.ASN || "")}" target="_blank">${escapeHtml(data.ISP || "Unknown")}</a>`;
  if (data.ASNimg) {
    ownerHtml += ` <img src="${escapeURI(data.ASNimg)}" style="max-height:32px;max-width:150px"/>`;
  }
  $("#owner").html(ownerHtml);

  $("#ptr").text(data.PTR || "-");
  const flagImg = data.img ? `<img src="${escapeURI(data.img)}" width="16" /> ` : "";
  const city = data.City || data.ISP_City;
  const cityPart = city ? `, ${escapeHtml(city)}` : "";
  $("#location").html(`${flagImg}${escapeHtml(data.Country || "Unknown")}${cityPart}`);
}

function showErrorState(message) {
  $("#IPv4, #IPv6, #owner, #location").text(message);
}

$('a[data-toggle="tab"]').on("click", function (e) {
  const tabId = e.target.id;
  if (tabId === "hardware_list-tab") {
    loadHardwareTab();
  } else if (tabId === "http-tab") {
    loadHttpTab();
  }
});

function loadHardwareTab() {
  if ($(".hardware_info").html().trim() !== "") return;

  if (chrome.system?.cpu) {
    chrome.system.cpu.getInfo((data) => {
      $(".hardware_info").append(`<tr><td>Processor:</td><td>${escapeHtml(data.modelName)} x ${data.numOfProcessors}</td></tr>`);

      const arg = getClientInfo();
      if (arg.gpu) {
        $(".hardware_info").append(`<tr><td>GPU:</td><td>${escapeHtml(arg.gpu.model || "Unknown")}</td></tr>`);
        if (arg.gpu.vendor) {
          const vendorSlug = encodeURIComponent(arg.gpu.vendor.toLowerCase());
          $(".hardware_info").append(
            `<tr><td>GPU Vendor:</td><td><img src="${dynamicCdnOrigin}/ip2whois/img/icons/${vendorSlug}.svg" title="${escapeHtml(arg.gpu.vendor)}" style="max-height:20px;max-width:80px;"> ${escapeHtml(arg.gpu.vendor)}</td></tr>`
          );
        }
      }

      if (arg.connection) {
        const connType = arg.connection.effectiveType === "4g" ? "4G/Wifi/Cable" : (arg.connection.effectiveType || "Unsupported");
        $(".hardware_info").append(`<tr><td>Connection:</td><td>${escapeHtml(connType)}</td></tr>`);
        $(".hardware_info").append(`<tr><td id="latency_ping_text">Ping:</td><td id="latency_ping">${arg.connection.rtt ?? "Process."} ms</td></tr>`);
      } else {
        $(".hardware_info").append("<tr><td>Connection:</td><td>Unsupported</td></tr>");
        $(".hardware_info").append("<tr><td>Ping:</td><td id='latency_ping'>Process.</td></tr>");
      }

      pingTestRtt();
    });
  }

  if (chrome.system?.memory) {
    chrome.system.memory.getInfo((data) => {
      $(".hardware_info").append(
        `<tr><td>Memory:</td><td>total: ${bytesToSize(data.capacity)}<br/> free: ${bytesToSize(data.availableCapacity)}</td></tr>`
      );
    });
  }

  if (chrome.system?.display) {
    chrome.system.display.getInfo((data) => {
      if (data?.[0]?.bounds) {
        $(".hardware_info").append(`<tr><td>Display:</td><td>${data[0].bounds.width} x ${data[0].bounds.height}</td></tr>`);
      }
    });
  }
}

function loadHttpTab() {
  if ($("#http_results").html().trim() !== "") return;
  const host = $("#http-tab").attr("host-name");
  const proto = $("#http-tab").attr("host-proto") || "http";
  if (!host) return;

  $.ajax({
    url: `${API_BASE}/test/start/0/${encodeURIComponent(host)}`,
    method: "POST",
    data: { proto },
    headers: { Accept: "application/json" }
  })
    .done((data) => {
      if (data?.success && Array.isArray(data.serverlist)) {
        data.serverlist.forEach((v) => {
          let cdnOrigin = dynamicCdnOrigin;
          try {
            if (v.country_img) cdnOrigin = new URL(v.country_img).origin;
          } catch {}

          $("#http_results").append(
            `<tr id="${escapeHtml(v.name)}">` +
            `<td><img src="${escapeURI(v.country_img)}" width="16" class="m-2"/> ${escapeHtml(v.city)}</td>` +
            `<td class="loader-cell" colspan="7" style="text-align:center;"><img src="${cdnOrigin}/ip2whois/img/tail-spin.svg" width="32"></td>` +
            `</tr>`
          );
        });
        pollTestStatus(data.testid, "#http_results");
      } else {
        $("#http_results").html(`<tr><td colspan="8" class="text-danger">Server error: ${escapeHtml(data?.message || "Unknown")}</td></tr>`);
      }
    })
    .fail((xhr, status) => {
      $("#http_results").html(`<tr><td colspan="8" class="text-danger">Request failed: ${escapeHtml(status)}</td></tr>`);
    });
}

function pollTestStatus(testid, elem, attempts = 0) {
  if (attempts > 60) {
    $(`${elem} .loader-cell`).replaceWith(`<td colspan="2" class="text-danger">Timeout waiting for server</td>`);
    return;
  }

  $.get(`${API_BASE}/test/status/${encodeURIComponent(testid)}`)
    .done((data) => {
      if ($('[data-toggle="tooltip"]').tooltip) {
        $('[data-toggle="tooltip"]').tooltip();
      }
      if (data?.success) {
        if (Array.isArray(data.results)) {
          buildHttpResults(data.results, elem);
        }
        if (!data.ended) {
          setTimeout(() => pollTestStatus(testid, elem, attempts + 1), 1000);
        }
      } else {
        $(`${elem} .loader-cell`).replaceWith(`<td colspan="2" class="text-danger">Error: ${escapeHtml(data?.message || "Failed")}</td>`);
      }
    })
    .fail(() => {
      setTimeout(() => pollTestStatus(testid, elem, attempts + 1), 1500);
    });
}

function buildHttpResults(results, elem) {
  results.forEach((v) => {
    const row = $(`${elem} #${CSS.escape(v.name)}`);
    const loader = row.find(".loader-cell");
    if (loader.length === 0) return;

    loader.remove();

    if (!v.success) {
      row.append(`<td colspan="2" class="text-danger">Failed: ${escapeHtml(v.message || "Error")}</td>`);
      return;
    }

    const code = Number(v.http_code);
    let color = "uk-text-danger";
    if (code >= 200 && code <= 308) color = "uk-text-success";
    else if (code >= 400 && code <= 404) color = "uk-text-warning";

    const codeText = formatHttpCode(code, v.redirect_url);
    row.append(`<td class="${color}">${codeText}</td>`);
    row.append(`<td>${escapeHtml(v.primary_ip || "-")}</td>`);
  });
}

function formatHttpCode(code, redirectUrl) {
  const safeRedirect = redirectUrl ? `<br>${escapeHtml(redirectUrl)}` : "";
  const map = {
    0: "0 Failed",
    200: "200 OK",
    301: `301 Moved Permanently${safeRedirect}`,
    302: `302 Found${safeRedirect}`,
    304: "304 Not Modified",
    307: `307 Temporary Redirect${safeRedirect}`,
    308: `308 Permanent Redirect${safeRedirect}`,
    400: "400 Bad Request",
    401: "401 Unauthorized",
    403: "403 Forbidden",
    404: "404 Not Found",
    500: "500 Internal Server Error",
    502: "502 Bad Gateway",
    503: "503 Service Unavailable",
    504: "504 Gateway Timeout"
  };
  return map[code] || String(code);
}

async function measureSinglePing(url) {
  const start = performance.now();
  try {
    await fetch(`${url}?q=${Date.now()}`, { cache: "no-store" });
    return Math.max(1, Math.round(performance.now() - start - 2));
  } catch {
    return null;
  }
}

function applyLatencyColor(ms) {
  if (ms > 100) return "#a61818";
  if (ms > 70) return "#ff0000";
  if (ms > 40) return "#d7ac34";
  return "#44a618";
}

async function pingTestRtt(label = "Ping CF") {
  $("#latency_ping_text").text(label);
  let sum = 0;
  let successCount = 0;

  for (let i = 0; i < COUNT_TRY; i++) {
    const rtt = await measureSinglePing(`${SPEEDTEST_BASE}latency.ttf`);
    if (rtt !== null) {
      sum += rtt;
      successCount++;
      $("#latency_ping").text(`${rtt} ms`).css("color", applyLatencyColor(rtt));
    } else {
      $("#latency_ping").text("Timeout").css("color", "#a61818");
    }
    await delay(250);
  }

  if (successCount > 0) {
    const avg = (sum / successCount).toFixed(2);
    pingDiff = Number(avg);
    $("#latency_ping").text(`Avg ${avg} ms`).css("color", applyLatencyColor(pingDiff));
  } else {
    pingDiff = 0;
    $("#latency_ping").text("Failed").css("color", "#a61818");
  }
}

function updateProgress(received, fileSize = 1) {
  if (received === 0) {
    totalPercent = 0;
    return;
  }
  const percent = (received / fileSize) * 100;
  const elapsedSec = (performance.now() - startSpeedtestTime) / 1000;
  if (elapsedSec > 0.2) {
    const speedMbps = ((received * 8) / (1024 * 1024 * elapsedSec)).toFixed(0);
    $("#progress_speed_text").text(`${speedMbps} Mbps`);
  }
  const offset = 261 - Math.round((261 * (totalPercent + percent / COUNT_TRY)) / 100);
  $("#progress_speed").attr("stroke-dashoffset", `${Math.max(0, offset)}px`);
}

async function downloadWithProgress(url, expectedSize = 0) {
  startSpeedtestTime = performance.now();
  const separator = url.includes("?") ? "&" : "?";
  const response = await fetch(`${url}${separator}cachedrop=${Math.random()}`, { cache: "no-store" });
  if (!response.ok) throw new Error(`HTTP ${response.status}`);

  const reader = response.body.getReader();
  let received = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) {
      totalPercent += 100 / COUNT_TRY;
      break;
    }
    received += value.length;
    if (expectedSize > 0) {
      updateProgress(received, expectedSize);
    }
  }

  const duration = Math.max(0.01, (performance.now() - startSpeedtestTime) / 1000);
  return { duration, bytes: received };
}

async function autoSelectSize() {
  updateProgress(0);
  const result = await downloadWithProgress(`${SPEEDTEST_BASE}testfile512k.bin?size=small`);
  const effectiveDuration = Math.max(0.05, result.duration - pingDiff / 1000);
  const speedMbps = (result.bytes * 8) / (1024 * 1024 * effectiveDuration);

  if (speedMbps < 20) return 1 * 1024 * 1024;
  if (speedMbps < 45) return 2 * 1024 * 1024;
  if (speedMbps < 100) return 5 * 1024 * 1024;
  if (speedMbps < 200) return 10 * 1024 * 1024;
  if (speedMbps < 400) return 25 * 1024 * 1024;
  return 50 * 1024 * 1024;
}

async function runSpeedTest() {
  if (speedStarted) {
    alert("Test already started! Wait for it to complete.");
    return;
  }

  const speedTextEl = document.getElementById("speedtext") || $("#speedtext");
  speedStarted = true;
  pingDiff = 0;
  totalPercent = 0;

  if (speedTextEl) speedTextEl.innerText = "Preparing…";
  $("#speedtestbutton").text("Processing..").addClass("disabled");

  $("#dl_speed").html(
    '<svg width="200" height="200" viewBox="-12.875 -12.875 128.75 128.75" xmlns="http://www.w3.org/2000/svg" style="transform:rotate(-90deg)">' +
      '<circle r="41.5" cx="51.5" cy="51.5" fill="transparent" stroke="#ffffff" stroke-width="2"></circle>' +
      '<circle id="progress_speed" r="41.5" cx="51.5" cy="51.5" stroke="#007bff" stroke-width="6" stroke-linecap="round" stroke-dashoffset="261px" fill="transparent" stroke-dasharray="260.62px"></circle>' +
      '<text x="20px" y="54px" fill="#000000" font-size="12px" font-weight="bold" style="transform:rotate(90deg) translate(0px, -99px)" id="progress_speed_text">Preparing</text>' +
    "</svg>"
  );

  try {
    await pingTestRtt("RTT to Cloudflare*");
    const targetSize = await autoSelectSize();
    const fileSizeMb = targetSize / (1024 * 1024);

    updateProgress(0);
    let totalBytes = 0;
    let totalDuration = 0;
    const testUrl = `${SPEEDTEST_BASE}testfile${fileSizeMb}m.bin?size=${targetSize}`;

    for (let i = 0; i < COUNT_TRY; i++) {
      const result = await downloadWithProgress(testUrl, targetSize);
      totalDuration += result.duration;
      totalBytes += result.bytes;
      const currentMbps = (result.bytes * 8) / (1024 * 1024 * result.duration);
      $("#progress_speed_text").text(`${currentMbps.toFixed(0)} Mbps`);
    }

    const avgMbps = (totalBytes * 8) / (1024 * 1024 * totalDuration);
    const totalMiB = totalBytes / (1024 * 1024);
    if (speedTextEl) {
      speedTextEl.innerText = `Speed: ${avgMbps.toFixed(2)} Mbps
Size: ${totalMiB.toFixed(2)} MiBytes`;
    }
  } catch (err) {
    console.error("Speedtest error:", err);
    $("#progress_speed_text").text("Error");
    if (speedTextEl) {
      speedTextEl.innerText = "Speedtest failed: network error";
    }
  } finally {
    $("#speedtestbutton").text("Start").removeClass("disabled");
    speedStarted = false;
    pingDiff = 0;
    totalPercent = 0;
  }
}

function decodePunycodeSafe(host) {
  if (typeof punycode !== "undefined" && typeof punycode.ToUnicode === "function") {
    try {
      return punycode.ToUnicode(host);
    } catch {
      return host;
    }
  }
  return host;
}

function bytesToSize(bytes) {
  const sizes = ["Bytes", "KB", "MB", "GB", "TB"];
  if (!bytes || bytes === 0) return "0 Byte";
  const i = Math.floor(Math.log(bytes) / Math.log(1024));
  return `${Math.round(bytes / Math.pow(1024, i))} ${sizes[i]}`;
}

function getClientInfo() {
  const ua = navigator.userAgent;
  let browserName = "Unknown";
  if (ua.includes("Edg/") || ua.includes("Edge")) browserName = "Edge";
  else if (ua.includes("Chrome")) browserName = "Chrome";
  else if (ua.includes("Firefox")) browserName = "Firefox";
  else if (ua.includes("Safari")) browserName = "Safari";

  return {
    userAgent: ua,
    browserName,
    platform: navigator.platform,
    language: navigator.language,
    languages: navigator.languages,
    screen: {
      width: window.screen.width,
      height: window.screen.height,
      availWidth: window.screen.availWidth,
      availHeight: window.screen.availHeight,
      colorDepth: window.screen.colorDepth,
      pixelRatio: window.devicePixelRatio
    },
    connection: navigator.connection
      ? {
          effectiveType: navigator.connection.effectiveType,
          downlink: navigator.connection.downlink,
          rtt: navigator.connection.rtt,
          saveData: navigator.connection.saveData
        }
      : null,
    gpu: getAccurateGPU()
  };
}

function getAccurateGPU() {
  const canvas = document.createElement("canvas");
  const gl = canvas.getContext("webgl") || canvas.getContext("experimental-webgl");
  if (!gl) return null;

  const ext = gl.getExtension("WEBGL_debug_renderer_info");
  const vendor = ext ? gl.getParameter(ext.UNMASKED_VENDOR_WEBGL) : gl.getParameter(gl.VENDOR);
  const renderer = ext ? gl.getParameter(ext.UNMASKED_RENDERER_WEBGL) : gl.getParameter(gl.RENDERER);

  return {
    vendor: normalizeVendor(vendor),
    model: cleanGPU(renderer),
    rawVendor: vendor,
    rawModel: renderer
  };
}

function cleanGPU(str) {
  if (!str) return null;
  str = str.trim();
  const adrenoMatch = str.match(/adreno[\s\-_]*(\(tm\))?\s*\d+/i);
  if (adrenoMatch) return adrenoMatch[0].replace(/\(tm\)/i, "TM").replace(/\s+/g, " ").trim();
  const angleMatch = str.match(/,\s*([^()]+?)\s*(\(|$)/);
  if (angleMatch) return angleMatch[1].trim();
  const generic = str.match(/[A-Za-z0-9()_\- ]+/);
  return generic ? generic[0].trim() : str;
}

function normalizeVendor(vendorStr) {
  if (!vendorStr) return null;
  vendorStr = vendorStr.trim();
  const match = vendorStr.match(/\(([^)]+)\)/);
  if (match) return match[1].trim();
  if (/google\s+inc/i.test(vendorStr)) return null;
  if (/nvidia/i.test(vendorStr)) return "NVIDIA";
  if (/amd|ati/i.test(vendorStr)) return "AMD";
  if (/intel/i.test(vendorStr)) return "Intel";
  if (/qualcomm/i.test(vendorStr)) return "Qualcomm";
  if (/apple/i.test(vendorStr)) return "Apple";
  return vendorStr;
}

function detectTargetType(host) {
  if (isIPv4(host) || isIPv6(host)) return "ip";
  const domainRegex = /^(?!-)(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]?(\.(xn--)?[a-z0-9-]{1,61})+$/;
  return domainRegex.test(host) ? "domain" : null;
}

function isIPv4(ip) {
  const parts = ip.split(".");
  return parts.length === 4 && parts.every((p) => /^\d{1,3}$/.test(p) && Number(p) >= 0 && Number(p) <= 255);
}

function isIPv6(ip) {
  if (!ip.includes(":")) return false;
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:))$/;
  return ipv6Regex.test(ip);
}

function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function escapeURI(url) {
  if (!url) return "";
  try {
    const parsed = new URL(url);
    return (parsed.protocol === "http:" || parsed.protocol === "https:" || parsed.protocol === "data:") ? url : "";
  } catch {
    return "";
  }
}
