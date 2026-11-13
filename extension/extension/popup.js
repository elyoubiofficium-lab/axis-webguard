
"use strict";

document.addEventListener("DOMContentLoaded", init);

let activeTabId = null;

async function init() {
  const scanButton = document.getElementById("scanButton");

  scanButton.addEventListener("click", runScan);

  try {
    const tabs = await chrome.tabs.query({
      active: true,
      currentWindow: true
    });

    const tab = tabs[0];

    if (!tab || !tab.id || !tab.url) {
      showUnavailable("No active browser page was found.");
      return;
    }

    activeTabId = tab.id;
    showPage(tab.url);

    if (!/^https?:\/\//i.test(tab.url)) {
      showUnavailable(
        "Open a regular website beginning with https:// or http://, then try again."
      );
      return;
    }

    await runScan();
  } catch (error) {
    showUnavailable("Chrome could not access the current tab. Open a normal website and try again.");
  }
}

function showPage(url) {
  const pageUrl = document.getElementById("pageUrl");

  try {
    const parsed = new URL(url);
    pageUrl.textContent = parsed.hostname;
    pageUrl.title = url;
  } catch {
    pageUrl.textContent = "Current page";
  }
}

function setStatus(text, type = "") {
  const status = document.getElementById("status");
  status.textContent = text;
  status.className = "status";

  if (type) {
    status.classList.add(type);
  }
}

function showUnavailable(message) {
  setStatus("UNAVAILABLE", "error");

  document.getElementById("message").textContent = message;
  document.getElementById("scanButton").disabled = true;
  document.getElementById("results").hidden = true;
}

async function runScan() {
  if (!activeTabId) return;

  const button = document.getElementById("scanButton");
  const message = document.getElementById("message");

  button.disabled = true;
  button.textContent = "Scanning...";
  setStatus("SCANNING", "scanning");
  message.textContent = "Reviewing selected page signals locally...";

  try {
    const results = await chrome.scripting.executeScript({
      target: { tabId: activeTabId },
      func: scanCurrentPage
    });

    const report = results && results[0] && results[0].result;

    if (!report) {
      throw new Error("No scan report was returned.");
    }

    renderReport(report);
    setStatus("SCAN COMPLETE");
    message.textContent =
      "Scan complete. Page data was not sent to an external scanning service.";
  } catch (error) {
    console.error("AXIS WebGuard scan error:", error);

    setStatus("UNAVAILABLE", "error");
    message.textContent =
      "Chrome could not scan this page. Some browser pages and protected pages cannot be inspected.";
    document.getElementById("results").hidden = true;
  } finally {
    button.disabled = false;
    button.textContent = "Scan this page again";
  }
}

/*
 * This function is injected into the active tab by Chrome.
 * Keep its logic self-contained because Chrome serializes it.
 */
function scanCurrentPage() {
  const page = new URL(window.location.href);
  const hostname = page.hostname.toLowerCase();
  const isHttps = page.protocol === "https:";

  const links = Array.from(document.querySelectorAll("a[href]"));
  const forms = Array.from(document.forms);

  let insecureLinks = 0;
  let placeholderLinks = 0;
  let shortenedLinks = 0;
  let mixedContent = 0;
  let insecurePasswordForms = 0;

  const shortenerDomains = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "rb.gy",
    "rebrand.ly",
    "ow.ly",
    "buff.ly",
    "shorturl.at",
    "lnkd.in",
    "goo.su"
  ];

  const brandDomains = {
    paypal: ["paypal.com"],
    google: ["google.com", "google.co.uk", "google.ca", "google.co.in"],
    apple: ["apple.com"],
    microsoft: ["microsoft.com", "live.com", "outlook.com"],
    amazon: ["amazon.com", "amazon.co.uk", "amazon.ca", "amazon.de", "amazon.fr"],
    facebook: ["facebook.com", "fb.com"],
    instagram: ["instagram.com"],
    netflix: ["netflix.com"],
    linkedin: ["linkedin.com"]
  };

  const findings = [];

  function addFinding(level, title, description, points = 0) {
    findings.push({ level, title, description });
    return points;
  }

  function isIpAddress(host) {
    return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
  }

  function belongsToDomain(host, domain) {
    return host === domain || host.endsWith("." + domain);
  }

  function isShortener(host) {
    return shortenerDomains.some(domain => belongsToDomain(host, domain));
  }

  function hasBrandImpersonation(host) {
    const labels = host.split(".");
    const tokens = labels.flatMap(label => label.split(/[-_]/));

    for (const [brand, allowedDomains] of Object.entries(brandDomains)) {
      if (!tokens.includes(brand)) continue;

      const isAllowed = allowedDomains.some(domain =>
        belongsToDomain(host, domain)
      );

      if (!isAllowed) return brand;
    }

    return null;
  }

  if (!isHttps) {
    addFinding(
      "danger",
      "The page does not use HTTPS",
      "The connection is not encrypted with HTTPS. Avoid entering passwords or payment details on this page.",
      25
    );
  } else {
    addFinding(
      "info",
      "HTTPS connection detected",
      "The page uses an encrypted connection. HTTPS alone does not prove that a website is trustworthy.",
      0
    );
  }

  if (hostname.includes("xn--")) {
    addFinding(
      "warning",
      "Internationalized domain detected",
      "This hostname contains Punycode. Some lookalike domains use similar-looking characters. This is a warning signal, not proof of fraud.",
      18
    );
  }

  if (isIpAddress(hostname)) {
    addFinding(
      "warning",
      "Website uses an IP address",
      "The page is opened directly through an IP address instead of a usual domain name. Check that you expected this destination.",
      18
    );
  }

  const impersonatedBrand = hasBrandImpersonation(hostname);

  if (impersonatedBrand) {
    addFinding(
      "danger",
      "Possible brand impersonation",
      "The hostname contains the name of " + impersonatedBrand +
        " but does not match the known domain patterns checked by this tool. Verify the address independently.",
      25
    );
  }

  for (const anchor of links) {
    const rawHref = (anchor.getAttribute("href") || "").trim();

    if (
      rawHref === "" ||
      rawHref === "#" ||
      /^javascript:/i.test(rawHref)
    ) {
      placeholderLinks++;
      continue;
    }

    try {
      const destination = new URL(anchor.href);

      if (isHttps && destination.protocol === "http:") {
        insecureLinks++;
      }

      if (destination.protocol === "http:" || destination.protocol === "https:") {
        if (isShortener(destination.hostname.toLowerCase())) {
          shortenedLinks++;
        }
      }
    } catch {
      // Invalid or unsupported link formats are ignored.
    }
  }

  if (insecureLinks > 0) {
    addFinding(
      "warning",
      insecureLinks + " insecure link" + (insecureLinks === 1 ? "" : "s") + " found",
      "Some links lead to HTTP pages, which do not use an encrypted connection.",
      Math.min(insecureLinks * 5, 15)
    );
  }

  if (shortenedLinks > 0) {
    addFinding(
      "warning",
      shortenedLinks + " shortened link" + (shortenedLinks === 1 ? "" : "s") + " found",
      "Shortened links hide their final destination. Check where they lead before opening them.",
      Math.min(shortenedLinks * 5, 10)
    );
  }

  if (placeholderLinks > 0) {
    addFinding(
      "info",
      placeholderLinks + " placeholder or script link" +
        (placeholderLinks === 1 ? "" : "s"),
      "Some links do not point to a normal web address. This is usually a page-quality issue, not proof of a security threat.",
      0
    );
  }

  if (isHttps) {
    const resources = Array.from(
      document.querySelectorAll(
        "img[src], script[src], iframe[src], source[src], video[src], audio[src], link[rel~='stylesheet'][href]"
      )
    );

    for (const resource of resources) {
      const value = resource.src || resource.href;

      if (value && /^http:\/\//i.test(value)) {
        mixedContent++;
      }
    }
  }

  if (mixedContent > 0) {
    addFinding(
      "danger",
      mixedContent + " insecure page resource" +
        (mixedContent === 1 ? "" : "s") + " found",
      "This HTTPS page loads some resources over HTTP. These resources may not be protected by the page's encrypted connection.",
      15
    );
  }

  for (const form of forms) {
    const passwordInput = form.querySelector('input[type="password"]');
    if (!passwordInput) continue;

    let actionUrl;

    try {
      actionUrl = new URL(
        form.getAttribute("action") || window.location.href,
        window.location.href
      );
    } catch {
      continue;
    }

    if (
      window.location.protocol === "http:" ||
      actionUrl.protocol === "http:"
    ) {
      insecurePasswordForms++;
    }
  }

  if (insecurePasswordForms > 0) {
    addFinding(
      "danger",
      "Password form uses an insecure connection",
      "A password form appears to use HTTP for the page or its submission destination. Do not enter credentials until you verify the website.",
      35
    );
  }

  const score = Math.min(
    100,
    findings.reduce((total, finding) => {
      const weights = {
        danger: 1,
        warning: 1,
        info: 1
      };
      return total + (finding.points || 0) * weights[finding.level];
    }, 0)
  );

  return {
    hostname,
    protocol: page.protocol,
    linkCount: links.length,
    formCount: forms.length,
    score,
    findings
  };
}

function renderReport(report) {
  document.getElementById("results").hidden = false;

  document.getElementById("scoreValue").textContent = report.score;
  document.getElementById("connection").textContent =
    report.protocol === "https:" ? "HTTPS" : "HTTP";
  document.getElementById("linksCount").textContent = report.linkCount;
  document.getElementById("formsCount").textContent = report.formCount;

  const scoreLabel = document.getElementById("scoreLabel");
  const scoreBadge = document.getElementById("scoreBadge");

  scoreBadge.className = "score-badge";

  if (report.score >= 50) {
    scoreLabel.textContent = "Multiple warning signals found";
    scoreBadge.classList.add("danger");
  } else if (report.score >= 20) {
    scoreLabel.textContent = "Some warning signals found";
    scoreBadge.classList.add("warning");
  } else if (report.score > 0) {
    scoreLabel.textContent = "Few warning signals found";
  } else {
    scoreLabel.textContent = "No warning signals detected by these checks";
  }

  const list = document.getElementById("findingsList");
  list.replaceChildren();

  if (!report.findings.length) {
    const empty = document.createElement("p");
    empty.className = "message";
    empty.textContent = "No findings were returned by the current checks.";
    list.appendChild(empty);
  } else {
    for (const finding of report.findings) {
      const item = document.createElement("article");
      item.className = "finding " + finding.level;

      const title = document.createElement("div");
      title.className = "finding-title";

      const symbol = document.createElement("span");
      symbol.textContent =
        finding.level === "danger" ? "!" :
        finding.level === "warning" ? "△" : "i";

      const heading = document.createElement("span");
      heading.textContent = finding.title;

      title.append(symbol, heading);

      const description = document.createElement("p");
      description.textContent = finding.description;

      item.append(title, description);
      list.appendChild(item);
    }
  }

  document.getElementById("scanTime").textContent =
    new Date().toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit"
    });
}
