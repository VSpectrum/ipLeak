/**
 * Main UI entrypoint wiring HTTP IP inspection, WebRTC leak check, and BitTorrent check.
 */

import { classifyAddresses, fetchClientIp } from "./api.js";
import { createTorrentController } from "./torrent.js";
import {
  buildWebRtcVerdict,
  comparisonBadge,
  formatEndpoint,
  gatherWebRTCCandidates,
} from "./webrtc.js";

let currentBrowserIp = null;
let currentHttpScope = null;

// --- 1. HTTP Client IP Section ---

const httpIpValueEl = document.getElementById("http-ip-value");
const httpIpBadgesEl = document.getElementById("http-ip-badges");
const httpDetectedViaEl = document.getElementById("http-detected-via");
const httpUserAgentEl = document.getElementById("http-user-agent");
const httpLocalNoteEl = document.getElementById("http-local-note");
const copyHttpIpBtn = document.getElementById("copy-http-ip-btn");
const refreshHttpIpBtn = document.getElementById("refresh-http-ip-btn");

function makeBadge(text, variant = "") {
  const span = document.createElement("span");
  span.className = variant ? `badge ${variant}` : "badge";
  span.textContent = text;
  return span;
}

async function loadHttpIp() {
  refreshHttpIpBtn.disabled = true;
  try {
    const info = await fetchClientIp();
    currentBrowserIp = info.ip;
    currentHttpScope = info.scope;
    httpIpValueEl.textContent = info.ip;
    copyHttpIpBtn.disabled = false;

    httpIpBadgesEl.replaceChildren();
    if (info.version) {
      httpIpBadgesEl.appendChild(makeBadge(`IPv${info.version}`, "badge-info"));
    }
    const scopeVariant = info.is_public ? "badge-ok" : "badge-warn";
    httpIpBadgesEl.appendChild(makeBadge(info.scope.toUpperCase(), scopeVariant));

    httpDetectedViaEl.textContent = info.detected_via;
    httpUserAgentEl.textContent = info.user_agent || "—";

    if (info.scope === "loopback" || info.scope === "private" || info.scope === "link_local") {
      httpLocalNoteEl.classList.remove("hidden");
    } else {
      httpLocalNoteEl.classList.add("hidden");
    }
  } catch (err) {
    currentBrowserIp = null;
    currentHttpScope = null;
    httpIpValueEl.textContent = "Unavailable";
    httpDetectedViaEl.textContent = err.message;
  } finally {
    refreshHttpIpBtn.disabled = false;
  }
}

refreshHttpIpBtn.addEventListener("click", loadHttpIp);
copyHttpIpBtn.addEventListener("click", async () => {
  if (!currentBrowserIp) return;
  await navigator.clipboard.writeText(currentBrowserIp);
  const prev = copyHttpIpBtn.textContent;
  copyHttpIpBtn.textContent = "Copied!";
  window.setTimeout(() => {
    copyHttpIpBtn.textContent = prev;
  }, 1400);
});

// --- 2. WebRTC Leak Check Section ---

const runWebrtcBtn = document.getElementById("run-webrtc-btn");
const webrtcIdleEl = document.getElementById("webrtc-idle");
const webrtcResultsEl = document.getElementById("webrtc-results");
const webrtcVerdictEl = document.getElementById("webrtc-verdict");
const webrtcTbodyEl = document.getElementById("webrtc-tbody");

async function runWebrtcCheck() {
  runWebrtcBtn.disabled = true;
  runWebrtcBtn.textContent = "Checking STUN…";

  try {
    const result = await gatherWebRTCCandidates({
      timeoutMs: 4000,
      classify: classifyAddresses,
    });
    webrtcIdleEl.classList.add("hidden");
    webrtcResultsEl.classList.remove("hidden");
    webrtcTbodyEl.replaceChildren();

    const verdict = buildWebRtcVerdict({
      supported: result.supported,
      candidates: result.candidates,
      httpIp: currentBrowserIp,
      httpScope: currentHttpScope,
    });
    webrtcVerdictEl.className = `verdict-banner verdict-${verdict.tone}`;
    webrtcVerdictEl.textContent = verdict.text;
    if (!result.supported || result.candidates.length === 0) return;

    for (const cand of result.candidates) {
      const tr = document.createElement("tr");

      const addrTd = document.createElement("td");
      addrTd.className = "mono";
      addrTd.textContent = formatEndpoint(cand.address, cand.port);
      tr.appendChild(addrTd);

      const scopeTd = document.createElement("td");
      scopeTd.appendChild(
        makeBadge((cand.scope || "unknown").toUpperCase(), cand.isPublic ? "badge-info" : "")
      );
      tr.appendChild(scopeTd);

      const typeTd = document.createElement("td");
      typeTd.className = "mono";
      typeTd.textContent = cand.candidateType;
      tr.appendChild(typeTd);

      const protoTd = document.createElement("td");
      protoTd.className = "mono";
      protoTd.textContent = cand.protocol.toUpperCase();
      tr.appendChild(protoTd);

      const relatedTd = document.createElement("td");
      relatedTd.className = "mono";
      if (cand.relatedAddress) {
        const label = document.createElement("span");
        label.textContent = formatEndpoint(cand.relatedAddress, cand.relatedPort);
        relatedTd.appendChild(label);
        relatedTd.appendChild(document.createTextNode(" "));
        relatedTd.appendChild(
          makeBadge(
            (cand.relatedScope || "unknown").toUpperCase(),
            cand.relatedIsPublic ? "badge-info" : ""
          )
        );
      } else {
        relatedTd.textContent = "—";
      }
      tr.appendChild(relatedTd);

      const cmpTd = document.createElement("td");
      const comparison = comparisonBadge(cand, currentBrowserIp, currentHttpScope);
      cmpTd.appendChild(makeBadge(comparison.text, comparison.variant));
      tr.appendChild(cmpTd);

      webrtcTbodyEl.appendChild(tr);
    }
  } catch (err) {
    webrtcIdleEl.classList.add("hidden");
    webrtcResultsEl.classList.remove("hidden");
    webrtcVerdictEl.className = "verdict-banner verdict-warn";
    webrtcVerdictEl.textContent = `WebRTC check failed: ${err.message}`;
    webrtcTbodyEl.replaceChildren();
  } finally {
    runWebrtcBtn.disabled = false;
    runWebrtcBtn.textContent = "Re-check WebRTC Leak";
  }
}

runWebrtcBtn.addEventListener("click", runWebrtcCheck);

// --- 3. BitTorrent Leak Check Section ---

createTorrentController({
  getBrowserIp: () => currentBrowserIp,
});

// Kick off HTTP IP lookup immediately on page load
loadHttpIp();

