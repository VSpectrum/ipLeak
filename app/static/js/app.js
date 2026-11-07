/**
 * Main UI entrypoint wiring HTTP IP inspection, WebRTC leak check, and BitTorrent check.
 */

import { fetchClientIp } from "./api.js";
import { gatherWebRTCCandidates } from "./webrtc.js";
import { createTorrentController } from "./torrent.js";

let currentBrowserIp = null;

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

    if (info.scope === "loopback" || info.scope === "private") {
      httpLocalNoteEl.classList.remove("hidden");
    } else {
      httpLocalNoteEl.classList.add("hidden");
    }
  } catch (err) {
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
    const result = await gatherWebRTCCandidates({ timeoutMs: 4000 });
    webrtcIdleEl.classList.add("hidden");
    webrtcResultsEl.classList.remove("hidden");
    webrtcVerdictEl.className = "verdict-banner";
    webrtcTbodyEl.replaceChildren();

    if (!result.supported) {
      webrtcVerdictEl.classList.add("verdict-ok");
      webrtcVerdictEl.textContent = "WebRTC (RTCPeerConnection) is disabled in this browser — no WebRTC IP leak possible.";
      return;
    }

    if (result.candidates.length === 0) {
      webrtcVerdictEl.classList.add("verdict-ok");
      webrtcVerdictEl.textContent = "No ICE candidates were exposed (WebRTC UDP/STUN may be blocked by your browser or firewall).";
      return;
    }

    const publicMismatches = result.candidates.filter(
      (c) => c.isPublic && currentBrowserIp && c.address !== currentBrowserIp
    );
    const anyPublic = result.candidates.some((c) => c.isPublic);

    if (publicMismatches.length > 0) {
      webrtcVerdictEl.classList.add("verdict-danger");
      const leakedList = [...new Set(publicMismatches.map((c) => c.address))].join(", ");
      webrtcVerdictEl.textContent =
        `Potential WebRTC Leak: STUN discovered public IP (${leakedList}) that differs from your HTTP IP (${currentBrowserIp})!`;
    } else if (anyPublic) {
      webrtcVerdictEl.classList.add("verdict-ok");
      webrtcVerdictEl.textContent =
        "Public WebRTC STUN address matches your HTTP IP — no proxy/VPN bypass detected.";
    } else {
      webrtcVerdictEl.classList.add("verdict-ok");
      webrtcVerdictEl.textContent =
        "Only local/mDNS ICE candidates were gathered; no public IP was exposed via WebRTC.";
    }

    for (const cand of result.candidates) {
      const tr = document.createElement("tr");

      const addrTd = document.createElement("td");
      addrTd.className = "mono";
      addrTd.textContent = cand.port ? `${cand.address}:${cand.port}` : cand.address;
      tr.appendChild(addrTd);

      const scopeTd = document.createElement("td");
      scopeTd.appendChild(
        makeBadge(cand.scope.toUpperCase(), cand.isPublic ? "badge-info" : "")
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

      const cmpTd = document.createElement("td");
      if (!cand.isPublic) {
        cmpTd.appendChild(makeBadge("Local / Non-Public"));
      } else if (currentBrowserIp && cand.address === currentBrowserIp) {
        cmpTd.appendChild(makeBadge("Matches HTTP IP", "badge-ok"));
      } else {
        cmpTd.appendChild(makeBadge("Differs from HTTP IP", "badge-danger"));
      }
      tr.appendChild(cmpTd);

      webrtcTbodyEl.appendChild(tr);
    }
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

