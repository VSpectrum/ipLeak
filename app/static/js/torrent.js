/**
 * Frontend controller for BitTorrent magnet generation and connection polling.
 */

import { createTorrentSession, fetchTorrentSession } from "./api.js";
import { formatEndpoint } from "./webrtc.js";

const SOURCE_LABELS = {
  http_tracker: "HTTP Tracker",
  udp_tracker: "UDP Tracker",
  bt_peer: "Peer Handshake (TCP)",
  bt_peer_outbound: "Outbound Peer Probe (TCP)",
  http_scrape: "HTTP Scrape",
  udp_scrape: "UDP Scrape",
};

export function createTorrentController({ getBrowserIp }) {
  const generateBtn = document.getElementById("generate-magnet-btn");
  const stopBtn = document.getElementById("stop-torrent-btn");
  const refreshBtn = document.getElementById("refresh-torrent-btn");
  const copyMagnetBtn = document.getElementById("copy-magnet-btn");
  const openMagnetLink = document.getElementById("open-magnet-link");
  const downloadTorrentLink = document.getElementById("download-torrent-link");
  const magnetInput = document.getElementById("magnet-uri-input");
  const infoHashEl = document.getElementById("session-info-hash");
  const endpointsEl = document.getElementById("session-endpoints");
  const peerProbeRowEl = document.getElementById("peer-probe-row");
  const peerProbePillsEl = document.getElementById("peer-probe-pills");

  const idleBox = document.getElementById("torrent-idle");
  const panel = document.getElementById("torrent-panel");
  const listenerDot = document.getElementById("listener-dot");
  const listenerStatus = document.getElementById("listener-status-text");
  const expiryEl = document.getElementById("session-expiry");
  const verdictEl = document.getElementById("torrent-verdict");
  const emptyHitsEl = document.getElementById("torrent-empty-hits");
  const hitsWrapEl = document.getElementById("torrent-hits-wrap");
  const tbody = document.getElementById("torrent-tbody");

  let activeToken = null;
  let pollTimer = null;
  let listening = false;
  let expiresAtMs = null;
  let expiryTimer = null;

  function pausePolling() {
    if (pollTimer !== null) {
      window.clearInterval(pollTimer);
      pollTimer = null;
    }
  }

  function stopExpiryTimer() {
    if (expiryTimer !== null) {
      window.clearInterval(expiryTimer);
      expiryTimer = null;
    }
  }

  function clearExpiry() {
    stopExpiryTimer();
    expiresAtMs = null;
    expiryEl.textContent = "";
    expiryEl.classList.remove("expiry-soon");
  }

  function haltListening(reasonText) {
    listening = false;
    pausePolling();
    listenerDot.classList.remove("active");
    if (reasonText) listenerStatus.textContent = reasonText;
    stopBtn.classList.add("hidden");
  }

  function tickExpiry() {
    if (expiresAtMs === null) return;
    const remaining = Math.round((expiresAtMs - Date.now()) / 1000);
    if (remaining <= 0) {
      stopExpiryTimer();
      expiresAtMs = null;
      expiryEl.textContent = "Expired";
      expiryEl.classList.add("expiry-soon");
      if (listening) {
        activeToken = null;
        haltListening("Session expired. Generate a new magnet link to run another test.");
      }
      return;
    }
    const minutes = Math.floor(remaining / 60);
    const seconds = remaining % 60;
    expiryEl.textContent = `Expires in ${minutes}:${String(seconds).padStart(2, "0")}`;
    expiryEl.classList.toggle("expiry-soon", remaining <= 60);
  }

  function noteExpiry(expiresAtSeconds) {
    if (!expiresAtSeconds) return;
    expiresAtMs = expiresAtSeconds * 1000;
    tickExpiry();
    if (expiryTimer === null && expiresAtMs !== null) {
      expiryTimer = window.setInterval(tickExpiry, 1000);
    }
  }

  function resumePolling() {
    if (!listening || !activeToken || pollTimer !== null) return;
    pollTimer = window.setInterval(pollOnce, 1500);
    pollOnce();
  }

  async function pollOnce() {
    if (!activeToken) return;
    try {
      const session = await fetchTorrentSession(activeToken);
      if (!session) {
        activeToken = null;
        haltListening("Session expired. Generate a new magnet link to run another test.");
        stopExpiryTimer();
        expiryEl.textContent = "Expired";
        expiryEl.classList.add("expiry-soon");
        return;
      }
      renderSession(session);
    } catch (err) {
      listenerStatus.textContent = `Polling error: ${err.message}`;
    }
  }

  function renderEndpoints(session) {
    endpointsEl.replaceChildren();
    for (const tr of session.trackers || []) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = tr.startsWith("udp://") ? "UDP Tracker Active" : "HTTP Tracker Active";
      badge.title = tr;
      endpointsEl.appendChild(badge);
    }
    if (session.peers && session.peers.length > 0) {
      const peerBadge = document.createElement("span");
      peerBadge.className = "badge";
      peerBadge.textContent = `TCP Peer (${session.peers[0]})`;
      endpointsEl.appendChild(peerBadge);
    }
  }

  function renderVerdict(session) {
    const detections = session.detections || [];
    if (detections.length === 0) {
      verdictEl.classList.add("hidden");
      return;
    }

    verdictEl.classList.remove("hidden", "verdict-ok", "verdict-warn", "verdict-danger");
    const summary = session.summary || {};
    const browserIp = getBrowserIp() || session.creator_ip;

    if (summary.has_multi_ip_leak || (summary.reported_mismatch_ips && summary.reported_mismatch_ips.length > 0)) {
      verdictEl.classList.add("verdict-danger");
      verdictEl.textContent =
        "Multiple IP addresses detected across BitTorrent protocols or announce parameters! " +
        "Your proxy/VPN may be leaking UDP tracker traffic, peer TCP handshakes, or self-reported IP parameters.";
      return;
    }

    const torrentIp = summary.unique_ips && summary.unique_ips[0];
    if (torrentIp && browserIp && torrentIp !== browserIp) {
      verdictEl.classList.add("verdict-warn");
      verdictEl.textContent =
        `Torrent IP (${torrentIp}) differs from Browser HTTP IP (${browserIp}). ` +
        "Verify whether this is your intended torrent proxy/VPN IP or an unproxied leak.";
      return;
    }

    verdictEl.classList.add("verdict-ok");
    verdictEl.textContent =
      `All observed BitTorrent connections (${torrentIp}) match your Browser HTTP IP (${browserIp}).`;
  }

  function renderProbes(session) {
    const probes = session.peer_probes || {};
    const entries = Object.entries(probes);
    if (entries.length === 0) {
      peerProbeRowEl.classList.add("hidden");
      peerProbePillsEl.replaceChildren();
      return;
    }
    peerProbeRowEl.classList.remove("hidden");
    peerProbePillsEl.replaceChildren();
    for (const [endpoint, status] of entries) {
      const badge = document.createElement("span");
      const variant =
        status === "open" ? "badge-warn" : status === "closed" ? "" : "badge-info";
      badge.className = variant ? `badge ${variant}` : "badge";
      const label =
        status === "open"
          ? `${endpoint} (Open / Reachable)`
          : status === "closed"
            ? `${endpoint} (Closed / NAT)`
            : `${endpoint} (Probing…)`;
      badge.textContent = label;
      peerProbePillsEl.appendChild(badge);
    }
  }

  function renderSession(session) {
    noteExpiry(session.expires_at);
    renderVerdict(session);
    renderProbes(session);
    const detections = session.detections || [];

    if (detections.length === 0) {
      emptyHitsEl.classList.remove("hidden");
      hitsWrapEl.classList.add("hidden");
      tbody.replaceChildren();
      return;
    }

    emptyHitsEl.classList.add("hidden");
    hitsWrapEl.classList.remove("hidden");
    tbody.replaceChildren();

    const browserIp = getBrowserIp() || session.creator_ip;

    for (const det of detections) {
      const tr = document.createElement("tr");

      // 1. Observed IP + port
      const ipTd = document.createElement("td");
      ipTd.className = "mono";
      ipTd.textContent = formatEndpoint(det.ip, det.port);
      tr.appendChild(ipTd);

      // 2. Source protocol
      const srcTd = document.createElement("td");
      const srcBadge = document.createElement("span");
      srcBadge.className = "badge badge-info";
      srcBadge.textContent = SOURCE_LABELS[det.source] || det.source;
      srcTd.appendChild(srcBadge);
      tr.appendChild(srcTd);

      // 3. Client
      const clientTd = document.createElement("td");
      clientTd.textContent = det.client || "Unknown";
      tr.appendChild(clientTd);

      // 4. Self-reported IP params
      const repTd = document.createElement("td");
      repTd.className = "mono";
      if (det.reported_ips && det.reported_ips.length > 0) {
        const hasDiff = det.reported_ips.some((ip) => ip !== det.ip);
        const span = document.createElement("span");
        span.className = hasDiff ? "badge badge-danger" : "badge";
        span.textContent = det.reported_ips.join(", ");
        repTd.appendChild(span);
      } else {
        repTd.textContent = "—";
      }
      tr.appendChild(repTd);

      // 5. Hit count
      const hitsTd = document.createElement("td");
      hitsTd.className = "mono";
      hitsTd.textContent = String(det.hit_count || 1);
      tr.appendChild(hitsTd);

      // 6. Comparison vs Browser IP
      const cmpTd = document.createElement("td");
      const cmpBadge = document.createElement("span");
      const matches = browserIp ? det.ip === browserIp : det.matches_browser_ip;
      cmpBadge.className = matches ? "badge badge-ok" : "badge badge-warn";
      cmpBadge.textContent = matches ? "Same as Browser" : "Different IP";
      cmpTd.appendChild(cmpBadge);
      tr.appendChild(cmpTd);

      tbody.appendChild(tr);
    }
  }

  async function startNewSession() {
    haltListening();
    clearExpiry();
    activeToken = null;
    generateBtn.disabled = true;
    generateBtn.textContent = "Generating…";

    try {
      const session = await createTorrentSession();
      activeToken = session.token;
      listening = true;

      idleBox.classList.add("hidden");
      panel.classList.remove("hidden");
      stopBtn.classList.remove("hidden");

      magnetInput.value = session.magnet_uri;
      openMagnetLink.href = session.magnet_uri;
      downloadTorrentLink.href = session.torrent_url;
      infoHashEl.textContent = session.info_hash;
      renderEndpoints(session);
      renderSession(session);

      listenerDot.classList.add("active");
      listenerStatus.textContent = document.hidden
        ? "Paused while this tab is hidden. The session stays active until it expires."
        : "Listening for HTTP tracker, UDP tracker, and TCP peer connections (polling every 1.5s)…";

      generateBtn.textContent = "New Magnet Link";
      if (!document.hidden) {
        pollTimer = window.setInterval(pollOnce, 1500);
      }
    } catch (err) {
      if (panel.classList.contains("hidden")) {
        idleBox.classList.remove("hidden");
        idleBox.textContent = `Error creating magnet session: ${err.message}`;
      } else {
        listenerStatus.textContent = err.message;
      }
      generateBtn.textContent = activeToken ? "New Magnet Link" : "Generate Magnet Link";
    } finally {
      generateBtn.disabled = false;
    }
  }

  document.addEventListener("visibilitychange", () => {
    if (!listening) return;
    if (document.hidden) {
      pausePolling();
      listenerDot.classList.remove("active");
      listenerStatus.textContent =
        "Paused while this tab is hidden. The session stays active until it expires.";
      return;
    }
    listenerDot.classList.add("active");
    listenerStatus.textContent =
      "Listening for HTTP tracker, UDP tracker, and TCP peer connections (polling every 1.5s)…";
    resumePolling();
  });

  generateBtn.addEventListener("click", startNewSession);
  stopBtn.addEventListener("click", () =>
    haltListening("Stopped listening. Click New Magnet Link to start another test.")
  );
  refreshBtn.addEventListener("click", pollOnce);

  copyMagnetBtn.addEventListener("click", async () => {
    if (!magnetInput.value) return;
    await navigator.clipboard.writeText(magnetInput.value);
    const original = copyMagnetBtn.textContent;
    copyMagnetBtn.textContent = "Copied!";
    window.setTimeout(() => {
      copyMagnetBtn.textContent = original;
    }, 1400);
  });

  return { startNewSession, stopPolling: haltListening };
}

