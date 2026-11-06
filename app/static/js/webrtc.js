/**
 * Pure client-side WebRTC ICE candidate leak checker.
 */

const DEFAULT_STUN_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
  { urls: "stun:stun.cloudflare.com:3478" },
];

/**
 * Parse a standard RFC 5245 / RFC 8445 ICE candidate line into structured fields.
 */
export function parseIceCandidate(candidateLine) {
  if (!candidateLine || !candidateLine.includes("candidate:")) {
    return null;
  }
  const trimmed = candidateLine.replace(/^a=/, "").trim();
  const parts = trimmed.split(/\s+/);
  // Format: candidate:<foundation> <component> <protocol> <priority> <address> <port> typ <type> ...
  if (parts.length < 8 || parts[6] !== "typ") {
    return null;
  }

  const protocol = parts[2].toLowerCase();
  const address = parts[4].replace(/^\[|\]$/g, "");
  const port = Number.parseInt(parts[5], 10) || null;
  const candidateType = parts[7].toLowerCase();
  const scopeInfo = classifyCandidateAddress(address);

  return {
    address,
    port,
    protocol,
    candidateType,
    scope: scopeInfo.scope,
    isPublic: scopeInfo.isPublic,
  };
}

/**
 * Classify an ICE candidate address into mDNS, loopback, private LAN, or public IPv4/IPv6.
 */
export function classifyCandidateAddress(address) {
  const lower = address.toLowerCase();
  if (lower.endsWith(".local")) {
    return { scope: "mdns", isPublic: false };
  }
  if (lower === "127.0.0.1" || lower === "::1" || lower.startsWith("127.")) {
    return { scope: "loopback", isPublic: false };
  }
  if (
    lower.startsWith("10.") ||
    lower.startsWith("192.168.") ||
    /^172\.(1[6-9]|2\d|3[0-1])\./.test(lower) ||
    lower.startsWith("169.254.") ||
    lower.startsWith("fe80:") ||
    lower.startsWith("fc") ||
    lower.startsWith("fd")
  ) {
    return { scope: "private", isPublic: false };
  }
  return { scope: "public", isPublic: true };
}

/**
 * Gather WebRTC ICE candidates in the browser without contacting our backend.
 */
export async function gatherWebRTCCandidates({ timeoutMs = 4000 } = {}) {
  const PeerConn =
    window.RTCPeerConnection ||
    window.webkitRTCPeerConnection ||
    window.mozRTCPeerConnection;

  if (!PeerConn) {
    return { supported: false, candidates: [] };
  }

  const seen = new Map();
  const pc = new PeerConn({ iceServers: DEFAULT_STUN_SERVERS });

  const recordLine = (line) => {
    const parsed = parseIceCandidate(line);
    if (!parsed) return;
    const key = `${parsed.address}|${parsed.candidateType}|${parsed.protocol}`;
    if (!seen.has(key)) {
      seen.set(key, parsed);
    }
  };

  try {
    pc.createDataChannel("ipleak-probe");

    await new Promise((resolve) => {
      const timer = window.setTimeout(resolve, timeoutMs);
      const finish = () => {
        window.clearTimeout(timer);
        resolve();
      };

      pc.onicecandidate = (event) => {
        if (event.candidate && event.candidate.candidate) {
          recordLine(event.candidate.candidate);
        } else if (!event.candidate) {
          finish();
        }
      };

      pc.onicegatheringstatechange = () => {
        if (pc.iceGatheringState === "complete") {
          finish();
        }
      };

      pc.createOffer()
        .then((offer) => pc.setLocalDescription(offer))
        .catch(() => finish());
    });

    if (pc.localDescription && pc.localDescription.sdp) {
      for (const line of pc.localDescription.sdp.split(/\r?\n/)) {
        if (line.includes("candidate:")) {
          recordLine(line);
        }
      }
    }
  } finally {
    try {
      pc.close();
    } catch {
      // Ignore close errors
    }
  }

  return {
    supported: true,
    candidates: Array.from(seen.values()),
  };
}

