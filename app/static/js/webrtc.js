/**
 * Client-side WebRTC ICE candidate parser and leak verdicts.
 * STUN queries stay in the browser. Address scope comes from /api/ip/classify
 * when that request succeeds, and from the local classifier otherwise.
 */

const DEFAULT_STUN_SERVERS = [
  { urls: "stun:stun.l.google.com:19302" },
  { urls: "stun:stun1.l.google.com:19302" },
  { urls: "stun:stun.cloudflare.com:3478" },
];

function scopeResult(scope, isPublic = false) {
  return { scope, isPublic };
}

function parseIPv4(address) {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(address);
  if (!match) return null;
  const octets = match.slice(1).map((part) => Number(part));
  if (octets.some((part) => part > 255)) return null;
  return octets;
}

function classifyIPv4(octets) {
  const [a, b, c] = octets;
  if (a === 127) return scopeResult("loopback");
  if (a === 169 && b === 254) return scopeResult("link_local");
  if (
    a === 10 ||
    (a === 192 && b === 168) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 100 && b >= 64 && b <= 127)
  ) {
    return scopeResult("private");
  }
  if (
    a === 0 ||
    a >= 224 ||
    (a === 192 && b === 0 && c === 2) ||
    (a === 198 && b === 51 && c === 100) ||
    (a === 203 && b === 0 && c === 113) ||
    (a === 198 && (b === 18 || b === 19))
  ) {
    return scopeResult("reserved");
  }
  return scopeResult("public", true);
}

function classifyIPv6(address) {
  const lower = address.toLowerCase();
  if (lower === "::1") return scopeResult("loopback");
  if (lower === "::") return scopeResult("reserved");
  const first = lower.split(":")[0] || "0";
  const head = Number.parseInt(first || "0", 16);
  if (Number.isNaN(head)) return scopeResult("unknown");
  if (head >= 0xfe80 && head <= 0xfebf) return scopeResult("link_local");
  if (head >= 0xfc00 && head <= 0xfdff) return scopeResult("private");
  if (head >= 0xff00) return scopeResult("reserved");
  if (lower === "2001:db8::" || lower.startsWith("2001:db8:")) return scopeResult("reserved");
  return scopeResult("public", true);
}

export function formatEndpoint(address, port) {
  if (!address) return "";
  if (!port) return address;
  const host = address.includes(":") && !address.startsWith("[") ? `[${address}]` : address;
  return `${host}:${port}`;
}

function isPlaceholderAddress(address) {
  const value = String(address).trim().toLowerCase();
  return value === "0.0.0.0" || value === "::" || value === "0:0:0:0:0:0:0:0";
}

/**
 * Classify an ICE address the same way the server does.
 * Hostnames that are not mDNS stay unknown instead of being treated as public.
 */
export function classifyCandidateAddress(address) {
  if (!address) return scopeResult("unknown");
  let value = String(address).trim();
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  const zoneAt = value.indexOf("%");
  if (zoneAt !== -1) value = value.slice(0, zoneAt);
  if (value.toLowerCase().endsWith(".local")) return scopeResult("mdns");

  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(value);
  if (mapped) value = mapped[1];

  const ipv4 = parseIPv4(value);
  if (ipv4) return classifyIPv4(ipv4);
  if (value.includes(":")) return classifyIPv6(value);
  return scopeResult("unknown");
}

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
  const extras = {};
  for (let index = 8; index < parts.length - 1; index += 2) {
    extras[parts[index].toLowerCase()] = parts[index + 1];
  }

  let relatedAddress = extras.raddr ? extras.raddr.replace(/^\[|\]$/g, "") : null;
  let relatedPort = extras.rport ? Number.parseInt(extras.rport, 10) || null : null;
  if (!relatedAddress || isPlaceholderAddress(relatedAddress)) {
    relatedAddress = null;
    relatedPort = null;
  }

  const scopeInfo = classifyCandidateAddress(address);
  const relatedInfo = relatedAddress ? classifyCandidateAddress(relatedAddress) : null;

  return {
    address,
    port,
    protocol,
    candidateType,
    relatedAddress,
    relatedPort,
    relatedScope: relatedInfo ? relatedInfo.scope : null,
    relatedIsPublic: relatedInfo ? relatedInfo.isPublic : false,
    scope: scopeInfo.scope,
    isPublic: scopeInfo.isPublic,
  };
}

function httpIsLocal(httpScope) {
  return httpScope === "loopback" || httpScope === "private" || httpScope === "link_local";
}

export function canonicalIp(ip) {
  if (!ip) return "";
  let value = String(ip).trim().toLowerCase();
  if (value.startsWith("[") && value.endsWith("]")) value = value.slice(1, -1);
  const zoneAt = value.indexOf("%");
  if (zoneAt !== -1) value = value.slice(0, zoneAt);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(value);
  if (mapped) return mapped[1];
  if (value.includes(":")) return canonicalIpv6(value);
  return value;
}

function canonicalIpv6(address) {
  let value = address;
  const v4Tail = value.match(/^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (v4Tail) {
    const octets = v4Tail[2].split(".").map((part) => Number(part));
    if (octets.some((part) => part > 255)) return address;
    const hi = ((octets[0] << 8) | octets[1]).toString(16);
    const lo = ((octets[2] << 8) | octets[3]).toString(16);
    value = `${v4Tail[1]}${hi}:${lo}`;
  }
  const halves = value.split("::");
  if (halves.length > 2) return address;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (missing < 0) return address;
  const groups = halves.length === 2 ? [...head, ...Array(missing).fill("0"), ...tail] : head;
  if (groups.length !== 8) return address;
  const nums = groups.map((group) => Number.parseInt(group || "0", 16));
  if (nums.some((num) => Number.isNaN(num) || num > 0xffff)) return address;

  let bestStart = -1;
  let bestLen = 0;
  let index = 0;
  while (index < 8) {
    if (nums[index] !== 0) {
      index += 1;
      continue;
    }
    let end = index;
    while (end < 8 && nums[end] === 0) end += 1;
    if (end - index > bestLen) {
      bestStart = index;
      bestLen = end - index;
    }
    index = end;
  }
  const hex = nums.map((num) => num.toString(16));
  if (bestLen > 1) {
    return `${hex.slice(0, bestStart).join(":")}::${hex.slice(bestStart + bestLen).join(":")}`;
  }
  return hex.join(":");
}

export function addressFamily(ip) {
  const canonical = canonicalIp(ip);
  if (!canonical) return null;
  if (canonical.includes(":")) return 6;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(canonical)) return 4;
  return null;
}

export function sameIp(left, right) {
  const a = canonicalIp(left);
  const b = canonicalIp(right);
  return Boolean(a) && a === b;
}

function familyLabel(family) {
  return family === 6 ? "IPv6" : "IPv4";
}

function uniquePublicAddresses(candidates) {
  const ips = [];
  for (const cand of candidates) {
    if (cand.isPublic && cand.address) ips.push(cand.normalizedIp || cand.address);
    if (cand.relatedIsPublic && cand.relatedAddress) {
      ips.push(cand.relatedNormalized || cand.relatedAddress);
    }
  }
  const unique = [];
  for (const ip of ips) {
    if (!unique.some((existing) => sameIp(existing, ip))) unique.push(ip);
  }
  return unique;
}

function groupPublicByFamily(ips) {
  const groups = { 4: [], 6: [] };
  for (const ip of ips) {
    const family = addressFamily(ip);
    if (!family) continue;
    if (!groups[family].some((existing) => sameIp(existing, ip))) groups[family].push(ip);
  }
  return groups;
}

/**
 * Decide the WebRTC banner from gathered candidates and the HTTP connection scope.
 */
export function buildWebRtcVerdict({ supported, candidates, httpIp, httpScope }) {
  if (!supported) {
    return {
      tone: "ok",
      text: "WebRTC (RTCPeerConnection) is disabled in this browser — no WebRTC IP leak possible.",
    };
  }
  if (!candidates.length) {
    return {
      tone: "ok",
      text: "No ICE candidates were exposed (WebRTC UDP/STUN may be blocked by your browser or firewall).",
    };
  }

  const publicIps = uniquePublicAddresses(candidates);
  if (publicIps.length === 0) {
    return {
      tone: "ok",
      text: "Only local or mDNS ICE candidates were gathered. No public IP was exposed via WebRTC.",
    };
  }

  const listed = publicIps.join(", ");
  if (httpIsLocal(httpScope) || !httpIp) {
    const seen = httpIp ? `${httpIp} (${httpScope})` : "no public HTTP address";
    return {
      tone: "warn",
      text:
        `WebRTC exposed public address ${listed}. ` +
        `The HTTP connection only saw ${seen}, so this server could not see that address.`,
    };
  }

  const httpFamily = addressFamily(httpIp);
  const grouped = groupPublicByFamily(publicIps);
  const leaked = [];
  for (const family of [4, 6]) {
    const group = grouped[family];
    if (family === httpFamily) {
      leaked.push(...group.filter((ip) => !sameIp(ip, httpIp)));
    } else if (group.length > 1) {
      leaked.push(...group);
    }
  }
  if (leaked.length > 0) {
    return {
      tone: "danger",
      text:
        `Potential WebRTC leak: STUN discovered public ${familyLabel(addressFamily(leaked[0]))} ` +
        `(${leaked.join(", ")}) that differs from your HTTP IP (${httpIp}).`,
    };
  }

  const otherFamily = httpFamily === 4 ? 6 : 4;
  const others = httpFamily ? grouped[otherFamily] : [];
  if (others.length > 0) {
    const httpLabel = familyLabel(httpFamily);
    const otherLabel = familyLabel(otherFamily);
    const matched = httpFamily ? grouped[httpFamily] : [];
    const matchedText = matched.length
      ? `Public ${httpLabel} from WebRTC matches your HTTP IP (${httpIp}). `
      : `Your HTTP connection used ${httpLabel} ${httpIp}. `;
    return {
      tone: "ok",
      text:
        `${matchedText}WebRTC also exposed ${otherLabel} ${others.join(", ")}. ` +
        "That is the other address family on this network, not a leak.",
    };
  }

  return {
    tone: "ok",
    text: "Public WebRTC STUN address matches your HTTP IP. No proxy or VPN bypass detected.",
  };
}

/**
 * Label for the candidate-versus-HTTP column.
 */
export function comparisonBadge(candidate, httpIp, httpScope) {
  if (!candidate.isPublic) {
    return { text: "Local / Non-Public", variant: "" };
  }
  if (httpIsLocal(httpScope)) {
    return { text: "Not visible over HTTP", variant: "badge-warn" };
  }
  const candidateIp = candidate.normalizedIp || candidate.address;
  if (httpIp && addressFamily(candidateIp) && addressFamily(candidateIp) !== addressFamily(httpIp)) {
    return { text: "Other address family", variant: "badge-info" };
  }
  if (httpIp && sameIp(candidateIp, httpIp)) {
    return { text: "Matches HTTP IP", variant: "badge-ok" };
  }
  return { text: "Differs from HTTP IP", variant: "badge-danger" };
}

function applyClassification(candidate, row, related) {
  if (row) {
    candidate.scope = row.scope;
    candidate.isPublic = Boolean(row.is_public);
    if (row.ip) candidate.normalizedIp = row.ip;
  }
  if (related) {
    candidate.relatedScope = related.scope;
    candidate.relatedIsPublic = Boolean(related.is_public);
    if (related.ip) candidate.relatedNormalized = related.ip;
  }
}

async function annotateCandidates(candidates, classify) {
  for (const cand of candidates) {
    const own = classifyCandidateAddress(cand.address);
    cand.scope = own.scope;
    cand.isPublic = own.isPublic;
    if (cand.relatedAddress) {
      const related = classifyCandidateAddress(cand.relatedAddress);
      cand.relatedScope = related.scope;
      cand.relatedIsPublic = related.isPublic;
    }
  }
  if (!classify || candidates.length === 0) return;

  const addresses = [];
  for (const cand of candidates) {
    addresses.push(cand.address);
    if (cand.relatedAddress) addresses.push(cand.relatedAddress);
  }

  let body;
  try {
    body = await classify(addresses);
  } catch {
    return;
  }
  const byInput = new Map((body.results || []).map((row) => [row.input, row]));
  for (const cand of candidates) {
    applyClassification(cand, byInput.get(cand.address), byInput.get(cand.relatedAddress));
  }
}

/**
 * Gather WebRTC ICE candidates in the browser. STUN traffic does not go through this service.
 * `classify` is optional and, when provided, replaces the local scope with the server's.
 */
export async function gatherWebRTCCandidates({ timeoutMs = 4000, classify } = {}) {
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
    const key = [
      parsed.address,
      parsed.candidateType,
      parsed.protocol,
      parsed.relatedAddress || "",
    ].join("|");
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

  const candidates = Array.from(seen.values());
  await annotateCandidates(candidates, classify);
  return {
    supported: true,
    candidates,
  };
}
