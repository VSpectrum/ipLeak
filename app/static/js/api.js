/**
 * Thin HTTP client wrappers for the backend endpoints.
 */

async function errorDetail(response, fallback) {
  try {
    const body = await response.json();
    if (typeof body.detail === "string" && body.detail) return body.detail;
  } catch {
    // The body was not JSON.
  }
  return fallback;
}

export async function fetchClientIp() {
  const response = await fetch("/api/ip", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Failed to fetch client IP (HTTP ${response.status})`);
  }
  return response.json();
}

export async function classifyAddresses(addresses) {
  const unique = [...new Set(addresses.filter(Boolean))];
  if (unique.length === 0) return { results: [] };
  const response = await fetch("/api/ip/classify", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    cache: "no-store",
    body: JSON.stringify({ addresses: unique }),
  });
  if (!response.ok) {
    throw new Error(
      await errorDetail(response, `Failed to classify addresses (HTTP ${response.status})`),
    );
  }
  return response.json();
}

export async function createTorrentSession() {
  const response = await fetch("/api/torrent/sessions", {
    method: "POST",
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(
      await errorDetail(response, `Failed to create torrent session (HTTP ${response.status})`),
    );
  }
  return response.json();
}

export async function fetchTorrentSession(token) {
  const response = await fetch(`/api/torrent/sessions/${encodeURIComponent(token)}`, {
    cache: "no-store",
  });
  if (response.status === 404) {
    return null;
  }
  if (!response.ok) {
    throw new Error(`Failed to fetch session status (HTTP ${response.status})`);
  }
  return response.json();
}

