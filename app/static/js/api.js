/**
 * Thin HTTP client wrappers for the backend endpoints.
 */

export async function fetchClientIp() {
  const response = await fetch("/api/ip", { cache: "no-store" });
  if (!response.ok) {
    throw new Error(`Failed to fetch client IP (HTTP ${response.status})`);
  }
  return response.json();
}

export async function createTorrentSession() {
  const response = await fetch("/api/torrent/sessions", {
    method: "POST",
    cache: "no-store",
  });
  if (!response.ok) {
    throw new Error(`Failed to create torrent session (HTTP ${response.status})`);
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

