# IP Leak Check Service

A lightweight, modular **FastAPI** service inspired by [ipleak.net](https://ipleak.net) to inspect:

1. **HTTP Connection IP (on load)** — Immediately shows the IPv4/IPv6 address, network scope, and headers observed when loading the page.
2. **WebRTC Leak Check (on button click, client-side)** — Uses `RTCPeerConnection` against public STUN servers directly in the browser to check whether WebRTC exposes public or local LAN IPs outside your proxy/VPN.
3. **BitTorrent Leak Check (magnet + `.torrent` generator & multi-protocol listener)** — Generates a unique BEP 9 magnet link and downloadable `.torrent` file advertising:
   - **HTTP Tracker (`/announce/{token}`)** — Captures HTTP tracker announces, scrape hits, and any self-reported `&ip=` / `&ipv6=` query parameter leaks (BEP 3 / BEP 23 / BEP 48).
   - **Dual-Stack UDP Tracker (`udp://<host>:6969/announce`)** — Captures both IPv4 and IPv6 UDP tracker announces (BEP 15), catching HTTP/SOCKS-only proxy setups or IPv6 leaks.
   - **Dual-Stack TCP Peer Listener & Outbound Prober (`x.pe=<host>:6889`)** — Accepts incoming 68-byte BitTorrent peer wire handshakes (BEP 3) over IPv4/IPv6 and actively probes the client's announced `IP:port` to verify whether its listening port is externally reachable.

---

## Quick Start (Docker Compose)

```powershell
# Build and start the container in the background (maps 8000/tcp, 6969/udp, 6889/tcp)
docker compose up -d --build

# Follow container logs
docker compose logs -f
```

Then open `http://localhost:8000`.

---

## Local Development (`.venv`)

```powershell
# 1. Create and activate a virtual environment (Windows PowerShell)
python -m venv .venv
.\.venv\Scripts\Activate.ps1
# (On Linux/macOS: source .venv/bin/activate)

# 2. Install runtime dependencies (or requirements-dev.txt for tests & linter)
pip install -r requirements.txt
# pip install -r requirements-dev.txt

# 3. Start the FastAPI server (also starts UDP tracker on :6969 and TCP peer listener on :6889)
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

Then open `http://127.0.0.1:8000` (or `http://<your-server-ip>:8000`).

---

## Project Layout

```text
app/
├── config.py              # IPLEAK_* environment settings dataclass
├── ip_utils.py            # Client IP extraction, IPv4-mapped IPv6 normalization, scope classification
├── main.py                # FastAPI app factory & lifespan managing UDP/TCP BitTorrent listeners
├── routes/
│   ├── ip.py              # GET /api/ip
│   └── torrent.py         # POST/GET /api/torrent/sessions, GET /announce, GET /scrape
├── torrent/
│   ├── bencode.py         # Minimal BEP 3 bencode encoder/decoder
│   ├── magnet.py          # Magnet URI builder & Azureus/Mainline peer_id client decoder
│   ├── store.py           # Bounded TTL in-memory session & detection store
│   ├── udp_tracker.py     # Asyncio BEP 15 UDP tracker server
│   └── peer_server.py     # Asyncio BEP 3 TCP peer handshake server
└── static/
    ├── index.html         # Single-page UI
    ├── styles.css         # Responsive styling
    └── js/
        ├── app.js         # Entry point wiring HTTP IP, WebRTC button, and BitTorrent controller
        ├── api.js         # Fetch wrappers
        ├── webrtc.js      # Client-side RTCPeerConnection ICE candidate parser & leak detector
        └── torrent.js     # Magnet session UI & live polling controller
```

---

## Configuration (Environment Variables)

All settings are optional and have sensible defaults in `app/config.py`:

| Variable | Default | Description |
| --- | --- | --- |
| `IPLEAK_BIND_HOST` | `::` | Bind address for UDP tracker & TCP peer listeners (`::` enables dual-stack IPv4+IPv6) |
| `IPLEAK_PUBLIC_HOST` | *(from HTTP request)* | Explicit hostname/IP placed into generated magnet URIs |
| `IPLEAK_PUBLIC_HTTP_BASE_URL` | *(from HTTP request)* | Explicit base URL for HTTP `/announce` in magnet URIs |
| `IPLEAK_PUBLIC_IPV4` | *(auto when host is IPv4)* | Public IPv4 returned in compact 6-byte tracker `peers` responses |
| `IPLEAK_UDP_TRACKER_ENABLED` | `true` | Enable BEP 15 UDP tracker listener |
| `IPLEAK_UDP_TRACKER_PORT` | `6969` | UDP tracker port (falls back to ephemeral port if busy unless strict) |
| `IPLEAK_PEER_SERVER_ENABLED` | `true` | Enable BEP 3 TCP peer handshake listener |
| `IPLEAK_PEER_SERVER_PORT` | `6889` | TCP peer listener port |
| `IPLEAK_PEER_PROBE_ENABLED` | `true` | Actively probe client's announced TCP port with a BitTorrent handshake |
| `IPLEAK_PEER_PROBE_TIMEOUT` | `2.0` | Timeout in seconds for outbound peer TCP probes |
| `IPLEAK_STRICT_PORTS` | `false` | Fail startup instead of falling back if UDP/TCP port is occupied |
| `IPLEAK_TRUST_PROXY_HEADERS` | `false` | Read `X-Forwarded-For` / `CF-Connecting-IP` / `X-Real-IP` when behind a reverse proxy |
| `IPLEAK_SESSION_TTL_SECONDS` | `900` | Magnet session lifetime in seconds (15 minutes) |
| `IPLEAK_MAX_SESSIONS` | `1000` | Maximum concurrent in-memory sessions |

---

## Running Tests & Linting

```bash
pytest -v --cov=app
ruff check .
```

