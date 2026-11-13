"""Run the IP leak service as one dual-stack process."""

from __future__ import annotations

import argparse
import logging
import socket
import sys

import uvicorn

from app.config import load_settings
from app.ip_utils import bind_listener_socket
from app.main import enforce_single_process

logger = logging.getLogger("uvicorn.error")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the IP Leak Check service")
    parser.add_argument(
        "--reload",
        action="store_true",
        help="Restart when Python files change",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="HTTP port. Defaults to IPLEAK_HTTP_PORT or 8000.",
    )
    return parser


def main(argv: list[str] | None = None) -> None:
    """Bind HTTP the same way as the UDP and TCP listeners, then serve one process."""
    args = _build_parser().parse_args(argv)
    try:
        enforce_single_process()
    except RuntimeError as exc:
        print(exc, file=sys.stderr)
        raise SystemExit(1) from exc

    settings = load_settings()
    port = settings.http_port if args.port is None else args.port
    sock = bind_listener_socket(settings.bind_host, port, socket.SOCK_STREAM)
    bound_port = int(sock.getsockname()[1])

    config = uvicorn.Config(
        "app.main:app",
        workers=1,
        reload=args.reload,
        log_level="info",
        access_log=True,
    )
    config.configure_logging()
    logger.info(
        "IP Leak Check HTTP server on port %d (bind %s). Open http://127.0.0.1:%d",
        bound_port,
        settings.bind_host,
        bound_port,
    )

    server = uvicorn.Server(config)
    if args.reload:
        from uvicorn.supervisors import ChangeReload

        ChangeReload(config, target=server.run, sockets=[sock]).run()
        return

    server.run(sockets=[sock])


if __name__ == "__main__":
    main()
