FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    IPLEAK_BIND_HOST="::" \
    IPLEAK_UDP_TRACKER_PORT=6969 \
    IPLEAK_PEER_SERVER_PORT=6889 \
    IPLEAK_STRICT_PORTS=true

WORKDIR /app

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 1000 appuser

COPY app ./app

USER appuser

EXPOSE 8000/tcp
EXPOSE 6969/udp
EXPOSE 6889/tcp

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/ip', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

