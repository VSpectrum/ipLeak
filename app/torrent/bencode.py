"""Minimal BEP 3 bencode encoder and decoder for BitTorrent tracker responses."""

from __future__ import annotations

from typing import Any


def bencode(value: Any) -> bytes:
    """Encode a Python int, bytes, str, list/tuple, or dict into BEP 3 bencode bytes."""
    if isinstance(value, bool):
        raise TypeError("Booleans are not valid bencode values")
    if isinstance(value, int):
        return f"i{value}e".encode("ascii")
    if isinstance(value, bytes):
        return f"{len(value)}:".encode("ascii") + value
    if isinstance(value, str):
        encoded = value.encode("utf-8")
        return f"{len(encoded)}:".encode("ascii") + encoded
    if isinstance(value, (list, tuple)):
        return b"l" + b"".join(bencode(item) for item in value) + b"e"
    if isinstance(value, dict):
        items: list[tuple[bytes, bytes]] = []
        for raw_key, item_val in value.items():
            if isinstance(raw_key, bytes):
                key_bytes = raw_key
            elif isinstance(raw_key, str):
                key_bytes = raw_key.encode("utf-8")
            else:
                raise TypeError(f"Bencode dict keys must be bytes or str, got {type(raw_key)!r}")
            items.append((key_bytes, bencode(item_val)))
        items.sort(key=lambda pair: pair[0])
        body = b"".join(bencode(k) + v for k, v in items)
        return b"d" + body + b"e"
    raise TypeError(f"Unsupported type for bencode: {type(value)!r}")


def bdecode(data: bytes) -> Any:
    """Decode BEP 3 bencoded bytes into Python int, bytes, list, or dict[bytes, Any]."""
    if not isinstance(data, (bytes, bytearray)) or not data:
        raise ValueError("Cannot bdecode empty or non-bytes payload")

    value, next_idx = _decode_at(bytes(data), 0)
    if next_idx != len(data):
        raise ValueError(f"Trailing bytes after bencoded payload at index {next_idx}")
    return value


def _decode_at(buf: bytes, idx: int) -> tuple[Any, int]:
    if idx >= len(buf):
        raise ValueError("Unexpected end of bencode buffer")

    token = buf[idx : idx + 1]

    if token == b"i":
        end = buf.find(b"e", idx + 1)
        if end == -1:
            raise ValueError("Unterminated bencode integer")
        raw_num = buf[idx + 1 : end]
        if not raw_num or raw_num == b"-0" or (raw_num.startswith(b"0") and len(raw_num) > 1) or raw_num.startswith(b"-0"):
            raise ValueError(f"Invalid bencode integer: {raw_num!r}")
        return int(raw_num.decode("ascii")), end + 1

    if token == b"l":
        idx += 1
        items = []
        while idx < len(buf) and buf[idx : idx + 1] != b"e":
            item, idx = _decode_at(buf, idx)
            items.append(item)
        if idx >= len(buf):
            raise ValueError("Unterminated bencode list")
        return items, idx + 1

    if token == b"d":
        idx += 1
        result: dict[bytes, Any] = {}
        prev_key: bytes | None = None
        while idx < len(buf) and buf[idx : idx + 1] != b"e":
            if not (48 <= buf[idx] <= 57):
                raise ValueError("Bencode dict key must be a byte string")
            key, idx = _decode_at(buf, idx)
            if prev_key is not None and key <= prev_key:
                raise ValueError("Bencode dict keys must be sorted in ascending byte order")
            prev_key = key
            val, idx = _decode_at(buf, idx)
            result[key] = val
        if idx >= len(buf):
            raise ValueError("Unterminated bencode dict")
        return result, idx + 1

    colon = buf.find(b":", idx)
    if colon == -1:
        raise ValueError(f"Invalid bencode token at index {idx}")
    raw_len = buf[idx:colon]
    if not raw_len or not raw_len.isdigit() or (raw_len.startswith(b"0") and len(raw_len) > 1):
        raise ValueError(f"Invalid bencode string length: {raw_len!r}")
    length = int(raw_len.decode("ascii"))
    start = colon + 1
    end = start + length
    if end > len(buf):
        raise ValueError("Bencode byte string exceeds buffer length")
    return buf[start:end], end
