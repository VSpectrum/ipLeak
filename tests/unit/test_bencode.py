"""Unit tests for BEP 3 bencode encoder and decoder."""

from __future__ import annotations

import pytest

from app.torrent.bencode import bdecode, bencode


def test_bencode_primitives_and_collections() -> None:
    assert bencode(0) == b"i0e"
    assert bencode(42) == b"i42e"
    assert bencode(-15) == b"i-15e"
    assert bencode(b"") == b"0:"
    assert bencode(b"\xff\x00\xfe") == b"3:\xff\x00\xfe"
    assert bencode("spam") == b"4:spam"
    assert bencode(["spam", 4]) == b"l4:spami4ee"


def test_bencode_sorts_dictionary_keys_by_raw_bytes() -> None:
    payload = {
        "peers": b"\x7f\x00\x00\x01\x1a\xe9",
        "complete": 1,
        "interval": 60,
    }
    encoded = bencode(payload)
    assert encoded.startswith(b"d8:completei1e8:intervali60e5:peers6:")
    decoded = bdecode(encoded)
    assert decoded == {
        b"complete": 1,
        b"interval": 60,
        b"peers": b"\x7f\x00\x00\x01\x1a\xe9",
    }


def test_bencode_rejects_booleans_and_unsupported_types() -> None:
    with pytest.raises(TypeError):
        bencode(True)
    with pytest.raises(TypeError):
        bencode({123: "bad-key"})  # type: ignore[dict-item]
    with pytest.raises(TypeError):
        bencode(object())


@pytest.mark.parametrize(
    "invalid",
    [
        b"",
        b"i03e",
        b"i-0e",
        b"i12",
        b"03:abc",
        b"5:hi",
        b"l4:spam",
        b"d1:bi1e1:ai2ee",  # unsorted keys
        b"di1e4:spame",  # non-bytes key
        b"i1eextra",  # trailing bytes
    ],
)
def test_bdecode_rejects_malformed_inputs(invalid: bytes) -> None:
    with pytest.raises(ValueError):
        bdecode(invalid)

