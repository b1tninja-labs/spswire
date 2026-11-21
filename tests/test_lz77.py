"""The GM 0x4d LZ77 decoder round-trips and rejects malformed buffers."""

from __future__ import annotations

import pytest
import samples

from spswire import lz77


def test_a_literal_only_stream_round_trips():
    plaintext = b"spswire lz77 round-trip sample"
    assert lz77.decompress(samples.roundtrip_lz77(plaintext)) == plaintext


def test_a_back_reference_copies_with_overlap():
    # "ab", then copy 4 bytes from distance 2 (overlap => "abab"), then literal "c".
    tokens = [
        samples.lz77_token(ord("a")),
        samples.lz77_token(ord("b")),
        samples.lz77_token(ord("c"), length=4, distance=2),
    ]
    buffer = samples.lz77_buffer(out_size=7, tokens=tokens)
    assert lz77.decompress(buffer) == b"ababab" + b"c"


def test_trailing_slack_under_ten_bytes_is_allowed():
    buffer = samples.lz77_buffer(1, [samples.lz77_token(ord("Z"))], slack=9)
    assert lz77.decompress(buffer) == b"Z"


def test_a_short_buffer_is_an_error():
    with pytest.raises(lz77.LZ77Error):
        lz77.decompress(b"\x00\x00\x00")


def test_comp_size_too_far_from_the_body_is_an_error():
    buffer = samples.lz77_buffer(1, [samples.lz77_token(ord("Z"))], slack=10)
    with pytest.raises(lz77.LZ77Error):
        lz77.decompress(buffer)


def test_an_out_of_range_back_reference_is_an_error():
    buffer = samples.lz77_buffer(1, [samples.lz77_token(ord("a"), length=1, distance=1)])
    with pytest.raises(lz77.LZ77Error):
        lz77.decompress(buffer)


def test_an_oversized_output_declaration_is_an_error():
    buffer = samples.lz77_buffer(lz77.MAX_OUTPUT + 1, [samples.lz77_token(0)])
    with pytest.raises(lz77.LZ77Error):
        lz77.decompress(buffer)
