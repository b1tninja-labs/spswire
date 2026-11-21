"""The U-Boot legacy header parses and flags the GM 0x4d compression."""

from __future__ import annotations

import pytest
import samples

from spswire import uimage


def test_a_gm_lz77_kernel_header_is_parsed():
    payload = b"\x11\x22\x33\x44"
    header = uimage.parse(samples.uimage(payload, name="Linux-3.14.51-03444-g5cbc1b7"))
    assert header.size == len(payload)
    assert header.load == 0x10008000
    assert header.entry == 0x10008000
    assert header.os_name == "linux"
    assert header.arch_name == "arm"
    assert header.type_name == "kernel"
    assert header.comp == uimage.COMP_GM_LZ77
    assert header.comp_name == "gm-lz77"
    assert header.is_gm_lz77
    assert header.name == "Linux-3.14.51-03444-g5cbc1b7"


def test_a_stock_gzip_header_is_not_gm_lz77():
    header = uimage.parse(samples.uimage(b"xyz", comp=uimage.COMP_GZIP))
    assert header.comp_name == "gzip"
    assert not header.is_gm_lz77


def test_the_payload_slice_follows_the_header():
    payload = b"kernelbytes"
    assert uimage.payload(samples.uimage(payload)) == payload


def test_a_bad_magic_is_an_error():
    with pytest.raises(uimage.UImageError):
        uimage.parse(b"\x00" * 64)


def test_a_payload_past_the_buffer_is_an_error():
    image = bytearray(samples.uimage(b"1234"))
    image[12:16] = (999).to_bytes(4, "big")  # claim a payload longer than the buffer
    with pytest.raises(uimage.UImageError):
        uimage.payload(bytes(image))
