"""The format sniffer names a buffer from its byte signature, or reports nothing."""

from __future__ import annotations

import samples

from spswire import detect


def test_each_container_format_is_identified_by_its_signature():
    assert detect.identify(samples.uimage(b"payload")) == "uimage"
    assert detect.identify(samples.ivt(0x909030, 0x909000, None, 0x200)) == "ivt"
    assert detect.identify(samples.dnl_stream()) == "dnl"

    xml = b"<BOSCHXML>" + b"x" * 64 + b"</BOSCHXML>"
    bundle = samples.smd(b"CERT", b"D" * 32, b"S" * 256, {"84029334": (b"d" * 32, b"s" * 256)})
    assert detect.identify(bundle.encode("ascii")) == "smd"
    assert detect.identify(samples.mnf_with_index([("84029334", 1, b"\xaa" * 32)], xml)) == "mnf"


def test_an_unrecognised_buffer_is_none():
    assert detect.identify(b"\x00" * 4096) is None
    assert detect.identify(b"") is None
