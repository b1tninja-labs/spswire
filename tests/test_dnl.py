"""The V850 master.dnl reader pins the $FLW_WRITER framing anchors."""

from __future__ import annotations

import pytest
import samples

from spswire import dnl


def test_the_flw_writer_records_are_framed():
    stream = samples.dnl_stream(
        device="D70F4006", sections=[(0x80, 0x00), (0x84, 0x01), (0x84, 0x02)]
    )
    assert dnl.has_flw_writer(stream)
    assert dnl.device_marker(stream) == "D70F4006"

    headers = dnl.section_headers(stream)
    assert [(h.type, h.index) for h in headers] == [(0x80, 0x00), (0x84, 0x01), (0x84, 0x02)]
    assert headers[0].offset == 0  # record 0 heads the stream
    assert all(h.offset >= 0 for h in headers)


def test_a_stream_without_the_signature_is_not_flw_writer():
    assert not dnl.has_flw_writer(b"\x55" * 4096)


def test_a_missing_device_marker_is_an_error():
    with pytest.raises(dnl.DNLError):
        dnl.device_marker(b"\x55" * 4096)


def test_the_embedded_rsa_verifier_is_detected():
    stream = samples.dnl_stream() + samples.dnl_rsa_blob(["ripemd160", "sha1", "sha256"])
    v = dnl.rsa_verifier(stream)
    assert v.present
    assert v.scheme_label
    assert set(v.digests) == {"ripemd160", "sha1", "sha256"}
    assert v.public_exponent_f4


def test_a_stream_with_no_verifier_apparatus_reports_absent():
    v = dnl.rsa_verifier(samples.dnl_stream())
    assert not v.present
    assert v.digests == ()
    assert not v.scheme_label


def test_the_weak_digest_oids_are_reported_for_review():
    # RIPEMD-160 and SHA-1 being accepted is itself a weakness worth surfacing.
    stream = samples.dnl_stream() + samples.dnl_rsa_blob(["sha1"], exponent=False)
    v = dnl.rsa_verifier(stream)
    assert "sha1" in v.digests
    assert not v.public_exponent_f4
