"""The .smd bundle splits into certificate, manifest and per-PN rows."""

from __future__ import annotations

import pytest
import samples

from spswire import smd


def _bundle() -> str:
    return samples.smd(
        signer=b"signer-cert-der",
        manifest_digest=b"manifest-digest-32",
        manifest_sig=b"manifest-rsa-signature",
        parts={
            "84029334": (b"iso-digest", b"iso-signature"),
            "23199236": (b"gn-digest", b"gn-signature"),
        },
    )


def test_the_certificate_and_manifest_rows_are_recovered():
    bundle = smd.parse(_bundle())
    assert bundle.signer_certificate == b"signer-cert-der"
    assert bundle.manifest_digest == b"manifest-digest-32"
    assert bundle.manifest_signature == b"manifest-rsa-signature"


def test_each_part_pairs_its_digest_and_signature():
    bundle = smd.parse(_bundle())
    assert set(bundle.parts) == {"84029334", "23199236"}
    assert bundle.parts["84029334"].digest == b"iso-digest"
    assert bundle.parts["84029334"].signature == b"iso-signature"
    assert bundle.parts["23199236"].signature == b"gn-signature"


def test_bytes_and_text_parse_the_same():
    text = _bundle()
    assert smd.parse(text.encode("ascii")) == smd.parse(text)


def test_an_empty_bundle_is_an_error():
    with pytest.raises(smd.SMDError):
        smd.parse(b"not a pem bundle")
