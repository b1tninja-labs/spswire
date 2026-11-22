"""The kernel capability decompresses a uImage end to end."""

from __future__ import annotations

import pytest
import samples

from spswire import kernel, uimage


def test_a_gm_lz77_uimage_decompresses_to_its_payload():
    plaintext = b"Linux kernel bytes recovered from the 0x4d codec" * 4
    image = samples.lz77_uimage(plaintext)
    assert kernel.decompress(image) == plaintext


def test_an_uncompressed_uimage_is_returned_as_is():
    payload = b"already a flat image"
    image = samples.uimage(payload, comp=uimage.COMP_NONE)
    assert kernel.decompress(image) == payload


def test_an_unsupported_compression_is_an_error():
    image = samples.uimage(b"gzipped", comp=uimage.COMP_GZIP)
    with pytest.raises(kernel.KernelError):
        kernel.decompress(image)


def test_a_bad_header_raises_the_uimage_error():
    with pytest.raises(uimage.UImageError):
        kernel.decompress(b"\x00" * 64)
