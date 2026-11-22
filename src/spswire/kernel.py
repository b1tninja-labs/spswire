"""Recover a GMG3 kernel from its ``uImage``, end to end.

A GMG3 boot partition ships the Linux kernel as a U-Boot legacy image whose ``comp`` byte is the
GM ``0x4d`` LZ77 codec. This capability ties :mod:`spswire.uimage` and :mod:`spswire.lz77`
together: parse the header, take the payload, and decode it to the kernel bytes. It is the typical
use -- turning a shipped ``uImage`` into the ``vmlinux`` it carries -- without the caller wiring
the two parsers by hand.
"""

from __future__ import annotations

from spswire import lz77, uimage


class KernelError(ValueError):
    """The ``uImage`` payload is not a compression this capability can decode."""


def decompress(image: bytes) -> bytes:
    """Return the decompressed kernel from a ``uImage``.

    The 64-byte U-Boot header selects the codec: ``0x4d`` is the GM LZ77 reader, and an
    uncompressed image is returned as-is. Any other compression raises :class:`KernelError`
    (this capability does not pull in gzip/bzip2/lzma/lzo). A malformed header or LZ77 stream
    raises the underlying :class:`spswire.uimage.UImageError` / :class:`spswire.lz77.LZ77Error`.
    """
    header = uimage.parse(image)
    payload = uimage.payload(image)
    if header.comp == uimage.COMP_GM_LZ77:
        return lz77.decompress(payload)
    if header.comp == uimage.COMP_NONE:
        return payload
    raise KernelError(f"uImage compression {header.comp_name} is not decoded here")
