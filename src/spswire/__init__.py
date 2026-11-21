"""Read the firmware-container formats of a GM GMG3 service-programming update set.

``spswire`` is a read-only reader for the file formats an SPS update set delivers (as pulled
through a TDS subscription for a GMG3 / ADIT-platform GM module): the custom ``0x4d`` uImage
LZ77 codec, the U-Boot legacy image header, the i.MX6 Image Vector Table, the GM ``.smd``
signature bundle, and the ``.mnf`` manifest's release XML. It parses bytes and returns
structure; it never flashes, verifies, signs, or opens a device, and it vendors no firmware.

The byte-level authority is the ``volt`` reverse-engineering write-up (read-only, not
vendored here); ``docs/sources.md`` records it and the public format references.
"""

from __future__ import annotations

from spswire import ivt, lz77, mnf, smd, uimage

__all__ = ["ivt", "lz77", "mnf", "smd", "uimage"]
