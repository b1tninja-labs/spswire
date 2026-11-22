"""The Renesas ``$FLW_WRITER`` framing of a V850 ``master.dnl`` download stream.

``master.dnl`` is the V850 companion-MCU image, shipped inside ``container.iso`` under
``firmware/v850/<variant>/``. It is **not** a flat ROM: it is a framed flash-writer ("FLW")
download stream -- a Renesas µPD70F device marker, a ``$FLW_WRITER`` engine signature, a series of
``8X nn`` record headers, ``0x55`` fill and CRC16 trailers.

This reader pins the parts that are provable from the bytes alone: the device marker, the
``$FLW_WRITER`` signature, and the aligned **section-record headers** (``8X nn 00 00 00 00 00 00 ..
.. .. .. 00 80``). It does **not** return a byte-exact APP / BOOTLOADER / BOOTMANAGER section map:
the record semantics needed to partition the stream exactly are not recoverable from the bytes
without the flash-writer's own grammar, and the bootloader block uses a different header variant.
Those stay flagged. No firmware is vendored; tests use a synthetic stream built to this framing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Final

FLW_WRITER: Final = b"$FLW_WRITER"
_DEVICE_MARKER = re.compile(rb"D70F[0-9A-Fa-f]{4}")
#: An aligned section-record header: 0x8X type, index, six zero bytes, six bytes, then 0x00 0x80.
_SECTION_HEADER = re.compile(rb"[\x80-\x8f].\x00\x00\x00\x00\x00\x00.{6}\x00\x80", re.DOTALL)
_HEADER_SCAN_LIMIT: Final = 0x4000


class DNLError(ValueError):
    """The bytes are not a recognisable ``$FLW_WRITER`` download stream."""


@dataclass(frozen=True)
class SectionHeader:
    """One aligned ``$FLW_WRITER`` section-record header."""

    offset: int
    type: int
    index: int


def has_flw_writer(data: bytes) -> bool:
    """Whether the Renesas ``$FLW_WRITER`` flash-writer engine signature is present."""
    return FLW_WRITER in data


def device_marker(data: bytes) -> str:
    """The Renesas µPD70F device marker (for example ``D70F4006``) from the stream header."""
    match = _DEVICE_MARKER.search(data, 0, _HEADER_SCAN_LIMIT)
    if match is None:
        raise DNLError("no µPD70F device marker found in the header")
    return match.group().decode("ascii")


def section_headers(data: bytes) -> list[SectionHeader]:
    """The aligned ``8X nn .. 00 80`` section-record headers, in file order.

    These are the writer's major section records (the header, bootmanager and application data
    records). The bootloader block uses a different header variant that is not enumerated here, and
    mapping these records to the APP / BL / BM partition is inferred, not proven from the bytes.
    """
    return [
        SectionHeader(offset=m.start(), type=data[m.start()], index=data[m.start() + 1])
        for m in _SECTION_HEADER.finditer(data)
    ]
