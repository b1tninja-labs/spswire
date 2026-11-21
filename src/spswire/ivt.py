"""The i.MX6 Image Vector Table that heads GMG3 SPL / reset-vector images.

``resetvect.bin`` and ``bootloader.bin`` in the boot partition are i.MX6 boot images headed
by an IVT. The IVT is eight little-endian words::

    0  header     tag 0xD1, length 0x0020 (big-endian), version
    1  entry      first-instruction address
    2  reserved1
    3  dcd        Device Config Data pointer (0 = none)
    4  boot_data  pointer to the boot-data block (start, length, plugin)
    5  self       the IVT's own load address
    6  csf         Command Sequence File pointer (0 = none)
    7  reserved2

``self`` is the load address of the IVT, so a pointer's file offset is ``pointer - self``.
An image that reserves a ``csf`` pointer whose file offset lands at end-of-file carries no
CSF block -- a HAB image header with the CSF slot present but empty. This reader parses the
table and reports that shape; it does not validate a signature.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

HEADER_TAG: Final = 0xD1
HEADER_LENGTH: Final = 0x20
IVT_SIZE: Final = 32
_VERSIONS: Final = frozenset({0x40, 0x41, 0x42, 0x43})


class IVTError(ValueError):
    """The buffer does not begin with an i.MX6 Image Vector Table."""


@dataclass(frozen=True)
class ImageVectorTable:
    """The parsed 32-byte i.MX Image Vector Table."""

    version: int
    entry: int
    dcd: int
    boot_data: int
    self_ptr: int
    csf: int

    def file_offset(self, pointer: int) -> int:
        """Translate a load-address pointer into a byte offset within the image."""
        return pointer - self.self_ptr if self.self_ptr else pointer

    @property
    def has_dcd(self) -> bool:
        """Whether the IVT carries a Device Config Data table."""
        return self.dcd != 0

    def csf_file_offset(self) -> int | None:
        """The CSF block's byte offset within the image, or ``None`` when no CSF is set."""
        if not self.csf:
            return None
        return self.file_offset(self.csf)

    def is_hab_open(self, file_len: int) -> bool:
        """Whether the image is shipped unsigned: no CSF, or a CSF that starts at EOF."""
        offset = self.csf_file_offset()
        return offset is None or offset >= file_len


def parse(data: bytes) -> ImageVectorTable:
    """Parse the IVT at the start of ``data``."""
    if len(data) < IVT_SIZE:
        raise IVTError("buffer is shorter than the 32-byte IVT")
    if data[0] != HEADER_TAG:
        raise IVTError(f"first byte 0x{data[0]:02x} is not the IVT tag 0xd1")
    length = int.from_bytes(data[1:3], "big")
    if length != HEADER_LENGTH:
        raise IVTError(f"IVT length 0x{length:04x} is not 0x0020")
    version = data[3]
    if version not in _VERSIONS:
        raise IVTError(f"IVT version 0x{version:02x} is not a known HAB version")
    words = [int.from_bytes(data[offset : offset + 4], "little") for offset in range(4, 32, 4)]
    entry, _reserved1, dcd, boot_data, self_ptr, csf, _reserved2 = words
    return ImageVectorTable(
        version=version,
        entry=entry,
        dcd=dcd,
        boot_data=boot_data,
        self_ptr=self_ptr,
        csf=csf,
    )
