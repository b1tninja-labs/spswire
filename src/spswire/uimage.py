"""The U-Boot legacy image header carried by GMG3 ``uImage`` and ramdisk members.

The header is the 64-byte big-endian ``image_header_t`` that ``mkimage`` writes, magic
``0x27051956``. The GMG3 boot partition (``volt/docs/BOOT-PARTITION.md`` section 4) ships a
kernel ``uImage`` whose ``comp`` byte is ``0x4d`` -- the GM LZ77 codec in :mod:`spswire.lz77`,
not one of the stock methods -- and a ``dlinitramfs.cpio.gz.uboot`` ramdisk of type 3.

This reader parses the header and returns the payload slice. It does not verify the header
or data CRC (``verify=no`` on this build) and it does not decompress: a ``0x4d`` payload is
handed to :func:`spswire.lz77.decompress` by the caller.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

MAGIC: Final = 0x27051956
HEADER_SIZE: Final = 64
NAME_SIZE: Final = 32

COMP_NONE: Final = 0x00
COMP_GZIP: Final = 0x01
COMP_BZIP2: Final = 0x02
COMP_LZMA: Final = 0x03
COMP_LZO: Final = 0x04
COMP_GM_LZ77: Final = 0x4D

_OS = {5: "linux"}
_ARCH = {2: "arm"}
_TYPE = {2: "kernel", 3: "ramdisk"}
_COMP = {
    COMP_NONE: "none",
    COMP_GZIP: "gzip",
    COMP_BZIP2: "bzip2",
    COMP_LZMA: "lzma",
    COMP_LZO: "lzo",
    COMP_GM_LZ77: "gm-lz77",
}


class UImageError(ValueError):
    """The buffer is not a U-Boot legacy image."""


@dataclass(frozen=True)
class UImageHeader:
    """The parsed 64-byte U-Boot legacy image header."""

    header_crc: int
    time: int
    size: int
    load: int
    entry: int
    data_crc: int
    os: int
    arch: int
    type: int
    comp: int
    name: str

    @property
    def os_name(self) -> str:
        return _OS.get(self.os, f"0x{self.os:02x}")

    @property
    def arch_name(self) -> str:
        return _ARCH.get(self.arch, f"0x{self.arch:02x}")

    @property
    def type_name(self) -> str:
        return _TYPE.get(self.type, f"0x{self.type:02x}")

    @property
    def comp_name(self) -> str:
        return _COMP.get(self.comp, f"0x{self.comp:02x}")

    @property
    def is_gm_lz77(self) -> bool:
        """Whether the payload is compressed with the GM ``0x4d`` LZ77 codec."""
        return self.comp == COMP_GM_LZ77


def parse(data: bytes) -> UImageHeader:
    """Parse the 64-byte header at the start of ``data``."""
    if len(data) < HEADER_SIZE:
        raise UImageError("buffer is shorter than the 64-byte header")
    magic = int.from_bytes(data[0:4], "big")
    if magic != MAGIC:
        raise UImageError(f"magic 0x{magic:08x} is not the U-Boot image magic")
    name = data[32:HEADER_SIZE].split(b"\x00", 1)[0].decode("ascii", "replace")
    return UImageHeader(
        header_crc=int.from_bytes(data[4:8], "big"),
        time=int.from_bytes(data[8:12], "big"),
        size=int.from_bytes(data[12:16], "big"),
        load=int.from_bytes(data[16:20], "big"),
        entry=int.from_bytes(data[20:24], "big"),
        data_crc=int.from_bytes(data[24:28], "big"),
        os=data[28],
        arch=data[29],
        type=data[30],
        comp=data[31],
        name=name,
    )


def payload(data: bytes) -> bytes:
    """Return the image payload: the ``size`` bytes after the 64-byte header."""
    header = parse(data)
    end = HEADER_SIZE + header.size
    if end > len(data):
        raise UImageError(f"payload of {header.size} bytes runs past the {len(data)}-byte buffer")
    return data[HEADER_SIZE:end]
