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
RSASSA_LABEL: Final = b"RSASSA-PKCS1-v1_5"
#: Standard PKCS#1 v1.5 DigestInfo prefixes (DER), by digest name.
_DIGESTINFO: Final = {
    "ripemd160": bytes.fromhex("3021300906052b2403020105000414"),
    "sha1": bytes.fromhex("3021300906052b0e03021a05000414"),
    "sha256": bytes.fromhex("3031300d060960864801650304020105000420"),
}
_RSA_F4: Final = bytes.fromhex("010001")  # the common RSA public exponent 65537
_KEY_WINDOW: Final = 0x400
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


@dataclass(frozen=True)
class RSAVerifier:
    """The embedded RSA PKCS#1 v1.5 verifier apparatus found in the image, if any."""

    scheme_label: bool
    digests: tuple[str, ...]
    public_exponent_f4: bool

    @property
    def present(self) -> bool:
        """Whether the image carries a usable PKCS#1 v1.5 verifier (scheme label and a digest)."""
        return self.scheme_label and bool(self.digests)


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


def rsa_verifier(data: bytes) -> RSAVerifier:
    """Detect the embedded RSA PKCS#1 v1.5 verifier -- the V850 image's own root of trust.

    The V850 ROM/FBL verifies its images itself; the firmware body carries, in plaintext, the
    verifier apparatus. This reader reports it from standard constants (so it is not tied to this
    image's offsets): the ``RSASSA-PKCS1-v1_5`` scheme label, the DER DigestInfo prefixes for the
    digests it supports (RIPEMD-160, SHA-1, SHA-256 -- the weak two being a finding in themselves),
    and whether the common public exponent 65537 (``01 00 01``) sits in the key region after the
    label. Finding the apparatus is not proof the ROM enforces it; that gate is off-image.
    """
    digests = tuple(name for name, prefix in _DIGESTINFO.items() if prefix in data)
    label_at = data.find(RSASSA_LABEL)
    exponent = label_at >= 0 and _RSA_F4 in data[label_at : label_at + _KEY_WINDOW]
    return RSAVerifier(scheme_label=label_at >= 0, digests=digests, public_exponent_f4=exponent)
