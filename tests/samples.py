"""Synthetic format samples built to the documented format specs.

No GM firmware bytes are vendored. Every buffer here is constructed field by field from the
documented layout so the readers can be exercised without a sample from a car.
"""

from __future__ import annotations

import base64
import struct

from spswire import uimage as uimage_mod


def lz77_token(literal: int, length: int = 0, distance: int = 0) -> bytes:
    """Encode one 3-byte GM LZ77 token."""
    value = (literal & 0xFF) | ((length & 0xF) << 8) | ((distance & 0xFFF) << 12)
    return value.to_bytes(3, "little")


def lz77_buffer(out_size: int, tokens: list[bytes], slack: int = 0) -> bytes:
    """Wrap tokens in the 8-byte ``[out_size][comp_size]`` header, with optional trailing slack."""
    body = b"".join(tokens)
    header = struct.pack("<II", out_size, len(body))
    return header + body + b"\x00" * slack


def uimage(
    payload: bytes, comp: int = uimage_mod.COMP_GM_LZ77, name: str = "Linux-3.14.51"
) -> bytes:
    """Build a 64-byte U-Boot legacy image header over ``payload`` (CRC fields left zero)."""
    header = struct.pack(
        ">IIIIIIIBBBB",
        uimage_mod.MAGIC,
        0,  # header crc (not checked here)
        0,  # time
        len(payload),
        0x10008000,  # load
        0x10008000,  # entry
        0,  # data crc
        5,  # os = linux
        2,  # arch = arm
        2,  # type = kernel
        comp,
    )
    header += name.encode("ascii").ljust(32, b"\x00")[:32]
    return header + payload


def ivt(
    entry: int, self_ptr: int, csf_file_offset: int | None, file_len: int, dcd: int = 0
) -> bytes:
    """Build a 32-byte i.MX IVT, then pad to ``file_len``.

    ``csf_file_offset`` is where the CSF would start within the image; ``None`` means no CSF.
    Pass ``file_len`` for the whole image so an EOF-resolving CSF reproduces the HAB-open shape.
    """
    csf = 0 if csf_file_offset is None else self_ptr + csf_file_offset
    ivt_bytes = struct.pack(
        "<BHB7I",
        0xD1,
        0x0020,  # length, big-endian in the wire layout
        0x40,  # version
        entry,
        0,  # reserved1
        dcd,
        self_ptr + 0x20,  # boot_data pointer (arbitrary, after the IVT)
        self_ptr,
        csf,
        0,  # reserved2
    )
    # struct packs the length little-endian; the IVT stores it big-endian, so fix those two bytes.
    fixed = bytearray(ivt_bytes)
    fixed[1], fixed[2] = 0x00, 0x20
    return bytes(fixed).ljust(file_len, b"\x00")


def smd(
    signer: bytes,
    manifest_digest: bytes,
    manifest_sig: bytes,
    parts: dict[str, tuple[bytes, bytes]],
) -> str:
    """Build a GM-style ``.smd`` PEM bundle (certificate, manifest rows, per-PN rows)."""

    def block(label: str, body: bytes) -> str:
        encoded = base64.b64encode(body).decode("ascii")
        return f"-----BEGIN {label}-----\n{encoded}\n-----END {label}-----\n"

    out = block("CERTIFICATE", signer)
    out += block("SHA256 MANIFEST", manifest_digest)
    out += block("sha256WithRSAEncryption MANIFEST", manifest_sig)
    for pn, (digest, signature) in parts.items():
        out += block(f"SHA256 SW PN {pn}", digest)
        out += block(f"sha256WithRSAEncryption SW PN {pn}", signature)
    return out


def mnf(index_bytes: bytes, release_xml: bytes) -> bytes:
    """Build a ``.mnf``: a binary index prefix followed by the base64 of the release XML."""
    return index_bytes + base64.b64encode(release_xml)


def mnf_record(pn: str, size_blocks: int, sha256: bytes) -> bytes:
    """One 57-byte .mnf index record: PN(8) + size(u32 BE) + SHA-256(32) + 0x1f + 12-byte pad."""
    return pn.encode("ascii") + struct.pack(">I", size_blocks) + sha256 + b"\x1f" + b"\x00" * 12


def mnf_with_index(
    entries: list[tuple[str, int, bytes]],
    release_xml: bytes,
    smd_pn: str = "84089010",
) -> bytes:
    """Build a .mnf: header, a zeroed .smd row, 57-byte records, a trailer, then the base64 XML."""
    out = bytearray(b"\x00\x01\x40\x1f")
    out += b"\x00" * 20
    out += smd_pn.encode("ascii") + b"\x1f" + b"\x00" * 20  # the zeroed signing row
    for pn, size_blocks, sha256 in entries:
        out += mnf_record(pn, size_blocks, sha256)
    out += b"\x00" * 16  # a trailing header (non-base64) before the blob
    out += base64.b64encode(release_xml)
    return bytes(out)


def roundtrip_lz77(plaintext: bytes) -> bytes:
    """A literal-only reference encoding of ``plaintext`` for the decoder to recover."""
    tokens = [lz77_token(byte) for byte in plaintext]
    return lz77_buffer(len(plaintext), tokens)


def lz77_uimage(plaintext: bytes) -> bytes:
    """A uImage whose payload is a GM 0x4d LZ77 buffer that decodes to ``plaintext``."""
    return uimage(roundtrip_lz77(plaintext), comp=uimage_mod.COMP_GM_LZ77)


def dnl_section_header(type_byte: int, index: int) -> bytes:
    """One aligned $FLW_WRITER section-record header (16 bytes ending 00 80)."""
    return bytes([type_byte, index]) + b"\x00" * 6 + b"\x70\x00\x12\x34\x56\x78" + b"\x00\x80"


def dnl_stream(device: str = "D70F4006", sections: list[tuple[int, int]] | None = None) -> bytes:
    """A synthetic master.dnl: a record-0 header with a device marker, $FLW_WRITER, section records."""
    if sections is None:
        sections = [(0x80, 0x00), (0x84, 0x01), (0x84, 0x02)]
    out = bytearray()
    out += dnl_section_header(*sections[0])  # record 0
    out += b"\x55" * (0xDD - len(out))  # fill up to the device marker offset
    out += device.encode("ascii") + b"  "
    out += b"\x55" * (0x3760 - len(out))
    out += b"$FLW_WRITER\x00"
    for type_byte, index in sections[1:]:
        out += b"\x55" * 64
        out += dnl_section_header(type_byte, index)
    return bytes(out)


class FakeVolume:
    """A minimal ISO-9660 reader stand-in: member(path) over a dict, raising KeyError-as-member."""

    def __init__(self, members: dict[str, bytes]) -> None:
        self._members = members

    def member(self, path: str) -> bytes:
        try:
            return self._members[path]
        except KeyError:
            raise FileNotFoundError(path) from None
