"""Synthetic format samples built to the specs in ``volt/docs``.

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


def roundtrip_lz77(plaintext: bytes) -> bytes:
    """A literal-only reference encoding of ``plaintext`` for the decoder to recover."""
    tokens = [lz77_token(byte) for byte in plaintext]
    return lz77_buffer(len(plaintext), tokens)
