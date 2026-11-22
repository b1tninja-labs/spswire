"""Identify which GMG3 container format a buffer is, from its byte signature.

A service-programming update set delivers several unlabelled binaries (``uImage``, ``bootloader.bin``,
``*.smd``, ``*.mnf``, ``master.dnl``). This module names one from the same signatures the format
readers key on -- the U-Boot magic, the i.MX IVT tag, the ``$FLW_WRITER`` engine string, a PEM
bundle, or a base64 release-XML blob -- so a caller can route a carved member to the right reader.

It inspects a single member's bytes and reads nothing else; a ``container.iso`` is an ISO volume,
not a member, so identify its carved contents rather than the whole image.
"""

from __future__ import annotations

from spswire import dnl, ivt, mnf, smd, uimage

_PEM_MARKER = b"-----BEGIN "

#: The format names :func:`identify` can return, in the order it tests them.
NAMES = ("uimage", "ivt", "dnl", "smd", "mnf")


def identify(data: bytes) -> str | None:
    """Return the container-format name for ``data``, or ``None`` if nothing matches.

    The strong binary magics are tested first (the U-Boot image header, then the i.MX IVT),
    then the ``$FLW_WRITER`` marker of a V850 ``master.dnl``, then a PEM ``.smd`` bundle, and
    finally a ``.mnf`` whose base64 blob decodes to release XML. Each test reuses the matching
    reader's own acceptance, so a name means that reader will parse the buffer.
    """
    if len(data) >= uimage.HEADER_SIZE and int.from_bytes(data[0:4], "big") == uimage.MAGIC:
        return "uimage"
    if len(data) >= ivt.IVT_SIZE and data[0] == ivt.HEADER_TAG:
        try:
            ivt.parse(data)
            return "ivt"
        except ivt.IVTError:
            pass
    if dnl.FLW_WRITER in data:
        return "dnl"
    if _PEM_MARKER in data:
        try:
            smd.parse(data)
            return "smd"
        except smd.SMDError:
            pass
    try:
        mnf.release_xml(data)
        return "mnf"
    except mnf.MNFError:
        pass
    return None
