"""The GM ``.mnf`` manifest: the base64 release XML it carries.

The ``.mnf`` is not plain XML. Its header is a binary part-number to ``(size, SHA-256)``
index, followed by a base64 blob that decodes to the release XML (the ``<OVERALL>`` /
``<RELEASE>`` / ``<DEVICE>`` tree with the per-PN hashes).

This reader recovers the release XML, which is byte-defined: it is the longest base64 run in
the file whose decode is an XML document. The binary index record layout is not fixed without
a sample ``.mnf`` to pin field widths -- so it is a ROADMAP row, not a guessed parser here. No
firmware sample is vendored into this repository.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from typing import Final

_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")
_PART_NUMBER = re.compile(rb"\d{8}")

#: Block size the manifest's size field counts in.
SIZE_BLOCK: Final = 1024
#: Width of one regular index record: PN(8) + size(4) + SHA-256(32) + 0x1f + 12-byte pad.
_RECORD_SIZE: Final = 57
_PN_LEN: Final = 8
_SHA_LEN: Final = 32


class MNFError(ValueError):
    """The bytes are not a recoverable ``.mnf`` manifest."""


@dataclass(frozen=True)
class IndexEntry:
    """One part number's row in the ``.mnf`` binary index."""

    part_number: str
    size_blocks: int
    sha256: bytes
    zeroed: bool = False

    @property
    def nominal_size(self) -> int:
        """The size field times the 1024-byte block (nominal: not the exact payload length)."""
        return self.size_blocks * SIZE_BLOCK


def _blob_start(data: bytes) -> int:
    match = _B64_RUN.search(data)
    return match.start() if match else len(data)


def _candidates(data: bytes) -> list[bytes]:
    runs = [match.group() for match in _B64_RUN.finditer(data)]
    runs.sort(key=len, reverse=True)
    return runs


def index(data: bytes) -> list[IndexEntry]:
    """Parse the ``.mnf`` binary part-number index.

    The header carries a zeroed row for the signing ``.smd`` (so the ``.smd`` can sign the whole
    manifest), then fixed 57-byte records of ``[PN: 8 ASCII][size: u32 big-endian, in 1024-byte
    blocks][SHA-256: 32 bytes][0x1f][pad]``. Each :class:`IndexEntry` carries the part number, the
    SHA-256 of that payload (exact), and the block-count size field (nominal, see
    :attr:`IndexEntry.nominal_size`). A file with no part-number row raises :class:`MNFError`.
    """
    end = _blob_start(data)
    region = data[:end]

    first = _PART_NUMBER.search(region)
    if first is None:
        raise MNFError("no part-number row found")
    smd_off = first.start()
    entries = [IndexEntry(region[smd_off : smd_off + _PN_LEN].decode("ascii"), 0, b"", zeroed=True)]

    nxt = _PART_NUMBER.search(region, smd_off + _PN_LEN)
    if nxt is None:
        return entries
    off = nxt.start()
    while off + _PN_LEN + 4 + _SHA_LEN <= end:
        pn = data[off : off + _PN_LEN]
        if not pn.isdigit():
            break
        size_blocks = int.from_bytes(data[off + _PN_LEN : off + _PN_LEN + 4], "big")
        sha = data[off + _PN_LEN + 4 : off + _PN_LEN + 4 + _SHA_LEN]
        entries.append(IndexEntry(pn.decode("ascii"), size_blocks, sha))
        off += _RECORD_SIZE
    return entries


def release_xml(data: bytes) -> bytes:
    """Return the decoded release XML carried in a ``.mnf`` manifest.

    The blob is located as the longest base64 run whose decode begins (after optional
    whitespace) with ``<``. A file with no such run raises :class:`MNFError`.
    """
    for run in _candidates(data):
        if len(run) % 4:
            continue
        try:
            decoded = base64.b64decode(run, validate=True)
        except binascii.Error:
            continue
        if decoded.lstrip()[:1] == b"<":
            return decoded
    raise MNFError("no base64 run decoded to an XML document")
