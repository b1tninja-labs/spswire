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

_B64_RUN = re.compile(rb"[A-Za-z0-9+/]{64,}={0,2}")


class MNFError(ValueError):
    """The bytes do not carry a recoverable release-XML blob."""


def _candidates(data: bytes) -> list[bytes]:
    runs = [match.group() for match in _B64_RUN.finditer(data)]
    runs.sort(key=len, reverse=True)
    return runs


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
