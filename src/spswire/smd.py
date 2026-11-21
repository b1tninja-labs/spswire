"""The GM ``.smd`` signature bundle shipped beside a signed GMG3 update manifest.

The ``.smd`` (``volt/docs/UPDATE-CONTAINER.md`` section 7) is **not** PKCS#7. It is a
PEM-delimited bundle: one signer certificate, then detached digest / signature pairs for the
manifest and for each firmware part number::

    -----BEGIN CERTIFICATE-----                            signer leaf
    -----BEGIN SHA256 MANIFEST-----                        base64 SHA-256 of the .mnf
    -----BEGIN sha256WithRSAEncryption MANIFEST-----       RSA-2048 signature over that hash
    -----BEGIN SHA256 SW PN 84029334-----                  per-PN digest ...
    -----BEGIN sha256WithRSAEncryption SW PN 84029334----- ... and its signature

This reader splits the bundle into its labelled blocks and groups the per-PN rows. It does
not evaluate the signatures or the certificate chain -- it recovers the structure the GM
code-signing design intended, which this build ships with checking switched off.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass, field

_BLOCK = re.compile(
    r"-----BEGIN (?P<label>[^-]+?)-----\s*(?P<body>.*?)\s*(?=-----(?:END|BEGIN))",
    re.DOTALL,
)
_DIGEST = re.compile(r"^SHA256(?: SW PN (?P<pn>\S+)| MANIFEST)?$")
_SIGNATURE = re.compile(r"^sha256WithRSAEncryption(?: SW PN (?P<pn>\S+)| MANIFEST)?$")


class SMDError(ValueError):
    """The bytes are not a GM ``.smd`` PEM bundle."""


@dataclass(frozen=True)
class Block:
    """One ``-----BEGIN label-----`` block and its decoded base64 body."""

    label: str
    data: bytes


@dataclass(frozen=True)
class PartSignature:
    """The detached digest and RSA signature for one firmware part number."""

    digest: bytes | None = None
    signature: bytes | None = None


@dataclass(frozen=True)
class SMDBundle:
    """The structure of a GM ``.smd`` signature bundle."""

    signer_certificate: bytes | None
    manifest_digest: bytes | None
    manifest_signature: bytes | None
    parts: dict[str, PartSignature] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)


def _decode(body: str) -> bytes:
    stripped = "".join(body.split())
    try:
        return base64.b64decode(stripped, validate=True)
    except binascii.Error as error:
        raise SMDError(f"block body is not valid base64: {error}") from error


def parse(data: bytes | str) -> SMDBundle:
    """Parse a ``.smd`` bundle into its certificate, manifest and per-PN blocks."""
    text = data.decode("ascii", "replace") if isinstance(data, bytes) else data
    blocks = [
        Block(label=match.group("label").strip(), data=_decode(match.group("body")))
        for match in _BLOCK.finditer(text + "-----END-----")
    ]
    if not blocks:
        raise SMDError("no -----BEGIN-----  blocks found")

    signer: bytes | None = None
    manifest_digest: bytes | None = None
    manifest_signature: bytes | None = None
    parts: dict[str, PartSignature] = {}
    for block in blocks:
        if block.label == "CERTIFICATE":
            signer = block.data
            continue
        digest_match = _DIGEST.match(block.label)
        signature_match = _SIGNATURE.match(block.label)
        if digest_match:
            pn = digest_match.group("pn")
            if pn is None:
                manifest_digest = block.data
            else:
                parts[pn] = PartSignature(
                    digest=block.data, signature=parts.get(pn, PartSignature()).signature
                )
        elif signature_match:
            pn = signature_match.group("pn")
            if pn is None:
                manifest_signature = block.data
            else:
                parts[pn] = PartSignature(
                    digest=parts.get(pn, PartSignature()).digest, signature=block.data
                )

    return SMDBundle(
        signer_certificate=signer,
        manifest_digest=manifest_digest,
        manifest_signature=manifest_signature,
        parts=parts,
        blocks=blocks,
    )
