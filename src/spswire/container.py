"""The known layout of a GMG3 ``container.iso`` install container.

``container.iso`` (PN ``84029334``) is an ISO-9660 volume holding the installer: the Lua/shell
scripts, a busybox toolset, the Teseo and V850 firmware, the per-partition md5 manifests, and the
GM CA trust anchor. This module does **not** parse ISO 9660 -- that is a separate reader's job. It
names the container's known paths and delegates the volume walk to any reader that exposes
``member(path) -> bytes`` (for example ``iso9660.Volume``), so no second ISO parser lives here and
``spswire`` keeps no dependency on one.

Paths are the documented container layout; a reader is injected by the caller::

    import iso9660
    from spswire.container import Container

    c = Container(iso9660.open_volume(open("84029334", "rb").read()))
    ca = c.cacert()
    dnl = c.v850_dnl()
"""

from __future__ import annotations

from typing import Final, Protocol, runtime_checkable

#: The GM Code Signature CA trust anchor, shipped twice (byte-identical).
CACERT: Final = "security/cacert.pem"
CACERT_BOOT: Final = "bin/boot/CaCert.pem"
#: The RSA public key that equals the CA's SPKI.
PUBLIC_CODEKEY: Final = "security/public_codekey.pem"

#: Teseo (GNSS) firmware, md5-only.
TESEO_FLASHER: Final = "firmware/teseo/flasher.bin"
TESEO_APP: Final = "firmware/teseo/teseo_app.bin"

#: V850 companion-MCU hardware-revision slots; only ``gmmy16_b3`` is populated in 15.2B033.
V850_VARIANTS: Final = ("gmmy16_a", "gmmy16_b1", "gmmy16_b3")
V850_CRC_SECTIONS: Final = ("application", "bootloader", "bootmanager")

#: Per-partition integrity manifests (``.md5`` filesystem, ``.md5x`` raw block device).
MD5_MANIFESTS: Final = (
    "md5/boot.md5x",
    "md5/nor.md5x",
    "md5/nor_par.md5x",
    "md5/emmc_user.md5x",
    "md5/root.md5",
    "md5/static.md5",
    "md5/dynamic.md5",
    "md5/navdata.md5",
)


@runtime_checkable
class VolumeReader(Protocol):
    """Anything that returns a member's bytes by path -- e.g. ``iso9660.Volume``."""

    def member(self, path: str) -> bytes: ...


def v850_dir(variant: str = "gmmy16_b3") -> str:
    """The directory holding one V850 hardware variant's image and CRC sidecars."""
    if variant not in V850_VARIANTS:
        raise ValueError(f"{variant!r} is not one of {V850_VARIANTS}")
    return f"firmware/v850/{variant}"


def v850_dnl_path(variant: str = "gmmy16_b3") -> str:
    """The path of a V850 ``master.dnl`` image for one variant."""
    return f"{v850_dir(variant)}/master.dnl"


def v850_crc_path(section: str, variant: str = "gmmy16_b3") -> str:
    """The path of a V850 ``*.crc`` readback sidecar (application/bootloader/bootmanager)."""
    if section not in V850_CRC_SECTIONS:
        raise ValueError(f"{section!r} is not one of {V850_CRC_SECTIONS}")
    return f"{v850_dir(variant)}/{section}.crc"


class Container:
    """A GMG3 ``container.iso`` read through an injected ISO-9660 volume reader."""

    def __init__(self, volume: VolumeReader) -> None:
        self._volume = volume

    def member(self, path: str) -> bytes:
        """Return the bytes of one container member by path."""
        return self._volume.member(path)

    def cacert(self) -> bytes:
        """The GM Code Signature CA trust anchor (``security/cacert.pem``)."""
        return self._volume.member(CACERT)

    def public_codekey(self) -> bytes:
        """The RSA public key shipped as ``security/public_codekey.pem``."""
        return self._volume.member(PUBLIC_CODEKEY)

    def v850_dnl(self, variant: str = "gmmy16_b3") -> bytes:
        """The V850 ``master.dnl`` image for one hardware variant."""
        return self._volume.member(v850_dnl_path(variant))

    def v850_crc(self, section: str, variant: str = "gmmy16_b3") -> bytes:
        """One V850 ``*.crc`` readback sidecar for one hardware variant."""
        return self._volume.member(v850_crc_path(section, variant))
