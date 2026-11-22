"""The container reader maps known paths through an injected ISO-9660 reader."""

from __future__ import annotations

import pytest
import samples

from spswire import container


def _container() -> container.Container:
    volume = samples.FakeVolume(
        {
            container.CACERT: b"-----BEGIN CERTIFICATE-----\nGM CA\n",
            container.PUBLIC_CODEKEY: b"-----BEGIN PUBLIC KEY-----\n",
            "firmware/v850/gmmy16_b3/master.dnl": b"\x80\x00\x00\x00V850",
            "firmware/v850/gmmy16_b3/application.crc": b"533dd9bc387f98db",
        }
    )
    return container.Container(volume)


def test_a_known_container_path_returns_its_bytes():
    c = _container()
    assert c.cacert().startswith(b"-----BEGIN CERTIFICATE-----")
    assert c.public_codekey().startswith(b"-----BEGIN PUBLIC KEY-----")
    assert c.v850_dnl() == b"\x80\x00\x00\x00V850"
    assert c.v850_crc("application") == b"533dd9bc387f98db"


def test_the_v850_paths_are_built_from_the_documented_layout():
    assert container.v850_dnl_path("gmmy16_b3") == "firmware/v850/gmmy16_b3/master.dnl"
    assert container.v850_crc_path("bootloader") == "firmware/v850/gmmy16_b3/bootloader.crc"


def test_an_unknown_variant_or_section_is_rejected_before_a_read():
    with pytest.raises(ValueError):
        container.v850_dnl_path("gmmy16_z9")
    with pytest.raises(ValueError):
        container.v850_crc_path("nonsense")


def test_a_missing_member_propagates_the_reader_error():
    c = container.Container(samples.FakeVolume({}))
    with pytest.raises(FileNotFoundError):
        c.cacert()


def test_the_reader_only_needs_a_member_method():
    assert isinstance(samples.FakeVolume({}), container.VolumeReader)
