"""The ``python -m spswire`` dump CLI prints each container format's structure."""

from __future__ import annotations

from pathlib import Path

import pytest
import samples

from spswire import cli


def _write(tmp_path: Path, name: str, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def test_the_uimage_subcommand_prints_the_header(tmp_path, capsys):
    image = samples.uimage(b"KERNELPAYLOAD", name="Linux-3.14.51")
    assert cli.main(["uimage", _write(tmp_path, "uImage", image)]) == 0
    out = capsys.readouterr().out
    assert "name     Linux-3.14.51" in out
    assert "comp     gm-lz77" in out
    assert "gm-lz77  yes" in out


def test_the_mnf_subcommand_lists_the_index(tmp_path, capsys):
    xml = b"<BOSCHXML>" + b"x" * 64 + b"</BOSCHXML>"
    buffer = samples.mnf_with_index([("84029334", 100, b"\xaa" * 32)], release_xml=xml)
    assert cli.main(["mnf", _write(tmp_path, "part.mnf", buffer)]) == 0
    out = capsys.readouterr().out
    assert "84089010  (signing .smd row)" in out
    assert "84029334" in out
    assert (b"\xaa" * 32).hex() in out


def test_the_mnf_xml_flag_prints_the_release_xml(tmp_path, capsys):
    xml = b"<BOSCHXML>" + b"x" * 64 + b"</BOSCHXML>"
    buffer = samples.mnf_with_index([("84029334", 100, b"\xaa" * 32)], release_xml=xml)
    assert cli.main(["mnf", "--xml", _write(tmp_path, "part.mnf", buffer)]) == 0
    assert "<BOSCHXML>" in capsys.readouterr().out


def test_the_ivt_subcommand_reports_the_hab_shape(tmp_path, capsys):
    table = samples.ivt(entry=0x00909030, self_ptr=0x00909000, csf_file_offset=None, file_len=0x200)
    assert cli.main(["ivt", _write(tmp_path, "bootloader.bin", table)]) == 0
    out = capsys.readouterr().out
    assert "entry     0x00909030" in out
    assert "hab-open  yes" in out


def test_the_smd_subcommand_summarises_the_bundle(tmp_path, capsys):
    bundle = samples.smd(
        signer=b"CERTBYTES",
        manifest_digest=b"D" * 32,
        manifest_sig=b"S" * 256,
        parts={"84029334": (b"d" * 32, b"s" * 256)},
    )
    assert cli.main(["smd", _write(tmp_path, "part.smd", bundle.encode("ascii"))]) == 0
    out = capsys.readouterr().out
    assert "manifest  digest=yes signature=yes" in out
    assert "84029334  digest=yes signature=yes" in out


def test_the_dnl_subcommand_prints_the_anchors(tmp_path, capsys):
    stream = samples.dnl_stream() + samples.dnl_rsa_blob(["ripemd160", "sha1", "sha256"])
    assert cli.main(["dnl", _write(tmp_path, "master.dnl", stream)]) == 0
    out = capsys.readouterr().out
    assert "flw-writer  yes" in out
    assert "device      D70F4006" in out
    assert "rsa         present=yes exponent-65537=yes" in out


def test_the_container_subcommand_prints_the_layout(capsys):
    assert cli.main(["container"]) == 0
    out = capsys.readouterr().out
    assert "security/cacert.pem" in out
    assert "firmware/v850/gmmy16_b3/master.dnl" in out


def test_a_missing_file_returns_an_error_code(tmp_path):
    with pytest.raises(SystemExit) as caught:
        cli.main(["uimage", str(tmp_path / "does-not-exist")])
    assert caught.value.code == 2
