"""The .mnf binary part-number index parses PN, SHA-256 and the block-count size."""

from __future__ import annotations

import hashlib

import pytest
import samples

from spswire import mnf

_XML = (
    b"<BOSCHXML><OVERALL><FINALNAME>EXAMPLE_RELEASE</FINALNAME>"
    b"<SKIPCHECKSUM>true</SKIPCHECKSUM></OVERALL></BOSCHXML>"
)
_ENTRIES = [
    ("84029334", 8082, hashlib.sha256(b"container").digest()),
    ("84029335", 530, hashlib.sha256(b"eol-app").digest()),
    ("23199236", 205070, hashlib.sha256(b"gracenote").digest()),
]


def test_the_part_number_index_is_parsed():
    data = samples.mnf_with_index(_ENTRIES, _XML)
    entries = mnf.index(data)

    # The signing .smd row comes first and is zeroed.
    assert entries[0].part_number == "84089010"
    assert entries[0].zeroed
    assert entries[0].sha256 == b""

    rows = entries[1:]
    assert [e.part_number for e in rows] == ["84029334", "84029335", "23199236"]
    assert [e.size_blocks for e in rows] == [8082, 530, 205070]
    assert [e.sha256 for e in rows] == [sha for _, _, sha in _ENTRIES]
    assert not any(e.zeroed for e in rows)


def test_the_size_field_is_a_nominal_block_count():
    data = samples.mnf_with_index(_ENTRIES, _XML)
    container = mnf.index(data)[1]
    assert container.size_blocks == 8082
    assert container.nominal_size == 8082 * 1024


def test_index_and_release_xml_read_the_same_file():
    data = samples.mnf_with_index(_ENTRIES, _XML)
    assert mnf.release_xml(data) == _XML
    assert len(mnf.index(data)) == len(_ENTRIES) + 1  # + the .smd row


def test_a_file_with_no_part_number_row_is_an_error():
    with pytest.raises(mnf.MNFError):
        mnf.index(b"\x00\x10\x20\x30" * 4)
