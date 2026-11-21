"""The i.MX6 IVT parses and detects the HAB-open (CSF-at-EOF) shape."""

from __future__ import annotations

import pytest
import samples

from spswire import ivt


def test_a_bootloader_ivt_is_parsed():
    # An SPL-style IVT in the i.MX6 OCRAM region: entry 0x00909030, self 0x00909000, no DCD.
    image = samples.ivt(
        entry=0x00909030, self_ptr=0x00909000, csf_file_offset=0x4110, file_len=0x4110
    )
    table = ivt.parse(image)
    assert table.entry == 0x00909030
    assert table.self_ptr == 0x00909000
    assert not table.has_dcd
    assert table.file_offset(table.entry) == 0x30


def test_a_csf_that_resolves_to_eof_is_hab_open():
    file_len = 0x4110
    image = samples.ivt(
        entry=0x00909030, self_ptr=0x00909000, csf_file_offset=file_len, file_len=file_len
    )
    table = ivt.parse(image)
    assert table.csf_file_offset() == file_len
    assert table.is_hab_open(file_len)


def test_a_csf_inside_the_image_is_not_hab_open():
    file_len = 0x8000
    image = samples.ivt(
        entry=0x00909030, self_ptr=0x00909000, csf_file_offset=0x4110, file_len=file_len
    )
    table = ivt.parse(image)
    assert not table.is_hab_open(file_len)


def test_no_csf_counts_as_hab_open():
    image = samples.ivt(
        entry=0x00909030, self_ptr=0x00909000, csf_file_offset=None, file_len=0x4110
    )
    table = ivt.parse(image)
    assert table.csf_file_offset() is None
    assert table.is_hab_open(0x4110)


def test_a_non_ivt_buffer_is_an_error():
    with pytest.raises(ivt.IVTError):
        ivt.parse(b"\x00" * 32)
