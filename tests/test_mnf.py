"""The .mnf release-XML blob is recovered past a binary index prefix."""

from __future__ import annotations

import pytest
import samples

from spswire import mnf


_RELEASE_XML = (
    b"<OVERALL><FINALNAME>MEN2_EU_SK_E2322B</FINALNAME><SKIPCHECKSUM>true</SKIPCHECKSUM></OVERALL>"
)


def test_the_release_xml_is_decoded_from_the_blob():
    # A binary index prefix with high bytes and short runs, then the base64 XML.
    index = bytes(range(256)) * 4
    data = samples.mnf(index_bytes=index, release_xml=_RELEASE_XML)
    assert mnf.release_xml(data) == _RELEASE_XML


def test_a_file_with_no_xml_blob_is_an_error():
    with pytest.raises(mnf.MNFError):
        mnf.release_xml(bytes(range(256)) * 4)
