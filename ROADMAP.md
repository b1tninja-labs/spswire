# spswire

The reader is code and is pinned by a named test. A row stays `[ ]` until that code exists, and a
test marked `(to be written)` must not exist yet. Nothing here calls firmware trusted, and no GM
firmware bytes are vendored: every test buffer is built from the documented layout. A format the
`volt` write-up describes but does not pin byte-for-byte stays a `[ ]` row until a sample fixes its
record widths.

## Session

The `0x4d` LZ77 codec, the U-Boot legacy header, the i.MX6 IVT, the `.smd` bundle and the `.mnf`
release XML are code. The `container.iso` member map defers to the sibling `iso9660` reader. The
binary `.mnf` index and the V850 `master.dnl` `$FLW_WRITER` framing wait for a sample.

| Obligation | Spec | Status | Where | Milestone |
|---|---|---|---|---|
| `spswire.lz77` | `volt/docs/BOOT-PARTITION.md` §3 (`FUN_1782a130`) | `[ok]` | Decode a GM `comp=0x4d` buffer: the 8-byte `[out_size][comp_size]` header and the 3-byte `literal \| length \| distance` tokens, with overlap-capable back-references and the 8 MiB output cap. A short buffer, a `comp_size` more than ten bytes off the body, an out-of-range back-reference and an oversized `out_size` are errors. Test: `tests/test_lz77.py::test_a_literal_only_stream_round_trips`, `tests/test_lz77.py::test_a_back_reference_copies_with_overlap`, `tests/test_lz77.py::test_comp_size_too_far_from_the_body_is_an_error`, `tests/test_lz77.py::test_an_out_of_range_back_reference_is_an_error` | - |
| `spswire.uimage` | `volt/docs/BOOT-PARTITION.md` §4; U-Boot legacy `image_header_t` | `[ok]` | Parse the 64-byte big-endian header (magic `0x27051956`), report load/entry and the compression type, flag the `0x4d` GM codec, and return the payload slice. A bad magic and a payload past the buffer are errors. Test: `tests/test_uimage.py::test_a_gm_lz77_kernel_header_is_parsed`, `tests/test_uimage.py::test_the_payload_slice_follows_the_header`, `tests/test_uimage.py::test_a_bad_magic_is_an_error` | - |
| `spswire.ivt` | `volt/docs/BOOT-PARTITION.md` §2; i.MX6 HAB IVT | `[ok]` | Parse the 32-byte Image Vector Table (tag `0xd1`, length `0x0020`), translate a load-address pointer to a file offset, and report the HAB-open shape — no CSF, or a CSF that resolves to end-of-file. A non-IVT buffer is an error. Test: `tests/test_ivt.py::test_a_bootloader_ivt_is_parsed`, `tests/test_ivt.py::test_a_csf_that_resolves_to_eof_is_hab_open`, `tests/test_ivt.py::test_a_csf_inside_the_image_is_not_hab_open` | - |
| `spswire.smd` | `volt/docs/UPDATE-CONTAINER.md` §7 | `[ok]` | Split a GM `.smd` PEM bundle (not PKCS#7) into the signer certificate, the manifest digest and signature, and the per-PN digest/signature rows. An input with no `-----BEGIN-----` block is an error. The reader does not evaluate the signatures. Test: `tests/test_smd.py::test_the_certificate_and_manifest_rows_are_recovered`, `tests/test_smd.py::test_each_part_pairs_its_digest_and_signature` | - |
| `spswire.mnf` | `volt/docs/UPDATE-CONTAINER.md` §6 | `[part]` | Recover the base64 release XML a `.mnf` carries: the longest base64 run whose decode is an XML document. A file with no such run is an error. The binary PN→(size,SHA-256) index is the open row below. Test: `tests/test_mnf.py::test_the_release_xml_is_decoded_from_the_blob`, `tests/test_mnf.py::test_a_file_with_no_xml_blob_is_an_error` | - |
| `spswire.mnf.index` | `volt/docs/UPDATE-CONTAINER.md` §6 (binary PN index) | `[ ]` | Parse the binary part-number → (size, SHA-256) index at the head of a `.mnf`, with the `.smd` row zeroed. The record widths are not pinned by the write-up and need a sample `.mnf`; none is vendored. Test: `tests/test_mnf_index.py::test_the_part_number_index_is_parsed` (to be written) | - |
| `spswire.container` | `volt/docs/UPDATE-CONTAINER.md` §2 (`container.iso`) | `[ ]` | Map the known container paths (`security/cacert.pem`, `firmware/v850/*/master.dnl`, `md5/*`, the Lua install scripts) to their bytes by delegating the ISO 9660 walk to the sibling `iso9660` reader. No second ISO parser is kept here. Test: `tests/test_container.py::test_a_known_container_path_returns_its_bytes` (to be written) | - |
| `spswire.dnl` | `volt/docs/V850-FIRMWARE.md` §2 (`$FLW_WRITER` framing) | `[ ]` | Parse the Renesas `$FLW_WRITER` download stream of `master.dnl` — the `8X nn` record headers, the little-endian target addresses, the `0x55` fill and the CRC16 trailers — into a byte-exact section map. Flagged in the write-up; needs a sample to fix the record semantics. Test: `tests/test_dnl.py::test_the_flw_writer_records_are_framed` (to be written) | - |
