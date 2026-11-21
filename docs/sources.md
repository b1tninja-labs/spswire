# Sources

`spswire` reads file formats recovered by the `volt` reverse-engineering of a GM GMG3 MY17
infotainment head unit (`GMG3G_LINUX_15.2B033`), which the owner owns and analysed under an
authorized security assessment. The byte-level authority for each format is that write-up. The
firmware itself is **not** vendored into this repository; the sample buffers in `tests/` are
built field by field from the documented layouts.

## The byte-level write-up (read-only, not vendored)

In the sibling `volt` repository's `docs/`:

- `BOOT-PARTITION.md` section 3 — the GM `comp=0x4d` LZ77 codec (the 8-byte
  `[out_size][comp_size]` header and the 3-byte `literal | length | distance` token), reversed
  from `u-boot.bin.generic` (`FUN_1782a130`, text base `0x17800000`).
- `BOOT-PARTITION.md` section 4 — the `uImage` U-Boot legacy header (`comp=0x4d`, load/entry
  `0x10008000`).
- `BOOT-PARTITION.md` section 2 — the i.MX6 Image Vector Table of `resetvect.bin` /
  `bootloader.bin` and the HAB-open (CSF-at-EOF) shape.
- `UPDATE-CONTAINER.md` section 6 — the `.mnf` manifest (binary PN index + base64 release XML).
- `UPDATE-CONTAINER.md` section 7 — the `.smd` PEM signature bundle (not PKCS#7).
- `UPDATE-SET.md`, `V850-FIRMWARE.md` — the whole update set and the V850 `master.dnl`
  `$FLW_WRITER` framing (a ROADMAP row, not yet read here).

## Public format references

- U-Boot *legacy image* header (`image_header_t`, magic `0x27051956`), as written by `mkimage`.
- NXP i.MX 6 reference manual — the High Assurance Boot Image Vector Table layout.
- RSA PKCS#1 v1.5 `DigestInfo` prefixes (for the V850 verifier, a later ROADMAP row). For the
  normative text use the `primarysource` CLIs rather than quoting from memory.
- GM OBD / diagnostic parameter references are available through the `primarysource` `gm_*`
  tools; they are not needed by the format readers here.
