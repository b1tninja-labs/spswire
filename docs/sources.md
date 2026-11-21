# Sources

`spswire` reads the firmware-container formats used by a GM GMG3 / ADIT-platform
service-programming (SPS) update set. The formats are documented from public references and from
the author's own analysis of update packages. **No firmware is vendored into this repository.**
The sample buffers in `tests/` are built field by field from the documented layouts, not taken
from any shipped image.

## Public format references

- U-Boot *legacy image* header (`image_header_t`, magic `0x27051956`), as written by `mkimage` —
  the 64-byte big-endian header `spswire.uimage` parses.
- NXP i.MX 6 reference manual — the High Assurance Boot (HAB) Image Vector Table layout that
  `spswire.ivt` parses (header tag `0xd1`, length `0x0020`).
- The GM `comp=0x4d` uImage LZ77 codec: an 8-byte `[out_size][comp_size]` little-endian header
  followed by 3-byte `literal | length | distance` tokens with overlap-capable back-references.
- RSA PKCS#1 v1.5 `DigestInfo` prefixes, relevant to the V850 verifier (a later ROADMAP row). For
  normative text use the `primarysource` CLIs rather than quoting from memory.
- ISO/IEC 9660 for the `container.iso` volume; the `container` row delegates the volume walk to a
  separate ISO 9660 reader rather than keep a second parser here.
- GM OBD / diagnostic parameter references are available through the `primarysource` `gm_*` tools;
  they are not needed by the format readers here.
