# spswire

A read-only reader for the firmware-container formats a GM GMG3 service-programming update set
is built from.

**What it is.** A module-reprogramming package for a GMG3 / ADIT-platform GM head unit — pulled
through a TDS (Techline) subscription and applied by the Service Programming System (SPS) — is a
set of standard container formats: a signed `.mnf` manifest, a `.smd` signature bundle, an
`container.iso` installer, and i.MX6 boot images whose kernel is compressed with a GM-custom
`0x4d` LZ77 codec, plus the V850 companion-MCU `master.dnl`. Anyone with a TDS subscription who
downloads an SPS update for one of these modules holds the same formats. `spswire` parses those
bytes and returns structure. The vehicle-specific findings — which offsets a given dump carries,
what a particular NOR trust slot holds — stay in the `volt` research write-up; this library is the
reusable format layer under that work, and the format layer a tool like `spskit` can build on.

**What the text is.** The byte-level authority is the `volt` reverse-engineering of
`GMG3G_LINUX_15.2B033` (an authorized assessment of a unit the owner owns). `docs/sources.md`
records the exact documents and sections. Each format this reader implements is one the write-up
pins byte-for-byte from the shipped images and a Ghidra decompilation; where the write-up only
describes a format's shape without fixing its record widths, that format is a ROADMAP row, not a
guessed parser. The public references — the U-Boot legacy image header, the i.MX6 HAB Image Vector
Table, PKCS#1 v1.5 `DigestInfo` — are named in `docs/sources.md`; normative wording is read through
the `primarysource` CLIs, never from memory. **No GM firmware bytes are vendored here.** The test
buffers are synthesised field by field from the documented layouts.

**What it does.**

- Decode a GM `comp=0x4d` uImage LZ77 buffer (the 8-byte `[out_size][comp_size]` header and the
  3-byte `literal | length | distance` tokens) and return the plaintext.
- Parse a U-Boot legacy image header (magic `0x27051956`) and report its load/entry addresses and
  its compression type, flagging the `0x4d` GM codec.
- Parse an i.MX6 Image Vector Table and report the HAB-open shape (a CSF pointer that resolves to
  end-of-file — "built for signing, shipped unsigned").
- Split a GM `.smd` PEM signature bundle into its signer certificate, the manifest digest and
  signature, and the per-part-number digest/signature rows. It is not PKCS#7 and this reader does
  not evaluate the signatures.
- Recover the base64 release XML carried in a `.mnf` manifest.

**What it is not.** `spswire` reads bytes. It does not flash, write, program, sign, verify a
signature, or open a device, a serial port, a socket, or a vehicle. It is not `spskit` (which
builds an SPS programming-data body) and not `voltkit` (the ELM327 OBD read client); it is the
format layer beneath that family. It does not walk the `container.iso` volume — that is an ISO 9660
reader, and the sibling `iso9660` project already returns a member's bytes; `spswire` will map the
known container paths through that reader rather than keep a second ISO parser. The V850
`master.dnl` `$FLW_WRITER` framing and the binary `.mnf` part-number index are documented in the
write-up but not byte-pinned there; they are ROADMAP rows that need a sample to fix the record
layout, and no sample is vendored. Writing a container, re-signing a manifest, and defeating a
trust anchor are out of scope; the research write-up records those as findings, not as tooling.

**Name.** `spswire`, checked with `projecthub shells names --index` against a 936,266-name
snapshot: both PyPI signals are 404 (free). `gmfwire`, `gmgwire` and `uimgwire` are also free and
were the alternatives; `spswire` was chosen because the formats are what the Service Programming
System delivers, which is the audience (a TDS subscriber) and ties it to the `spskit` / `techlinekit`
family without colliding with any of them. No Rust twin is opened.

**Trigger for code.** Met. The `0x4d` LZ77 codec, the U-Boot legacy header, the i.MX6 IVT and the
`.smd` bundle are each pinned byte-for-byte in the write-up (`docs/sources.md`), so the readers and
their tests exist now. The binary `.mnf` index, the `container.iso` path map, and the V850
`master.dnl` framing stay open until a sample pins them.

The library is `src/spswire`. Dependencies stay empty and there is no build backend.

From this directory, with `PYTHONDONTWRITEBYTECODE=1`:

    python -m pytest -q
    python -m ruff check src tests
    python -m ruff format --check src tests
    python -m mypy src tests
