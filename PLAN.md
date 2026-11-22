# spswire

A read-only reader for the firmware-container formats a GM GMG3 service-programming update set is
built from.

**What it is.** A module-reprogramming package for a GMG3 / ADIT-platform GM head unit — pulled
through a TDS (Techline) subscription and applied by the Service Programming System (SPS) — is a
set of container formats: a signed `.mnf` manifest, a `.smd` signature bundle, a `container.iso`
installer, and i.MX6 boot images whose kernel is compressed with a GM-custom `0x4d` LZ77 codec,
plus the V850 companion-MCU `master.dnl`. Anyone with a TDS subscription who downloads an SPS
update for one of these modules holds the same formats. `spswire` parses those bytes and returns
structure. It is the reusable format layer a tool like `spskit` can build on.

**What the text is.** Each format is documented from public references and from analysis of SPS
update packages. The public references — the U-Boot legacy image header, the i.MX6 HAB Image
Vector Table, PKCS#1 v1.5 `DigestInfo`, ISO/IEC 9660 — are named in `docs/sources.md`; normative
wording is read through the `primarysource` CLIs, never from memory. A format is implemented only
where its byte layout is fixed; where a format's record widths are not pinned, it is a ROADMAP row,
not a guessed parser. **No firmware is vendored here.** The test buffers are synthesised field by
field from the documented layouts.

**What it does.**

- Decode a GM `comp=0x4d` uImage LZ77 buffer (the 8-byte `[out_size][comp_size]` header and the
  3-byte `literal | length | distance` tokens) and return the plaintext.
- Parse a U-Boot legacy image header (magic `0x27051956`) and report its load/entry addresses and
  its compression type, flagging the `0x4d` GM codec.
- Parse an i.MX6 Image Vector Table and report whether a CSF pointer is present or resolves to
  end-of-file (an image built with a CSF slot but carrying no CSF block).
- Split a GM `.smd` PEM signature bundle into its signer certificate, the manifest digest and
  signature, and the per-part-number digest/signature rows. It is not PKCS#7 and this reader does
  not evaluate the signatures.
- Recover the base64 release XML carried in a `.mnf` manifest.
- Decompress a `uImage` to its kernel end to end (the header's codec drives it: `0x4d` LZ77 or an
  uncompressed image), composing the `uimage` and `lz77` readers.
- Map the known `container.iso` paths (the CA trust anchor, the V850 `master.dnl` and its `*.crc`
  sidecars) to their bytes, delegating the ISO 9660 walk to an injected reader such as
  `iso9660.Volume` so no ISO parser and no dependency on one lives here.

**What it is not.** `spswire` reads bytes. It does not flash, write, program, sign, verify a
signature, or open a device, a serial port, a socket, or a vehicle. It is not `spskit` (which
builds an SPS programming-data body) and not `voltkit` (the ELM327 OBD read client); it is the
format layer beneath that family. It does not walk the `container.iso` volume — that is an ISO 9660
reader, and a separate ISO 9660 project returns a member's bytes; `spswire` maps the known
container paths through that reader rather than keep a second ISO parser. The V850 `master.dnl`
`$FLW_WRITER` framing and the binary `.mnf` part-number index are ROADMAP rows that need a sample
to fix the record layout, and no sample is vendored. Writing a container, re-signing a manifest,
and modifying a trust anchor are out of scope.

**Name.** `spswire`, checked with `projecthub shells names --index` against a 936,266-name
snapshot: both PyPI signals are 404 (free). `gmfwire`, `gmgwire` and `uimgwire` are also free and
were the alternatives; `spswire` was chosen because the formats are what the Service Programming
System delivers, which is the audience (a TDS subscriber) and ties it to the `spskit` /
`techlinekit` family without colliding with any of them. No Rust twin is opened.

**Trigger for code.** Met. The `0x4d` LZ77 codec, the U-Boot legacy header, the i.MX6 IVT and the
`.smd` bundle each have a fixed byte layout, so the readers and their tests exist now. The binary
`.mnf` index, the `container.iso` path map, and the V850 `master.dnl` framing stay open until a
sample pins them.

The library is `src/spswire`. Dependencies stay empty and there is no build backend.

From this directory, with `PYTHONDONTWRITEBYTECODE=1`:

    python -m pytest -q
    python -m ruff check src tests
    python -m ruff format --check src tests
    python -m mypy src tests
