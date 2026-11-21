# Scope

`spswire` is a read-only reader for the firmware-container formats of a GM GMG3 service-programming
update set. It parses bytes and returns structure.

- Do not flash, write, program, re-sign, or verify. There is no write path, no signature check, no
  network, and no device, serial-port, socket or vehicle I/O. The `.smd` reader splits the bundle;
  it does not evaluate a certificate chain or an RSA signature.
- Do not vendor GM firmware. No `.mnf`, `.smd`, `container.iso`, `uImage`, `master.dnl`, `.bin` or
  any firmware byte goes into this repository. Test buffers are built field by field from the
  documented layouts in `volt/docs` (see `docs/sources.md`). Treat `volt` as read-only.
- Do not guess a byte layout. Implement a format only where the `volt` write-up pins it
  byte-for-byte. The binary `.mnf` index and the V850 `master.dnl` `$FLW_WRITER` framing are
  described but not pinned there; they stay `[ ]` ROADMAP rows until a sample fixes the record
  widths. Flag offsets the way the write-up does.
- Do not keep a second ISO 9660 reader. `container.iso` is an ISO 9660 volume; the sibling
  `iso9660` project returns a member's bytes. The container row maps known paths through it.
- Do not add a dependency or a build backend. The library is pure standard library; `dependencies`
  stays `[]` and there is no `[build-system]`. A new dependency needs a reason in the commit
  message. `test_roadmap.py` enforces the empty-dependency rule.
- Do not copy a VIN, a key, or any vehicle secret into the tree.
- A ROADMAP row is `[ ]` until its code exists, and its named test must not exist yet; a `[ok]` or
  `[part]` row names a test that does. `test_roadmap.py` enforces this.

From this directory, with `PYTHONDONTWRITEBYTECODE=1`, all four gates pass before a change is done:

    python -m ruff check src tests
    python -m ruff format --check src tests
    python -m mypy src tests
    python -m pytest -q
