"""The GM ``comp=0x4d`` uImage LZ77 codec, decode side.

GMG3 head-unit kernels ship as a U-Boot legacy image whose compression byte is
``0x4d`` (``'M'``) -- a custom type stock U-Boot does not define. The bootloader
``u-boot.bin.generic`` carries the codec (reversed as ``FUN_1782a130`` at text base
``0x17800000``) and the error string ``LZ77: uncompress or overwrite error %d``.

Stream shape, taken from that decompilation (``volt/docs/BOOT-PARTITION.md`` section 3):

* An 8-byte little-endian header ``[u32 out_size][u32 comp_size]``. ``out_size`` is the
  size of the decoded output; ``comp_size`` is the length of the token body. The caller
  caps the output at ``0x800000`` (8 MiB) and rejects a buffer whose body length is not
  within 10 bytes of ``comp_size``.
* The body is a flat stream of 3-byte little-endian tokens ``T``, each both a
  back-reference and a literal::

      literal  = T & 0xFF           bits 0-7
      length   = (T >> 8) & 0xF     bits 8-11, 0-15
      distance = (T >> 12) & 0xFFF  bits 12-23, 0-4095

  Per token: if ``distance != 0``, copy ``length`` bytes one at a time from
  ``out[pos - distance]`` (overlap is allowed, as in classic LZ77), advancing ``pos`` by
  ``length``; then always emit the one ``literal`` byte and advance ``pos`` by one.

Nothing here writes a token stream: this is a reader for shipped firmware, not a packer.
"""

from __future__ import annotations

from typing import Final

HEADER_SIZE: Final = 8
MAX_OUTPUT: Final = 0x800000
TOKEN_SIZE: Final = 3
MAX_SLACK: Final = 10


class LZ77Error(ValueError):
    """The buffer is not a well-formed GM ``0x4d`` LZ77 stream."""


def _header(data: bytes) -> tuple[int, int]:
    if len(data) < HEADER_SIZE:
        raise LZ77Error("buffer is shorter than the 8-byte header")
    out_size = int.from_bytes(data[0:4], "little")
    comp_size = int.from_bytes(data[4:8], "little")
    return out_size, comp_size


def declared_sizes(data: bytes) -> tuple[int, int]:
    """Return the header's ``(out_size, comp_size)`` without decoding the body."""
    return _header(data)


def decompress(data: bytes) -> bytes:
    """Decode a GM ``0x4d`` LZ77 buffer and return the recovered bytes.

    ``data`` is the whole codec buffer: the 8-byte header followed by the token body.
    The length of the result equals the header's ``out_size``. A buffer whose declared
    sizes, output cap or back-references are inconsistent raises :class:`LZ77Error`.
    """
    out_size, comp_size = _header(data)
    body_len = len(data) - HEADER_SIZE
    slack = body_len - comp_size
    if slack < 0 or slack >= MAX_SLACK:
        raise LZ77Error(f"comp_size {comp_size} is not within {MAX_SLACK} bytes of {body_len}")
    if out_size > MAX_OUTPUT:
        raise LZ77Error(f"out_size {out_size} exceeds the {MAX_OUTPUT}-byte cap")

    out = bytearray()
    body = memoryview(data)[HEADER_SIZE : HEADER_SIZE + comp_size]
    for start in range(0, comp_size - comp_size % TOKEN_SIZE, TOKEN_SIZE):
        token = int.from_bytes(body[start : start + TOKEN_SIZE], "little")
        literal = token & 0xFF
        length = (token >> 8) & 0xF
        distance = (token >> 12) & 0xFFF
        if distance:
            if distance > len(out):
                raise LZ77Error(f"back-reference distance {distance} precedes the output start")
            for _ in range(length):
                out.append(out[len(out) - distance])
        out.append(literal)

    if len(out) != out_size:
        raise LZ77Error(f"decoded {len(out)} bytes, header declared {out_size}")
    return bytes(out)
