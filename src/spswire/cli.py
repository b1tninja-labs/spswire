"""A read-only ``python -m spswire`` dump CLI over the container-format readers.

Each subcommand reads a file's bytes and prints the structure one field per line -- a
``uImage`` header, a ``.mnf`` binary index (or its release XML), an i.MX IVT, a ``.smd``
bundle, or a ``master.dnl`` ``$FLW_WRITER`` summary. ``container`` takes no file: it prints the
documented ``container.iso`` path layout, which is spswire's own data and needs no ISO reader.
``detect`` names the format of an unlabelled file (and exits 1 when nothing matches).

The CLI only reads and reports. It never writes, flashes, verifies or re-encodes, and it adds no
dependency: it is pure standard library over the library in this package.
"""

from __future__ import annotations

import argparse
from collections.abc import Sequence

from spswire import container, detect, dnl, ivt, mnf, smd, uimage


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _cmd_uimage(args: argparse.Namespace) -> int:
    header = uimage.parse(_read(args.file))
    print(f"name     {header.name}")
    print(f"size     {header.size}")
    print(f"load     0x{header.load:08x}")
    print(f"entry    0x{header.entry:08x}")
    print(f"os       {header.os_name}")
    print(f"arch     {header.arch_name}")
    print(f"type     {header.type_name}")
    print(f"comp     {header.comp_name}")
    print(f"gm-lz77  {'yes' if header.is_gm_lz77 else 'no'}")
    return 0


def _cmd_mnf(args: argparse.Namespace) -> int:
    data = _read(args.file)
    if args.xml:
        print(mnf.release_xml(data).decode("utf-8", "replace"))
        return 0
    for entry in mnf.index(data):
        if entry.zeroed:
            print(f"{entry.part_number}  (signing .smd row)")
        else:
            print(f"{entry.part_number}  {entry.nominal_size:>12} B  {entry.sha256.hex()}")
    return 0


def _cmd_ivt(args: argparse.Namespace) -> int:
    data = _read(args.file)
    table = ivt.parse(data)
    print(f"version   0x{table.version:02x}")
    print(f"entry     0x{table.entry:08x}")
    print(f"self      0x{table.self_ptr:08x}")
    print(f"dcd       {'0x%08x' % table.dcd if table.has_dcd else 'none'}")
    csf = table.csf_file_offset()
    print(f"csf       {'0x%x' % csf if csf is not None else 'none'}")
    print(f"hab-open  {'yes' if table.is_hab_open(len(data)) else 'no'}")
    return 0


def _cmd_smd(args: argparse.Namespace) -> int:
    bundle = smd.parse(_read(args.file))
    cert = bundle.signer_certificate
    print(f"signer    {len(cert)} B" if cert is not None else "signer    (none)")
    print(
        f"manifest  digest={'yes' if bundle.manifest_digest else 'no'} "
        f"signature={'yes' if bundle.manifest_signature else 'no'}"
    )
    for pn in sorted(bundle.parts):
        part = bundle.parts[pn]
        print(
            f"{pn}  digest={'yes' if part.digest else 'no'} "
            f"signature={'yes' if part.signature else 'no'}"
        )
    return 0


def _cmd_dnl(args: argparse.Namespace) -> int:
    data = _read(args.file)
    print(f"flw-writer  {'yes' if dnl.has_flw_writer(data) else 'no'}")
    try:
        print(f"device      {dnl.device_marker(data)}")
    except dnl.DNLError:
        print("device      (not found)")
    headers = dnl.section_headers(data)
    print(f"sections    {len(headers)}")
    for header in headers:
        print(f"  0x{header.offset:06x}  type=0x{header.type:02x} index=0x{header.index:02x}")
    verifier = dnl.rsa_verifier(data)
    digests = ", ".join(verifier.digests) if verifier.digests else "(none)"
    print(
        f"rsa         present={'yes' if verifier.present else 'no'} "
        f"exponent-65537={'yes' if verifier.public_exponent_f4 else 'no'}"
    )
    print(f"rsa-digests {digests}")
    return 0


def _cmd_container(args: argparse.Namespace) -> int:
    print(f"{container.CACERT}")
    print(f"{container.CACERT_BOOT}")
    print(f"{container.PUBLIC_CODEKEY}")
    print(f"{container.TESEO_FLASHER}")
    print(f"{container.TESEO_APP}")
    for variant in container.V850_VARIANTS:
        print(container.v850_dnl_path(variant))
        for section in container.V850_CRC_SECTIONS:
            print(container.v850_crc_path(section, variant))
    for path in container.MD5_MANIFESTS:
        print(path)
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    kind = detect.identify(_read(args.file))
    if kind is None:
        print("unknown")
        return 1
    print(kind)
    return 0


def build_parser() -> argparse.ArgumentParser:
    """The ``python -m spswire`` argument parser: one subcommand per container format."""
    parser = argparse.ArgumentParser(
        prog="spswire",
        description="Read-only dump of GM GMG3 service-programming container formats.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_uimage = sub.add_parser("uimage", help="dump a U-Boot legacy image header")
    p_uimage.add_argument("file")
    p_uimage.set_defaults(func=_cmd_uimage)

    p_mnf = sub.add_parser("mnf", help="dump a .mnf binary index, or its release XML")
    p_mnf.add_argument("file")
    p_mnf.add_argument("--xml", action="store_true", help="print the release XML instead")
    p_mnf.set_defaults(func=_cmd_mnf)

    p_ivt = sub.add_parser("ivt", help="dump an i.MX6 Image Vector Table")
    p_ivt.add_argument("file")
    p_ivt.set_defaults(func=_cmd_ivt)

    p_smd = sub.add_parser("smd", help="dump a .smd signature bundle's structure")
    p_smd.add_argument("file")
    p_smd.set_defaults(func=_cmd_smd)

    p_dnl = sub.add_parser("dnl", help="dump a V850 master.dnl $FLW_WRITER summary")
    p_dnl.add_argument("file")
    p_dnl.set_defaults(func=_cmd_dnl)

    p_container = sub.add_parser("container", help="print the known container.iso path layout")
    p_container.set_defaults(func=_cmd_container)

    p_detect = sub.add_parser(
        "detect", help="name the container format of a file (exit 1 if unknown)"
    )
    p_detect.add_argument("file")
    p_detect.set_defaults(func=_cmd_detect)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse ``argv`` and run a subcommand; a reader error prints to stderr and returns 2."""
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        exit_code: int = args.func(args)
    except (OSError, ValueError) as error:
        parser.exit(2, f"spswire: {error}\n")
    return exit_code
