"""A read-only ``python -m spswire`` dump CLI over the container-format readers.

Each subcommand reads a file's bytes and prints the structure one field per line -- a
``uImage`` header, a ``.mnf`` binary index (or its release XML), an i.MX IVT, a ``.smd``
bundle, or a ``master.dnl`` ``$FLW_WRITER`` summary. ``container`` takes no file: it prints the
documented ``container.iso`` path layout, which is spswire's own data and needs no ISO reader.
``detect`` names the format of an unlabelled file (and exits 1 when nothing matches). The dump
subcommands take ``--json`` for a machine-readable object instead of the aligned text. ``extract``
emits derived bytes -- a decompressed kernel, or the ``.smd`` signer certificate (raw DER,
unmodified) -- to stdout or a ``-o`` file.

The library stays read-only: ``extract`` is the CLI's only byte-producing path, and even it never
flashes a device, re-signs, or re-encodes its input. The CLI adds no dependency: it is pure
standard library over the library in this package.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from spswire import container, detect, dnl, ivt, kernel, mnf, smd, uimage


def _read(path: str) -> bytes:
    with open(path, "rb") as handle:
        return handle.read()


def _emit_json(payload: object) -> int:
    print(json.dumps(payload, indent=2))
    return 0


def _cmd_uimage(args: argparse.Namespace) -> int:
    header = uimage.parse(_read(args.file))
    if args.json:
        return _emit_json(
            {
                "name": header.name,
                "size": header.size,
                "load": header.load,
                "entry": header.entry,
                "os": header.os_name,
                "arch": header.arch_name,
                "type": header.type_name,
                "comp": header.comp_name,
                "gm_lz77": header.is_gm_lz77,
            }
        )
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
    entries = mnf.index(data)
    if args.json:
        return _emit_json(
            [
                {
                    "part_number": entry.part_number,
                    "size_blocks": entry.size_blocks,
                    "nominal_size": entry.nominal_size,
                    "sha256": entry.sha256.hex(),
                    "zeroed": entry.zeroed,
                }
                for entry in entries
            ]
        )
    for entry in entries:
        if entry.zeroed:
            print(f"{entry.part_number}  (signing .smd row)")
        else:
            print(f"{entry.part_number}  {entry.nominal_size:>12} B  {entry.sha256.hex()}")
    return 0


def _cmd_ivt(args: argparse.Namespace) -> int:
    data = _read(args.file)
    table = ivt.parse(data)
    csf = table.csf_file_offset()
    if args.json:
        return _emit_json(
            {
                "version": table.version,
                "entry": table.entry,
                "self": table.self_ptr,
                "dcd": table.dcd if table.has_dcd else None,
                "csf": csf,
                "hab_open": table.is_hab_open(len(data)),
            }
        )
    print(f"version   0x{table.version:02x}")
    print(f"entry     0x{table.entry:08x}")
    print(f"self      0x{table.self_ptr:08x}")
    print(f"dcd       {'0x%08x' % table.dcd if table.has_dcd else 'none'}")
    print(f"csf       {'0x%x' % csf if csf is not None else 'none'}")
    print(f"hab-open  {'yes' if table.is_hab_open(len(data)) else 'no'}")
    return 0


def _cmd_smd(args: argparse.Namespace) -> int:
    bundle = smd.parse(_read(args.file))
    cert = bundle.signer_certificate
    if args.json:
        return _emit_json(
            {
                "signer_bytes": len(cert) if cert is not None else None,
                "manifest": {
                    "digest": bundle.manifest_digest is not None,
                    "signature": bundle.manifest_signature is not None,
                },
                "parts": {
                    pn: {
                        "digest": part.digest is not None,
                        "signature": part.signature is not None,
                    }
                    for pn, part in sorted(bundle.parts.items())
                },
            }
        )
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
    try:
        marker: str | None = dnl.device_marker(data)
    except dnl.DNLError:
        marker = None
    headers = dnl.section_headers(data)
    verifier = dnl.rsa_verifier(data)
    if args.json:
        return _emit_json(
            {
                "flw_writer": dnl.has_flw_writer(data),
                "device": marker,
                "sections": [
                    {"offset": h.offset, "type": h.type, "index": h.index} for h in headers
                ],
                "rsa": {
                    "present": verifier.present,
                    "exponent_65537": verifier.public_exponent_f4,
                    "digests": list(verifier.digests),
                },
            }
        )
    print(f"flw-writer  {'yes' if dnl.has_flw_writer(data) else 'no'}")
    print(f"device      {marker if marker is not None else '(not found)'}")
    print(f"sections    {len(headers)}")
    for header in headers:
        print(f"  0x{header.offset:06x}  type=0x{header.type:02x} index=0x{header.index:02x}")
    digests = ", ".join(verifier.digests) if verifier.digests else "(none)"
    print(
        f"rsa         present={'yes' if verifier.present else 'no'} "
        f"exponent-65537={'yes' if verifier.public_exponent_f4 else 'no'}"
    )
    print(f"rsa-digests {digests}")
    return 0


def _cmd_container(args: argparse.Namespace) -> int:
    paths = [
        container.CACERT,
        container.CACERT_BOOT,
        container.PUBLIC_CODEKEY,
        container.TESEO_FLASHER,
        container.TESEO_APP,
    ]
    for variant in container.V850_VARIANTS:
        paths.append(container.v850_dnl_path(variant))
        paths.extend(
            container.v850_crc_path(section, variant) for section in container.V850_CRC_SECTIONS
        )
    paths.extend(container.MD5_MANIFESTS)
    if args.json:
        return _emit_json(paths)
    for path in paths:
        print(path)
    return 0


def _cmd_extract(args: argparse.Namespace) -> int:
    data = _read(args.file)
    if args.what == "kernel":
        out = kernel.decompress(data)
    else:  # "cert"
        cert = smd.parse(data).signer_certificate
        if cert is None:
            raise smd.SMDError("bundle carries no signer certificate")
        out = cert
    if args.output:
        with open(args.output, "wb") as handle:
            handle.write(out)
    else:
        sys.stdout.buffer.write(out)
    return 0


def _cmd_detect(args: argparse.Namespace) -> int:
    kind = detect.identify(_read(args.file))
    if kind is None:
        print("unknown")
        return 1
    print(kind)
    return 0


def _add_json(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--json", action="store_true", help="emit a JSON object instead of text")


def build_parser() -> argparse.ArgumentParser:
    """The ``python -m spswire`` argument parser: one subcommand per container format."""
    parser = argparse.ArgumentParser(
        prog="spswire",
        description="Read-only dump of GM GMG3 service-programming container formats.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_uimage = sub.add_parser("uimage", help="dump a U-Boot legacy image header")
    p_uimage.add_argument("file")
    _add_json(p_uimage)
    p_uimage.set_defaults(func=_cmd_uimage)

    p_mnf = sub.add_parser("mnf", help="dump a .mnf binary index, or its release XML")
    p_mnf.add_argument("file")
    p_mnf.add_argument("--xml", action="store_true", help="print the release XML instead")
    _add_json(p_mnf)
    p_mnf.set_defaults(func=_cmd_mnf)

    p_ivt = sub.add_parser("ivt", help="dump an i.MX6 Image Vector Table")
    p_ivt.add_argument("file")
    _add_json(p_ivt)
    p_ivt.set_defaults(func=_cmd_ivt)

    p_smd = sub.add_parser("smd", help="dump a .smd signature bundle's structure")
    p_smd.add_argument("file")
    _add_json(p_smd)
    p_smd.set_defaults(func=_cmd_smd)

    p_dnl = sub.add_parser("dnl", help="dump a V850 master.dnl $FLW_WRITER summary")
    p_dnl.add_argument("file")
    _add_json(p_dnl)
    p_dnl.set_defaults(func=_cmd_dnl)

    p_container = sub.add_parser("container", help="print the known container.iso path layout")
    _add_json(p_container)
    p_container.set_defaults(func=_cmd_container)

    p_detect = sub.add_parser(
        "detect", help="name the container format of a file (exit 1 if unknown)"
    )
    p_detect.add_argument("file")
    p_detect.set_defaults(func=_cmd_detect)

    p_extract = sub.add_parser(
        "extract", help="write derived bytes (a decompressed kernel or signer cert) to stdout"
    )
    p_extract.add_argument("what", choices=("kernel", "cert"))
    p_extract.add_argument("file")
    p_extract.add_argument("-o", "--output", help="write to this file instead of stdout")
    p_extract.set_defaults(func=_cmd_extract)

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
