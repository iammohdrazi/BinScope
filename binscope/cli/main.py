import argparse
import json
from binscope.core.elf_parser import parse_elf
from binscope.core.pe_parser import parse_pe


def main():
    parser = argparse.ArgumentParser(
        prog="binscope",
        description="Binscope - ELF/PE Binary Analysis Tool"
    )
    parser.add_argument("binary", help="Path to ELF or PE binary file")
    parser.add_argument(
        "-j", "--json", action="store_true",
        help="Output results in JSON format"
    )
    args = parser.parse_args()

    if args.binary.endswith((".exe", ".dll")):
        info = parse_pe(args.binary)
    else:
        info = parse_elf(args.binary)

    if args.json:
        print(json.dumps(info.to_dict(), indent=2))
    else:
        print(f"File: {info.filepath}")
        print(f"Format: {info.format}")
        print(f"Architecture: {info.arch}")
        print(f"Entrypoint: {hex(info.entrypoint)}")
        print("\nSections:")
        for s in info.sections:
            print(f"  - {s.name} @ {hex(s.addr)} size {s.size} type {s.type}")
        print("\nImports:")
        for i in info.imports:
            print(f"  - {i.name} (0x{i.addr:x})")
        print("\nExports:")
        for e in info.exports:
            print(f"  - {e.name} (0x{e.addr:x})")


if __name__ == "__main__":
    main()
