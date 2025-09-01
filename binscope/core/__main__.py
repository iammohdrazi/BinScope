import sys
from .elf_parser import parse_elf
from .pe_parser import parse_pe
from .utils import detect_os


def main():
    if len(sys.argv) < 2:
        print("Usage: python -m binscope.core <binary-file>")
        sys.exit(1)

    filepath = sys.argv[1]

    try:
        if filepath.endswith(".exe") or filepath.endswith(".dll"):
            info = parse_pe(filepath)
        else:
            info = parse_elf(filepath)

        print(f"Format: {info.format}")
        print(f"Arch: {info.arch}")
        print(f"Entrypoint: {hex(info.entrypoint)}")
        print(f"Sections: {len(info.sections)}")
        print(f"Symbols: {len(info.symbols)}")
        print(f"Imports: {len(info.imports)}")
        print(f"Exports: {len(info.exports)}")

    except Exception as e:
        print(f"[!] Error parsing {filepath}: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
