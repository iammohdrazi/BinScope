import lief
from .models import BinaryInfo, Section, Symbol, ImportEntry, ExportEntry


def parse_elf(filepath: str) -> BinaryInfo:
    """Parse an ELF binary using LIEF and return a BinaryInfo object."""
    binary = lief.parse(filepath)
    info = BinaryInfo(
        filepath=filepath,
        format="ELF",
        arch=str(binary.header.machine_type),
        entrypoint=binary.entrypoint
    )

    # Sections
    for sec in binary.sections:
        info.sections.append(
            Section(
                name=sec.name,
                addr=sec.virtual_address,
                size=sec.size,
                type=str(sec.type)
            )
        )

    # Symbols
    for sym in binary.symbols:
        info.symbols.append(
            Symbol(
                name=sym.name,
                addr=sym.value,
                size=sym.size,
                type=str(sym.type),
                binding=str(sym.binding)
            )
        )

    # Imports
    for imp in binary.imports:
        for entry in imp.entries:
            info.imports.append(
                ImportEntry(
                    name=entry.name,
                    addr=entry.iat_value
                )
            )

    # Exports
    for exp in binary.exported_functions:
        info.exports.append(
            ExportEntry(
                name=exp.name,
                addr=exp.address
            )
        )

    return info
