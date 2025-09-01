import lief
from .models import BinaryInfo, Section, Symbol, ImportEntry, ExportEntry


def parse_pe(filepath: str) -> BinaryInfo:
    """Parse a PE binary using LIEF and return a BinaryInfo object."""
    binary = lief.parse(filepath)
    info = BinaryInfo(
        filepath=filepath,
        format="PE",
        arch=str(binary.header.machine),
        entrypoint=binary.optional_header.addressof_entrypoint
    )

    # Sections
    for sec in binary.sections:
        info.sections.append(
            Section(
                name=sec.name,
                addr=sec.virtual_address,
                size=sec.size,
                type="N/A"
            )
        )

    # Symbols (PE doesn’t always store them, may be limited)
    for sym in binary.symbols:
        info.symbols.append(
            Symbol(
                name=sym.name,
                addr=sym.value,
                size=sym.section_number,
                type="N/A"
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
