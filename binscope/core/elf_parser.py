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

    # Symbols (both imports/exports come from here)
    for sym in binary.symbols:
        symbol_entry = Symbol(
            name=sym.name,
            addr=sym.value,
            size=sym.size,
            type=str(sym.type),
            binding=str(sym.binding)
        )
        info.symbols.append(symbol_entry)

        # Separate imports and exports
        if sym.name:  # only process named symbols
            if sym.shndx == lief.ELF.SYMBOL_SECTION_INDEX.UNDEF:
                # Undefined symbol → import
                info.imports.append(
                    ImportEntry(
                        name=sym.name,
                        addr=0  # imports don’t have a real address
                    )
                )
            else:
                # Defined global function → export
                if sym.type == lief.ELF.SYMBOL_TYPES.FUNC:
                    info.exports.append(
                        ExportEntry(
                            name=sym.name,
                            addr=sym.value
                        )
                    )

    return info
