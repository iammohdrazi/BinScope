# BinScope

BinScope parses ELF (Linux) and PE (Windows) binaries to extract:
- Sections
- Symbols (ELF: dynsym/symtab; PE: export names, limited COFF symbols)
- Imports & Exports
- Optional tiny disassembly helper (Capstone)

## Install (dev)
```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
# or: pip install -r requirements.txt
