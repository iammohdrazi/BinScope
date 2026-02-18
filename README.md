# BinScope

BinScope parses ELF (Linux) and PE (Windows) binaries to extract:
- Sections
- Symbols (ELF: dynsym/symtab; PE: export names, limited COFF symbols)
- Imports & Exports
- Optional tiny disassembly helper (Capstone)

## Features

- **Cross-platform binary analysis**: Supports both ELF (Linux) and PE (Windows) formats
- **Section extraction**: Analyze binary sections and their properties
- **Symbol parsing**: Extract dynamic and static symbols from binaries
- **Import/Export analysis**: Identify imported functions and exported symbols
- **Disassembly support**: Optional Capstone-based disassembly for deeper analysis

## Installation

### Development Install
```bash
python -m venv .venv
source .venv/bin/activate      # Windows: .venv\Scripts\activate
pip install -e .
# or: pip install -r requirements.txt
```

### Production Install
```bash
pip install binscope
```

## Usage

### Basic Usage
```python
from binscope import BinaryAnalyzer

# Analyze a binary
analyzer = BinaryAnalyzer("path/to/binary")
result = analyzer.analyze()

# Access sections
for section in result.sections:
    print(f"Section: {section.name}, Size: {section.size}")

# Access symbols
for symbol in result.symbols:
    print(f"Symbol: {symbol.name}, Type: {symbol.type}")
```

### Command Line Interface
```bash
binscope analyze /path/to/binary
binscope --help
```

## Requirements

- Python 3.7+
- pefile (for PE binaries)
- pyelftools (for ELF binaries)
- capstone (optional, for disassembly)

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- [pefile](https://github.com/erocarrera/pefile) for PE parsing
- [pyelftools](https://github.com/eliben/pyelftools) for ELF parsing
- [Capstone](https://www.capstone-engine.org/) for disassembly framework
