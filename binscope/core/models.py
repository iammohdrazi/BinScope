from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Section:
    name: str
    addr: int
    size: int
    type: str


@dataclass
class Symbol:
    name: str
    addr: int
    size: int
    type: str
    binding: Optional[str] = None


@dataclass
class ImportEntry:
    name: str
    addr: Optional[int] = None


@dataclass
class ExportEntry:
    name: str
    addr: Optional[int] = None


@dataclass
class BinaryInfo:
    filepath: str
    format: str  # ELF or PE
    arch: str
    entrypoint: int
    sections: List[Section] = field(default_factory=list)
    symbols: List[Symbol] = field(default_factory=list)
    imports: List[ImportEntry] = field(default_factory=list)
    exports: List[ExportEntry] = field(default_factory=list)
