import sys
import os
import pefile
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QFileDialog,
    QVBoxLayout, QHBoxLayout, QWidget, QLabel,
    QTextEdit, QAction, QTreeWidget, QTreeWidgetItem,
    QMenu, QLineEdit, QPushButton, QTabWidget, QStatusBar
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QColor

# try:
#     import cxxfilt  # for C++ demangling
#     demangle_available = True
# except ImportError:
#     demangle_available = False


class BinScopeGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BinScope - PE/DLL Analyzer")
        self.setGeometry(100, 100, 1200, 750)

        # Enable drag and drop
        self.setAcceptDrops(True)

        # Internal variables
        self.current_file_path = ""
        self.details_items = []  # must be initialized before toggle_details

        self.central_layout = QVBoxLayout()

        # File info label
        self.file_label = QLabel("No file loaded")
        self.central_layout.addWidget(self.file_label)

        # Search bar
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search exports/imports/sections...")
        self.search_input.textChanged.connect(self.filter_tree)
        search_layout.addWidget(QLabel("Search:"))
        search_layout.addWidget(self.search_input)

        # Toggle details button
        self.toggle_details_btn = QPushButton("Toggle Optional Header/Data Directories")
        self.toggle_details_btn.setCheckable(True)
        self.toggle_details_btn.setChecked(False)  # unchecked by default
        self.toggle_details_btn.clicked.connect(self.toggle_details)
        search_layout.addWidget(self.toggle_details_btn)

        self.central_layout.addLayout(search_layout)

        # Prevent search box auto-focus
        self.search_input.clearFocus()
        self.setFocus()

        # Tree widget
        self.tree_widget = QTreeWidget()
        self.tree_widget.setHeaderLabels(["Category", "Details"])
        self.tree_widget.setSelectionBehavior(QTreeWidget.SelectItems)
        self.tree_widget.setSelectionMode(QTreeWidget.SingleSelection)
        self.tree_widget.setContextMenuPolicy(Qt.CustomContextMenu)
        self.tree_widget.customContextMenuRequested.connect(self.show_context_menu)
        self.central_layout.addWidget(self.tree_widget)

        # Tab widget for info
        self.tabs = QTabWidget()
        self.info_box = QTextEdit()
        self.info_box.setReadOnly(True)
        self.tabs.addTab(self.info_box, "Raw Info")

        self.hex_box = QTextEdit()
        self.hex_box.setReadOnly(True)
        self.tabs.addTab(self.hex_box, "Hex Viewer")

        self.central_layout.addWidget(self.tabs)

        # Export summary button
        export_layout = QHBoxLayout()
        self.export_btn = QPushButton("Export Summary")
        self.export_btn.clicked.connect(self.export_summary)
        export_layout.addWidget(self.export_btn)
        export_layout.addStretch()
        self.central_layout.addLayout(export_layout)

        # Central widget
        container = QWidget()
        container.setLayout(self.central_layout)
        self.setCentralWidget(container)

        # Status bar
        self.status = QStatusBar()
        self.setStatusBar(self.status)
        self.status.showMessage("Drag and drop .exe or .dll files here, or use File → Open")

        # Menu bar
        self.init_menu()

    def init_menu(self):
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")
        open_action = QAction("Open DLL/EXE", self)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)
        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        help_menu = menubar.addMenu("Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)

    def show_about(self):
        self.info_box.setPlainText(
            "BinScope GUI\n\n"
            "Enhanced PE/DLL analyzer.\n"
            "Shows exports, sections, imports, headers, "
            "optional header details, and key data directories.\n\n"
            "Features:\n"
            "- Search and filter tree\n"
            "- Hex viewer tab\n"
            "- Export summary to file\n"
            "- Toggle optional headers\n"
            "- Drag and drop files\n"
            "- Status bar info"
        )

    def open_file(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Open Binary",
            "",
            "Binary Files (*.exe *.dll *.so);;All Files (*)"
        )
        if file_path:
            self.load_file(file_path)

    def load_file(self, file_path):
        self.current_file_path = file_path
        self.file_label.setText(f"Loaded: {os.path.basename(file_path)}")
        self.load_pe(file_path)
        self.load_hex(file_path)
        # hide optional details initially after file load
        self.toggle_details()

    # ----------------- Drag and Drop Handlers -----------------
    def dragEnterEvent(self, event):
        """Accept the drag if it's a file."""
        if event.mimeData().hasUrls():
            event.acceptProposedAction()
        else:
            event.ignore()

    def dropEvent(self, event):
        """Handle the dropped file(s)."""
        urls = event.mimeData().urls()
        if urls:
            # Take the first file dropped
            file_path = urls[0].toLocalFile()
            if os.path.isfile(file_path) and file_path.lower().endswith(('.exe', '.dll')):
                self.load_file(file_path)
                self.status.showMessage(f"File loaded via drag & drop: {os.path.basename(file_path)}")
            else:
                self.status.showMessage("Unsupported file type. Only .exe and .dll files are supported.")

    # ----------------- PE Loading -----------------
    def load_pe(self, file_path):
        try:
            pe = pefile.PE(file_path)
            self.tree_widget.clear()
            self.details_items.clear()

            # Exports
            exports_item = QTreeWidgetItem(self.tree_widget, ["Exports"])
            if hasattr(pe, "DIRECTORY_ENTRY_EXPORT"):
                for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                    name = exp.name.decode("utf-8") if exp.name else f"Ordinal {exp.ordinal}"
                    # if demangle_available:
                    #     try:
                    #         name = cxxfilt.demangle(name)
                    #     except Exception:
                    #         pass
                    full_addr = pe.OPTIONAL_HEADER.ImageBase + exp.address
                    short_addr = hex(full_addr & 0xFFFFF)
                    # ✅ No numbering prefix
                    QTreeWidgetItem(exports_item, [name, short_addr])

            # Sections
            sections_item = QTreeWidgetItem(self.tree_widget, ["Sections"])
            for section in pe.sections:
                QTreeWidgetItem(sections_item, [
                    section.Name.decode(errors="ignore").strip(),
                    f"VA: {hex(section.VirtualAddress)}, Size: {hex(section.Misc_VirtualSize)}, Raw: {hex(section.SizeOfRawData)}"
                ])

            # Imports
            imports_item = QTreeWidgetItem(self.tree_widget, ["Imports"])
            if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_item = QTreeWidgetItem(imports_item, [entry.dll.decode()])
                    for imp in entry.imports:
                        func_name = imp.name.decode() if imp.name else f"Ordinal {imp.ordinal}"
                        short_addr = hex(imp.address & 0xFFFFF)
                        QTreeWidgetItem(dll_item, [func_name, short_addr])

            # Headers
            headers_item = QTreeWidgetItem(self.tree_widget, ["Headers"])
            QTreeWidgetItem(headers_item, ["Machine", hex(pe.FILE_HEADER.Machine)])
            QTreeWidgetItem(headers_item, ["Sections Count", str(pe.FILE_HEADER.NumberOfSections)])
            QTreeWidgetItem(headers_item, ["TimeDateStamp", hex(pe.FILE_HEADER.TimeDateStamp)])
            QTreeWidgetItem(headers_item, ["Entry Point", hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)])
            QTreeWidgetItem(headers_item, ["Image Base", hex(pe.OPTIONAL_HEADER.ImageBase)])
            QTreeWidgetItem(headers_item, ["Subsystem", str(pe.OPTIONAL_HEADER.Subsystem)])

            # Optional Header
            opt_item = QTreeWidgetItem(self.tree_widget, ["Optional Header"])
            self.details_items.append(opt_item)
            QTreeWidgetItem(opt_item, ["Linker Version", f"{pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}"])
            QTreeWidgetItem(opt_item, ["Image Size", hex(pe.OPTIONAL_HEADER.SizeOfImage)])
            QTreeWidgetItem(opt_item, ["Section Alignment", hex(pe.OPTIONAL_HEADER.SectionAlignment)])
            QTreeWidgetItem(opt_item, ["File Alignment", hex(pe.OPTIONAL_HEADER.FileAlignment)])
            QTreeWidgetItem(opt_item, ["OS Version", f"{pe.OPTIONAL_HEADER.MajorOperatingSystemVersion}.{pe.OPTIONAL_HEADER.MinorOperatingSystemVersion}"])
            QTreeWidgetItem(opt_item, ["DLL Characteristics", hex(pe.OPTIONAL_HEADER.DllCharacteristics)])

            # Data Directories
            dirs_item = QTreeWidgetItem(self.tree_widget, ["Data Directories"])
            self.details_items.append(dirs_item)
            dirs = [
                ("Export Table", 0),
                ("Import Table", 1),
                ("Resource Table", 2),
                ("Base Relocation Table", 5),
                ("Debug", 6),
                ("TLS Table", 9),
            ]
            for name, idx in dirs:
                if idx < len(pe.OPTIONAL_HEADER.DATA_DIRECTORY):
                    entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[idx]
                    QTreeWidgetItem(dirs_item, [name, f"RVA: {hex(entry.VirtualAddress)}, Size: {hex(entry.Size)}"])

            # Keep tree collapsed
            for i in range(self.tree_widget.topLevelItemCount()):
                self.tree_widget.topLevelItem(i).setExpanded(False)

            # Raw info box
            info_text = [
                f"File: {file_path}",
                f"Architecture: {hex(pe.FILE_HEADER.Machine)}",
                f"Sections: {pe.FILE_HEADER.NumberOfSections}",
                f"Entry Point: {hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)}",
                f"Image Base: {hex(pe.OPTIONAL_HEADER.ImageBase)}",
                f"Exports: {len(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', []).symbols if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else [])}",
                f"Imports: {len(getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))}",
                f"Linker Version: {pe.OPTIONAL_HEADER.MajorLinkerVersion}.{pe.OPTIONAL_HEADER.MinorLinkerVersion}",
                f"Image Size: {hex(pe.OPTIONAL_HEADER.SizeOfImage)}",
                f"Section Alignment: {hex(pe.OPTIONAL_HEADER.SectionAlignment)}",
                f"File Alignment: {hex(pe.OPTIONAL_HEADER.FileAlignment)}",
            ]
            self.info_box.setPlainText("\n".join(info_text))

            # Update status bar
            self.status.showMessage(
                f"File loaded: {os.path.basename(file_path)} | "
                f"Exports: {len(getattr(pe, 'DIRECTORY_ENTRY_EXPORT', []).symbols if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') else 0)} | "
                f"Imports: {len(getattr(pe, 'DIRECTORY_ENTRY_IMPORT', []))} | "
                f"Sections: {pe.FILE_HEADER.NumberOfSections}"
            )

        except Exception as e:
            self.info_box.setPlainText(f"Error loading file: {e}")

    # ----------------- Hex Viewer -----------------
    def load_hex(self, file_path):
        try:
            with open(file_path, "rb") as f:
                content = f.read(4096)  # first 4KB
                hex_str = " ".join(f"{b:02X}" for b in content)
                self.hex_box.setPlainText(hex_str)
        except Exception as e:
            self.hex_box.setPlainText(f"Error reading hex: {e}")

    # ----------------- Context Menu -----------------
    def show_context_menu(self, pos):
        item = self.tree_widget.itemAt(pos)
        if item:
            menu = QMenu(self)
            copy_action = QAction("Copy", self)
            copy_action.triggered.connect(lambda: self.copy_item_text(item))
            menu.addAction(copy_action)
            copy_row = QAction("Copy Row", self)
            copy_row.triggered.connect(lambda: self.copy_row(item))
            menu.addAction(copy_row)
            copy_branch = QAction("Copy Branch", self)
            copy_branch.triggered.connect(lambda: self.copy_branch(item))
            menu.addAction(copy_branch)
            menu.exec_(self.tree_widget.mapToGlobal(pos))

    def copy_item_text(self, item):
        clipboard = QApplication.clipboard()
        col = self.tree_widget.currentColumn()
        text = item.text(col) if col >= 0 else item.text(0)
        clipboard.setText(text)

    def copy_row(self, item):
        clipboard = QApplication.clipboard()
        text = " | ".join(item.text(i) for i in range(item.columnCount()))
        clipboard.setText(text)

    def copy_branch(self, item):
        clipboard = QApplication.clipboard()

        def recurse(it):
            lines = []
            row_text = " | ".join(it.text(i) for i in range(it.columnCount()))
            lines.append(row_text)
            for idx in range(it.childCount()):
                lines.extend(recurse(it.child(idx)))
            return lines

        clipboard.setText("\n".join(recurse(item)))

    # ----------------- Toggle Details -----------------
    def toggle_details(self):
        for item in self.details_items:
            item.setHidden(not self.toggle_details_btn.isChecked())

    # ----------------- Tree Filter -----------------
    def filter_tree(self, text):
        text = text.lower()

        def match(item):
            matched = text in item.text(0).lower() or text in item.text(1).lower()
            child_matched = False
            for idx in range(item.childCount()):
                if match(item.child(idx)):
                    child_matched = True
            item.setHidden(not (matched or child_matched))
            item.setExpanded(child_matched)

            font = QFont()
            if matched and text != "":
                font.setBold(False)
                item.setFont(0, font)
                item.setFont(1, font)
                item.setForeground(0, QColor("black"))
                item.setForeground(1, QColor("black"))
            else:
                font.setBold(False)
                item.setFont(0, font)
                item.setFont(1, font)
                item.setForeground(0, QColor("black"))
                item.setForeground(1, QColor("black"))

            return matched or child_matched

        for i in range(self.tree_widget.topLevelItemCount()):
            match(self.tree_widget.topLevelItem(i))

    # ----------------- Export Summary -----------------
    def export_summary(self):
        if not self.current_file_path:
            self.status.showMessage("No file loaded for export")
            return
        path, _ = QFileDialog.getSaveFileName(self, "Save Summary", "", "Text Files (*.txt)")
        if path:
            with open(path, "w", encoding="utf-8") as f:
                f.write(self.info_box.toPlainText() + "\n\nTree Summary:\n")
                def write_tree(it, indent=0):
                    f.write("  " * indent + " | ".join(it.text(i) for i in range(it.columnCount())) + "\n")
                    for idx in range(it.childCount()):
                        write_tree(it.child(idx), indent + 1)
                for i in range(self.tree_widget.topLevelItemCount()):
                    write_tree(self.tree_widget.topLevelItem(i))
            self.status.showMessage(f"Summary exported to {path}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = BinScopeGUI()
    window.show()
    sys.exit(app.exec_())
