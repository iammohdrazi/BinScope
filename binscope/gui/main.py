import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QAction,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget, QMessageBox
)
from binscope.core.elf_parser import parse_elf
from binscope.core.pe_parser import parse_pe


class BinScopeGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("BinScope - Binary Inspector")
        self.setGeometry(200, 200, 900, 600)

        self.table = QTableWidget()
        layout = QVBoxLayout()
        layout.addWidget(self.table)

        container = QWidget()
        container.setLayout(layout)
        self.setCentralWidget(container)

        # Menu
        menubar = self.menuBar()
        file_menu = menubar.addMenu("File")

        open_action = QAction("Open Binary", self)
        open_action.triggered.connect(self.open_file)
        file_menu.addAction(open_action)

        exit_action = QAction("Exit", self)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

    def open_file(self):
        filepath, _ = QFileDialog.getOpenFileName(
            self, "Open Binary", "", "Binaries (*.exe *.dll *.so *.*)"
        )
        if filepath:
            try:
                if filepath.endswith((".exe", ".dll")):
                    info = parse_pe(filepath)
                else:
                    info = parse_elf(filepath)

                self.show_binary_info(info)

            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to parse: {e}")

    def show_binary_info(self, info):
        data = [
            ("File", info.filepath),
            ("Format", info.format),
            ("Architecture", info.arch),
            ("Entrypoint", hex(info.entrypoint)),
            ("Sections", str(len(info.sections))),
            ("Symbols", str(len(info.symbols))),
            ("Imports", str(len(info.imports))),
            ("Exports", str(len(info.exports))),
        ]

        self.table.setRowCount(len(data))
        self.table.setColumnCount(2)
        self.table.setHorizontalHeaderLabels(["Property", "Value"])
        for row, (key, value) in enumerate(data):
            self.table.setItem(row, 0, QTableWidgetItem(key))
            self.table.setItem(row, 1, QTableWidgetItem(value))


def main():
    app = QApplication(sys.argv)
    window = BinScopeGUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
