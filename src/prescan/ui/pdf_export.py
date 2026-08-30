"""HTML -> PDF export via QTextDocument/QPdfWriter (spec §16.1).

PDF generation lives in the UI layer because it needs Qt; core/report.py only
emits JSON and HTML (no Qt in core, §10.1). This keeps WeasyPrint/GTK off the
dependency list while still producing a PDF from the same HTML report.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtGui import QPageSize, QPdfWriter, QTextDocument


def html_to_pdf(html: str, dest: Path) -> None:
    """Render an HTML string to a PDF file at ``dest``."""
    writer = QPdfWriter(str(dest))
    writer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    writer.setResolution(96)
    document = QTextDocument()
    document.setHtml(html)
    document.print_(writer)
