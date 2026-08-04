"""Minimal, dependency-free .xlsx writer.

The venv has no openpyxl/xlsxwriter and this is a throwaway POC, so rather than mutate the
poetry environment we emit the OOXML parts by hand. An .xlsx is just a ZIP of XML: the five
parts below are the smallest set Excel/LibreOffice will open. Strings are written inline
(`t="inlineStr"`) so there is no shared-string table to maintain.

    write_workbook(path, {"Summary": [["key", "value"], ["tps", 638.0]], ...})

Sheets are written in dict order; each is a list of rows, each row a list of cells. `int`/`float`
become numeric cells, everything else is stringified.
"""
from __future__ import annotations

import zipfile
from pathlib import Path
from xml.sax.saxutils import escape

CONTENT_TYPES = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
    '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
    '<Default Extension="xml" ContentType="application/xml"/>'
    '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument'
    '.spreadsheetml.sheet.main+xml"/>{sheets}</Types>'
)
ROOT_RELS = (
    '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
    '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
    '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships'
    '/officeDocument" Target="xl/workbook.xml"/></Relationships>'
)


def _col(idx: int) -> str:
    """0-based column index -> spreadsheet letters (0 -> A, 26 -> AA)."""
    s = ""
    idx += 1
    while idx:
        idx, r = divmod(idx - 1, 26)
        s = chr(65 + r) + s
    return s


def _cell(ref: str, value) -> str:
    if isinstance(value, bool):                       # bool before int — bool IS an int in Python
        return f'<c r="{ref}" t="inlineStr"><is><t>{"TRUE" if value else "FALSE"}</t></is></c>'
    if isinstance(value, (int, float)):
        return f'<c r="{ref}"><v>{value!r}</v></c>' if isinstance(value, float) else \
               f'<c r="{ref}"><v>{value}</v></c>'
    return f'<c r="{ref}" t="inlineStr"><is><t>{escape(str(value))}</t></is></c>'


def _sheet_xml(rows: list[list]) -> str:
    body = []
    for r, row in enumerate(rows, start=1):
        cells = "".join(_cell(f"{_col(c)}{r}", v) for c, v in enumerate(row) if v is not None)
        body.append(f'<row r="{r}">{cells}</row>')
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
            f'<sheetData>{"".join(body)}</sheetData></worksheet>')


def write_workbook(path: str | Path, sheets: dict[str, list[list]]) -> Path:
    path = Path(path)
    names = list(sheets)
    overrides = "".join(
        f'<Override PartName="/xl/worksheets/sheet{i}.xml" ContentType="application/vnd'
        f'.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        for i in range(1, len(names) + 1))
    wb = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
          '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
          'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets>'
          + "".join(f'<sheet name="{escape(n)}" sheetId="{i}" r:id="rId{i}"/>'
                    for i, n in enumerate(names, start=1))
          + '</sheets></workbook>')
    wb_rels = ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
               '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
               + "".join(f'<Relationship Id="rId{i}" Type="http://schemas.openxmlformats.org'
                         f'/officeDocument/2006/relationships/worksheet" '
                         f'Target="worksheets/sheet{i}.xml"/>' for i in range(1, len(names) + 1))
               + '</Relationships>')

    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", CONTENT_TYPES.format(sheets=overrides))
        z.writestr("_rels/.rels", ROOT_RELS)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/_rels/workbook.xml.rels", wb_rels)
        for i, name in enumerate(names, start=1):
            z.writestr(f"xl/worksheets/sheet{i}.xml", _sheet_xml(sheets[name]))
    return path
