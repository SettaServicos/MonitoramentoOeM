import os
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile


def _xml_escape(txt: str) -> str:
    return (
        txt.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
    )


def _xlsx_col_name(index_zero_based: int) -> str:
    idx = int(index_zero_based)
    if idx < 0:
        raise ValueError("index de coluna invalido")
    letters = []
    while True:
        idx, rem = divmod(idx, 26)
        letters.append(chr(ord("A") + rem))
        if idx == 0:
            break
        idx -= 1
    return "".join(reversed(letters))


def _build_sheet_xml(rows):
    row_parts = []
    for row_idx, row in enumerate(rows, start=1):
        cell_parts = []
        for col_idx, value in enumerate(row):
            cell_ref = f"{_xlsx_col_name(col_idx)}{row_idx}"
            if isinstance(value, bool):
                val = "1" if value else "0"
                cell_parts.append(f'<c r="{cell_ref}" t="b"><v>{val}</v></c>')
                continue
            if isinstance(value, (int, float)):
                cell_parts.append(f'<c r="{cell_ref}"><v>{value}</v></c>')
                continue
            txt = "" if value is None else str(value)
            escaped = _xml_escape(txt)
            preserve = ' xml:space="preserve"' if (txt[:1] == " " or txt[-1:] == " ") else ""
            cell_parts.append(
                f'<c r="{cell_ref}" t="inlineStr"><is><t{preserve}>{escaped}</t></is></c>'
            )
        row_parts.append(f'<row r="{row_idx}">{"".join(cell_parts)}</row>')
    sheet_data = "".join(row_parts)
    return (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main">'
        f"<sheetData>{sheet_data}</sheetData>"
        "</worksheet>"
    )


def write_xlsx_file(path: Path, sheets):
    safe_sheets = []
    for idx, (name, rows) in enumerate(sheets, start=1):
        sheet_name = str(name or f"Sheet{idx}")[:31]
        sheet_rows = rows if isinstance(rows, list) else list(rows)
        safe_sheets.append((sheet_name, sheet_rows))

    sheet_entries = []
    rel_entries = []
    override_entries = []
    for idx, (sheet_name, rows) in enumerate(safe_sheets, start=1):
        rid = f"rId{idx}"
        sheet_entries.append(
            f'<sheet name="{_xml_escape(sheet_name)}" sheetId="{idx}" r:id="{rid}"/>'
        )
        rel_entries.append(
            f'<Relationship Id="{rid}" '
            'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" '
            f'Target="worksheets/sheet{idx}.xml"/>'
        )
        override_entries.append(
            f'<Override PartName="/xl/worksheets/sheet{idx}.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
        )

    workbook_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" '
        'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
        f"<sheets>{''.join(sheet_entries)}</sheets>"
        "</workbook>"
    )
    workbook_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        f"{''.join(rel_entries)}"
        "</Relationships>"
    )
    root_rels_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
        '<Relationship Id="rId1" '
        'Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" '
        'Target="xl/workbook.xml"/>'
        "</Relationships>"
    )
    content_types_xml = (
        '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
        '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
        '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
        '<Default Extension="xml" ContentType="application/xml"/>'
        '<Override PartName="/xl/workbook.xml" '
        'ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
        f"{''.join(override_entries)}"
        "</Types>"
    )

    tmp_path = path.with_suffix(path.suffix + ".tmp")
    with ZipFile(tmp_path, "w", compression=ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", content_types_xml)
        zf.writestr("_rels/.rels", root_rels_xml)
        zf.writestr("xl/workbook.xml", workbook_xml)
        zf.writestr("xl/_rels/workbook.xml.rels", workbook_rels_xml)
        for idx, (_, rows) in enumerate(safe_sheets, start=1):
            zf.writestr(f"xl/worksheets/sheet{idx}.xml", _build_sheet_xml(rows))
    os.replace(tmp_path, path)
