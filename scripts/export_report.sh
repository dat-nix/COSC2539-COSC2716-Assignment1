#!/bin/sh
set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PROJECT_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
REPORT_DIR="$PROJECT_ROOT/reports/final"
INPUT="$REPORT_DIR/cryptography_under_adversarial_conditions.md"
TEMPLATE=${REFERENCE_DOCX:-"$REPORT_DIR/reference.docx"}
case "$TEMPLATE" in
    /*) ;;
    *) TEMPLATE="$PROJECT_ROOT/$TEMPLATE" ;;
esac

if [ "$#" -gt 1 ]; then
    echo "Usage: $0 [output.docx]" >&2
    exit 2
fi

OUTPUT=${1:-"$REPORT_DIR/cryptography_under_adversarial_conditions.docx"}
case "$OUTPUT" in
    /*) ;;
    *) OUTPUT="$PROJECT_ROOT/$OUTPUT" ;;
esac

for tool in pandoc python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Required tool not found: $tool" >&2
        exit 127
    fi
done

for file in "$INPUT" "$TEMPLATE"; do
    if [ ! -r "$file" ]; then
        echo "Required input file is missing or unreadable: $file" >&2
        exit 1
    fi
done

if [ -e "$OUTPUT" ] && [ "${OVERWRITE:-0}" != "1" ]; then
    echo "Output already exists: $OUTPUT" >&2
    echo "Set OVERWRITE=1 to replace it after preserving any version you need." >&2
    exit 1
fi

mkdir -p "$(dirname -- "$OUTPUT")"
TMP_DIR=$(mktemp -d "$(dirname -- "$OUTPUT")/.report-export.XXXXXX")
TMP_OUTPUT="$TMP_DIR/report.docx"
trap 'rm -f "$TMP_OUTPUT"; rmdir "$TMP_DIR" 2>/dev/null || true' EXIT HUP INT TERM

# Run from the report directory: its ../../results image paths then resolve as written.
(cd "$REPORT_DIR" && pandoc "$(basename -- "$INPUT")" \
    --from=markdown-blank_before_header-implicit_figures \
    --to=docx \
    --resource-path=. \
    --reference-doc="$TEMPLATE" \
    --output="$TMP_OUTPUT")

# Apply the template's title, caption, bibliography, and table styles to the
# report's existing Markdown structures without changing its source text.
python3 - "$TMP_OUTPUT" <<'PY'
from pathlib import Path
from zipfile import ZipFile
from xml.etree import ElementTree as ET
from copy import deepcopy
import os
import re
import sys

path = Path(sys.argv[1])
W = 'http://schemas.openxmlformats.org/wordprocessingml/2006/main'
WP = 'http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing'
NS = {'w': W, 'wp': WP}
ET.register_namespace('w', W)
ET.register_namespace('wp', WP)

def q(local):
    return f'{{{W}}}{local}'

def text_of(paragraph):
    return ''.join(node.text or '' for node in paragraph.findall('.//w:t', NS))

def set_paragraph_style(paragraph, style_id):
    ppr = paragraph.find(q('pPr'))
    if ppr is None:
        ppr = ET.Element(q('pPr'))
        paragraph.insert(0, ppr)
    style = ppr.find(q('pStyle'))
    if style is None:
        style = ET.SubElement(ppr, q('pStyle'))
    style.set(q('val'), style_id)

def set_paragraph_flag(paragraph, name):
    ppr = paragraph.find(q('pPr'))
    if ppr is None:
        ppr = ET.Element(q('pPr'))
        paragraph.insert(0, ppr)
    if ppr.find(q(name)) is None:
        ET.SubElement(ppr, q(name))

def register_namespaces(data):
    for prefix, uri in re.findall(rb'xmlns(?::([A-Za-z_][\w.-]*))?=[\"\']([^\"\']+)', data):
        ET.register_namespace(prefix.decode() if prefix else '', uri.decode())

def process_document(data):
    register_namespaces(data)
    root = ET.fromstring(data)
    body = root.find('w:body', NS)
    children = list(body)
    first_title_done = False
    in_references = False
    for index, item in enumerate(children):
        if item.tag != q('p'):
            continue
        text = text_of(item).strip()
        if not text:
            if item.find('.//w:drawing', NS) is not None:
                set_paragraph_flag(item, 'keepNext')
            continue
        style = item.find('w:pPr/w:pStyle', NS)
        style_id = style.get(q('val')) if style is not None else ''
        if not first_title_done and style_id == 'Heading1':
            set_paragraph_style(item, 'Title')
            first_title_done = True
        elif text.startswith('RMIT COSC2539 - Assignment 1:'):
            set_paragraph_style(item, 'Subtitle')
        elif re.match(r'^Figure\s+[1-4]\.', text):
            set_paragraph_style(item, 'Caption')
        elif index + 1 < len(children) and children[index + 1].tag == q('tbl'):
            set_paragraph_style(item, 'TableCaption')
        if item.find('.//w:drawing', NS) is not None:
            set_paragraph_flag(item, 'keepNext')
            ppr = item.find(q('pPr'))
            jc = ppr.find(q('jc'))
            if jc is None:
                jc = ET.SubElement(ppr, q('jc'))
            jc.set(q('val'), 'center')
        if text == 'References':
            in_references = True
        elif text == 'Acknowledgements and AI disclosure':
            in_references = False
        elif in_references and re.match(r'^\[\d+\]', text):
            set_paragraph_style(item, 'Bibliography')
    return ET.tostring(root, encoding='UTF-8', xml_declaration=True)

def add_landscape_section_for_magnitude_table(data):
    register_namespaces(data)
    root = ET.fromstring(data)
    body = root.find('w:body', NS)
    children = list(body)
    wide_table = None
    for item in children:
        if item.tag != q('tbl'):
            continue
        first_row = item.find('w:tr', NS)
        if first_row is None:
            continue
        header = ' '.join(''.join(node.text or '' for node in cell.findall('.//w:t', NS))
                          for cell in first_row.findall('w:tc', NS))
        if 'Category, construction and comparison path' in header:
            wide_table = item
            break
    if wide_table is None:
        raise RuntimeError('Could not locate the RQ3 magnitude table for landscape layout')
    body_section = body.find(q('sectPr'))
    if body_section is None:
        raise RuntimeError('Document is missing its final section properties')
    table_index = list(body).index(wide_table)
    caption_index = table_index - 1
    if caption_index < 0 or list(body)[caption_index].tag != q('p'):
        raise RuntimeError('Could not locate the RQ3 magnitude table caption')

    def section_break(section_properties, width, height):
        props = deepcopy(section_properties)
        section_type = props.find(q('type'))
        if section_type is None:
            section_type = ET.Element(q('type'))
            place = 0
            for child in list(props):
                if child.tag in (q('headerReference'), q('footerReference'), q('footnotePr'), q('endnotePr')):
                    place += 1
            props.insert(place, section_type)
        section_type.set(q('val'), 'nextPage')
        page = props.find(q('pgSz'))
        if page is None:
            page = ET.SubElement(props, q('pgSz'))
        page.set(q('w'), str(width))
        page.set(q('h'), str(height))
        page.set(q('orient'), 'portrait' if width < height else 'landscape')
        margins = props.find(q('pgMar'))
        if margins is None:
            margins = ET.SubElement(props, q('pgMar'))
        for attr in ('top', 'right', 'bottom', 'left'):
            margins.set(q(attr), '1134')
        margins.set(q('header'), '567')
        margins.set(q('footer'), '567')
        margins.set(q('gutter'), '0')
        paragraph = ET.Element(q('p'))
        ppr = ET.SubElement(paragraph, q('pPr'))
        ppr.append(props)
        return paragraph

    # Close the portrait section immediately before the descriptive table label.
    body.insert(caption_index, section_break(body_section, 11906, 16838))
    # Keep the concise table note in the landscape section; subsequent extended
    # interpretation returns to the portrait section.
    current_table_index = list(body).index(wide_table)
    note_index = next((index for index, item in enumerate(list(body)[current_table_index + 1:],
                                                           start=current_table_index + 1)
                       if item.tag == q('p') and text_of(item).strip().startswith(
                           'Each mean/median pair summarizes 30 matched observations.')), None)
    if note_index is None:
        raise RuntimeError('Could not locate the RQ3 magnitude table note for landscape layout')
    body.insert(note_index + 1, section_break(body_section, 16838, 11906))
    return ET.tostring(root, encoding='UTF-8', xml_declaration=True)

def scale_table(data, target_twips=9638, landscape_twips=14570):
    register_namespaces(data)
    root = ET.fromstring(data)
    for table in root.findall('.//w:tbl', NS):
        grid = table.find(q('tblGrid'))
        if grid is None:
            continue
        columns = list(grid.findall(q('gridCol')))
        original = [int(col.get(q('w'), '0')) for col in columns]
        total = sum(original)
        if not total:
            continue
        first_row = table.find('w:tr', NS)
        header = ' '.join(''.join(node.text or '' for node in cell.findall('.//w:t', NS))
                          for cell in first_row.findall('w:tc', NS)) if first_row is not None else ''
        is_magnitude_table = 'Category, construction and comparison path' in header
        table_width = landscape_twips if is_magnitude_table else target_twips
        if is_magnitude_table and len(original) == 7:
            # Give the long scenario description enough room to avoid splitting
            # its label across pages; keep numeric columns compact but readable.
            scaled = [4300, 1000, 1900, 2000, 1700, 1500, 2170]
        else:
            scaled = [round(width * table_width / total) for width in original]
            scaled[-1] += table_width - sum(scaled)
        for col, width in zip(columns, scaled):
            col.set(q('w'), str(width))
        props = table.find(q('tblPr'))
        if props is None:
            props = ET.Element(q('tblPr'))
            table.insert(0, props)
        width = props.find(q('tblW'))
        if width is None:
            width = ET.SubElement(props, q('tblW'))
        width.set(q('w'), str(table_width))
        width.set(q('type'), 'dxa')
        layout = props.find(q('tblLayout'))
        if layout is None:
            layout = ET.SubElement(props, q('tblLayout'))
        layout.set(q('type'), 'fixed')
        for row_index, row in enumerate(table.findall(q('tr'))):
            trpr = row.find(q('trPr'))
            if trpr is None:
                trpr = ET.Element(q('trPr'))
                row.insert(0, trpr)
            if row_index == 0:
                if trpr.find(q('cantSplit')) is None:
                    ET.SubElement(trpr, q('cantSplit'))
                header = trpr.find(q('tblHeader'))
                if header is None:
                    header = ET.SubElement(trpr, q('tblHeader'))
                header.set(q('val'), 'true')
            else:
                if trpr.find(q('cantSplit')) is None:
                    ET.SubElement(trpr, q('cantSplit'))
            column_index = 0
            for cell in row.findall(q('tc')):
                tcpr = cell.find(q('tcPr'))
                if tcpr is None:
                    tcpr = ET.Element(q('tcPr'))
                    cell.insert(0, tcpr)
                span_node = tcpr.find(q('gridSpan'))
                span = int(span_node.get(q('val'), '1')) if span_node is not None else 1
                cell_width = sum(scaled[column_index:column_index + span])
                column_index += span
                tcw = tcpr.find(q('tcW'))
                if tcw is None:
                    tcw = ET.SubElement(tcpr, q('tcW'))
                tcw.set(q('w'), str(cell_width))
                tcw.set(q('type'), 'dxa')
                valign = tcpr.find(q('vAlign'))
                if valign is None:
                    valign = ET.SubElement(tcpr, q('vAlign'))
                valign.set(q('val'), 'top')
        if is_magnitude_table:
            # The dense selected RQ3 evidence table is kept together in its
            # landscape section. Compact only this appendix table so all rows
            # fit without reducing the font to an unreadable size.
            cell_margins = props.find(q('tblCellMar'))
            if cell_margins is None:
                cell_margins = ET.SubElement(props, q('tblCellMar'))
            for side, value in (('top', '35'), ('bottom', '35'),
                                ('left', '55'), ('right', '55')):
                margin = cell_margins.find(q(side))
                if margin is None:
                    margin = ET.SubElement(cell_margins, q(side))
                margin.set(q('w'), value)
                margin.set(q('type'), 'dxa')
            for paragraph in table.findall('.//w:p', NS):
                ppr = paragraph.find(q('pPr'))
                if ppr is None:
                    ppr = ET.Element(q('pPr'))
                    paragraph.insert(0, ppr)
                spacing = ppr.find(q('spacing'))
                if spacing is None:
                    spacing = ET.SubElement(ppr, q('spacing'))
                spacing.set(q('before'), '0')
                spacing.set(q('after'), '0')
                spacing.set(q('line'), '220')
                spacing.set(q('lineRule'), 'auto')
                for run in paragraph.findall('w:r', NS):
                    rpr = run.find(q('rPr'))
                    if rpr is None:
                        rpr = ET.Element(q('rPr'))
                        run.insert(0, rpr)
                    for size_name in ('sz', 'szCs'):
                        size = rpr.find(q(size_name))
                        if size is None:
                            size = ET.SubElement(rpr, q(size_name))
                        size.set(q('val'), '19')
    return ET.tostring(root, encoding='UTF-8', xml_declaration=True)

temp = path.with_suffix('.styled.docx')
with ZipFile(path, 'r') as source, ZipFile(temp, 'w') as target:
    for info in source.infolist():
        content = source.read(info.filename)
        if info.filename == 'word/document.xml':
            content = process_document(content)
            content = add_landscape_section_for_magnitude_table(content)
            content = scale_table(content)
        target.writestr(info, content)
os.replace(temp, path)
PY

mv -f "$TMP_OUTPUT" "$OUTPUT"
echo "Created $OUTPUT"
