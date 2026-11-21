"""Build the editable presentation with Pandoc's PowerPoint writer."""

from __future__ import annotations

import argparse
from io import BytesIO
from pathlib import Path
import re
import shutil
import subprocess
from zipfile import ZIP_DEFLATED, ZipFile


ROOT = Path(__file__).resolve().parents[1]
DEMO_DIR = ROOT / "demo"
SOURCE = DEMO_DIR / "presentation.md"
TEMPLATE = DEMO_DIR / "reference.pptx"
DEFAULT_OUTPUT = DEMO_DIR / "presentation.pptx"
REQUIRED_IMAGES = (
    ROOT / "results/symmetric/rq1/analysis/run_20261119_02/symmetric_rq1_execution_time.png",
    ROOT / "results/symmetric/rq3/analysis/run_20261119_03/symmetric_rq3_execution_time.png",
)


THEME_REPLACEMENTS = {
    b"1F497D": b"16324F",  # dark navy
    b"EEECE1": b"F4F6F8",  # cool near-white
    b"4F81BD": b"254E70",  # restrained blue
    b"C0504D": b"2A9D8F",  # teal
    b"9BBB59": b"77A9A1",  # muted teal
    b"8064A2": b"6C83A7",  # slate blue
    b"4BACC6": b"E9C46A",  # muted gold
    b"F79646": b"E76F51",  # restrained warm accent
    b"0000FF": b"2A9D8F",  # hyperlink
    b"800080": b"6C83A7",  # visited hyperlink
    b"Calibri": b"Arial",
}


def _require_command(command: str) -> None:
    if shutil.which(command) is None:
        raise SystemExit(f"Required command not found: {command}")


def _styled_reference_bytes(default_pptx: bytes) -> bytes:
    source = BytesIO(default_pptx)
    output = BytesIO()
    with ZipFile(source, "r") as source_zip, ZipFile(
        output, "w", compression=ZIP_DEFLATED
    ) as output_zip:
        for item in source_zip.infolist():
            content = source_zip.read(item.filename)
            if item.filename.startswith("ppt/theme/") and item.filename.endswith(".xml"):
                for old, new in THEME_REPLACEMENTS.items():
                    content = content.replace(old, new)
            output_zip.writestr(item, content)
    return output.getvalue()


def create_template() -> None:
    if TEMPLATE.exists():
        raise SystemExit(
            f"Refusing to overwrite existing template: {TEMPLATE.relative_to(ROOT)}"
        )
    _require_command("pandoc")
    result = subprocess.run(
        ["pandoc", "--print-default-data-file", "reference.pptx"],
        check=True,
        stdout=subprocess.PIPE,
    )
    TEMPLATE.write_bytes(_styled_reference_bytes(result.stdout))
    print(f"Created {TEMPLATE.relative_to(ROOT)} from the installed Pandoc template.")


def _fit_title_slide(xml: bytes) -> bytes:
    text = xml.decode("utf-8")
    shapes = re.findall(r"<p:sp>.*?</p:sp>", text, flags=re.DOTALL)
    original_title_shape = next(
        (shape for shape in shapes if 'type="ctrTitle"' in shape), None
    )
    if original_title_shape is None:
        raise SystemExit("Could not locate the title placeholder in the generated deck.")
    title_shape = original_title_shape

    title_shape = re.sub(
        r'(<a:off x="\d+" y=")\d+(" />)',
        r'\g<1>457200\2',
        title_shape,
        count=1,
    )
    title_shape = re.sub(
        r'(<a:ext cx="\d+" cy=")\d+(" />)',
        r'\g<1>1800000\2',
        title_shape,
        count=1,
    )
    title_shape = title_shape.replace("<a:rPr />", '<a:rPr sz="2800" />', 1)
    if 'sz="2800"' not in title_shape:
        raise SystemExit("Could not apply the title font-size adjustment.")
    return text.replace(original_title_shape, title_shape, 1).encode("utf-8")


def _style_chart_caption(xml: bytes, marker: str, font_size: int = 1200) -> bytes:
    text = xml.decode("utf-8")
    shapes = re.findall(r"<p:sp>.*?</p:sp>", text, flags=re.DOTALL)
    caption = next((shape for shape in shapes if marker in shape), None)
    if caption is None:
        raise SystemExit(f"Could not find chart-caption text: {marker}")
    styled_caption = re.sub(
        r"<a:rPr\s*/>", f'<a:rPr sz="{font_size}" />', caption
    )
    if styled_caption == caption:
        raise SystemExit(f"Could not style chart-caption text: {marker}")
    return text.replace(caption, styled_caption, 1).encode("utf-8")


def _postprocess_presentation(path: Path) -> None:
    entries = []
    with ZipFile(path, "r") as source_zip:
        for item in source_zip.infolist():
            content = source_zip.read(item.filename)
            if item.filename == "ppt/slides/slide1.xml":
                content = _fit_title_slide(content)
            elif item.filename == "ppt/slides/slide6.xml":
                content = _style_chart_caption(
                    content,
                    "Displayed chart: Symmetric category only.",
                    font_size=1500,
                )
            elif item.filename == "ppt/slides/slide8.xml":
                content = _style_chart_caption(
                    content, "Corrected run_20261119_02: Symmetric RQ3 mean decryption time"
                )
            entries.append((item, content))
    with ZipFile(path, "w", compression=ZIP_DEFLATED) as output_zip:
        for item, content in entries:
            output_zip.writestr(item, content)


def build_presentation(output_path: Path, overwrite: bool = False) -> None:
    _require_command("pandoc")
    if not SOURCE.is_file():
        raise SystemExit(f"Missing slide source: {SOURCE}")
    if not TEMPLATE.is_file():
        raise SystemExit(
            "Missing demo/reference.pptx. Create it first with "
            "python demo/build_presentation.py --create-template"
        )
    missing = [path.relative_to(ROOT) for path in REQUIRED_IMAGES if not path.is_file()]
    if missing:
        raise SystemExit(f"Missing chart image(s): {', '.join(map(str, missing))}")

    output_path = output_path if output_path.is_absolute() else ROOT / output_path
    output_path = output_path.resolve()
    if output_path.exists() and not overwrite:
        raise SystemExit(
            f"Refusing to overwrite existing output: {output_path}. "
            "Use --overwrite only after preserving the current copy."
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "pandoc",
        str(SOURCE.relative_to(ROOT)),
        "--from=markdown+fenced_divs+pipe_tables",
        "--to=pptx",
        "--standalone",
        "--slide-level=1",
        f"--reference-doc={TEMPLATE.relative_to(ROOT)}",
        "--resource-path=.",
        "-o",
        str(output_path),
    ]
    subprocess.run(command, cwd=ROOT, check=True)
    _postprocess_presentation(output_path)

    with ZipFile(output_path, "r") as presentation:
        names = presentation.namelist()
        slide_count = len(
            [name for name in names if re.fullmatch(r"ppt/slides/slide\d+\.xml", name)]
        )
        note_count = len(
            [
                name
                for name in names
                if re.fullmatch(r"ppt/notesSlides/notesSlide\d+\.xml", name)
            ]
        )
        media_count = len(
            [name for name in names if name.startswith("ppt/media/")]
        )
    if slide_count != 9:
        output_path.unlink(missing_ok=True)
        raise SystemExit(f"Expected 9 slides, found {slide_count}; output removed.")
    if media_count < len(REQUIRED_IMAGES):
        output_path.unlink(missing_ok=True)
        raise SystemExit("One or more chart images were not embedded; output removed.")
    if note_count < 8:
        output_path.unlink(missing_ok=True)
        raise SystemExit(f"Expected notes on each content slide; found {note_count}.")
    print(f"Created {output_path.relative_to(ROOT) if output_path.is_relative_to(ROOT) else output_path}")
    print(f"Slides: {slide_count}; speaker-note pages: {note_count}; embedded media: {media_count}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--create-template",
        action="store_true",
        help="Create demo/reference.pptx from Pandoc's installed default template.",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT,
        help="Output path (default: demo/presentation.pptx).",
    )
    parser.add_argument(
        "--overwrite",
        action="store_true",
        help="Allow replacement of the specified output file.",
    )
    args = parser.parse_args()
    if args.create_template:
        create_template()
    else:
        build_presentation(args.output, overwrite=args.overwrite)


if __name__ == "__main__":
    main()
