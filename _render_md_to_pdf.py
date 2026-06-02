"""One-shot markdown -> PDF renderer for review companion docs."""
import sys
from pathlib import Path

import markdown
from weasyprint import HTML, CSS

CSS_TEXT = """
@page {
  size: A4;
  margin: 18mm 16mm 18mm 16mm;
  @bottom-right {
    content: counter(page) " / " counter(pages);
    font-family: "DejaVu Sans", sans-serif;
    font-size: 8pt;
    color: #666;
  }
}
html { font-family: "DejaVu Sans", sans-serif; font-size: 9.5pt; line-height: 1.4; color: #1a1a1a; }
h1 { font-size: 18pt; border-bottom: 2px solid #222; padding-bottom: 4px; margin-top: 0; }
h2 { font-size: 13pt; border-bottom: 1px solid #aaa; padding-bottom: 2px; margin-top: 16px; }
h3 { font-size: 11pt; margin-top: 12px; }
h4 { font-size: 10pt; margin-top: 10px; }
p { margin: 6px 0; }
em { color: #555; }
hr { border: none; border-top: 1px solid #ccc; margin: 14px 0; }
code { font-family: "DejaVu Sans Mono", monospace; font-size: 9pt; background: #f4f4f4; padding: 1px 3px; border-radius: 2px; }
pre { font-family: "DejaVu Sans Mono", monospace; font-size: 8.5pt; background: #f4f4f4; padding: 8px; border-radius: 3px; overflow-x: auto; white-space: pre-wrap; word-wrap: break-word; }
pre code { background: transparent; padding: 0; font-size: 8.5pt; }
blockquote { margin: 8px 0; padding: 6px 12px; border-left: 3px solid #999; color: #444; background: #fafafa; }
table { border-collapse: collapse; width: 100%; margin: 8px 0; font-size: 8.5pt; table-layout: fixed; word-wrap: break-word; }
th, td { border: 1px solid #bbb; padding: 4px 6px; text-align: left; vertical-align: top; word-break: break-word; }
th { background: #ececec; font-weight: 600; }
tr:nth-child(even) td { background: #fafafa; }
ul, ol { margin: 6px 0; padding-left: 22px; }
li { margin: 2px 0; }
strong { color: #000; }
img { max-width: 100%; height: auto; display: block; margin: 10px auto; border: 1px solid #ddd; }
"""


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: render_md_to_pdf.py INPUT.md OUTPUT.pdf", file=sys.stderr)
        return 2
    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])
    md_text = src.read_text(encoding="utf-8")
    html_body = markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "sane_lists", "smarty", "toc"],
    )
    html_doc = (
        '<!doctype html><html><head><meta charset="utf-8">'
        f"<title>{src.stem}</title></head><body>{html_body}</body></html>"
    )
    # base_url = the markdown file's directory, so relative image paths
    # (e.g. plots_sweep/foo.png) resolve next to the source doc.
    HTML(string=html_doc, base_url=str(src.resolve().parent)).write_pdf(
        str(dst), stylesheets=[CSS(string=CSS_TEXT)]
    )
    print(f"wrote {dst}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
