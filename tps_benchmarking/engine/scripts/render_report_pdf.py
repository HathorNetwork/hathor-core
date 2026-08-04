"""Render a report Markdown file to a print-quality PDF (markdown → HTML → weasyprint).

Handles the report's raw-HTML cover/pagebreak divs, GitHub-style tables, and embedded figures (relative
image paths resolve against the Markdown file's directory). Usage:

  <venv>/bin/python tps_benchmarking/engine/scripts/render_report_pdf.py \
      tps_benchmarking/report/TPS-Benchmarking-Phase3-Optimizations.md [out.pdf]
"""
from __future__ import annotations

import sys
from pathlib import Path

import markdown
from weasyprint import HTML

CSS = """
@page { size: A4; margin: 2cm 1.9cm 1.8cm 1.9cm;
        @bottom-center { content: counter(page) " / " counter(pages);
                         color: #8a8a8a; font-size: 8pt; } }
@page :first { @bottom-center { content: none; } }
* { box-sizing: border-box; }
body { font-family: "DejaVu Serif", Georgia, serif; font-size: 10.2pt; line-height: 1.42; color: #1c1c1c; }
h1, h2, h3 { font-family: "DejaVu Sans", Helvetica, Arial, sans-serif; color: #0d2a4a; line-height: 1.2; }
h2 { font-size: 15pt; border-bottom: 2px solid #d7dee7; padding-bottom: 3px; margin-top: 1.1em; }
h3 { font-size: 12pt; color: #14508c; margin-top: 1.0em; }
p { margin: 0.5em 0; text-align: justify; }
strong { color: #111; }
a { color: #14508c; text-decoration: none; }

/* cover */
.cover { height: 25cm; display: flex; flex-direction: column; justify-content: center; text-align: center;
         page-break-after: always; }
.cover-kicker { letter-spacing: 4px; font-size: 11pt; color: #6b7684;
                font-family: "DejaVu Sans", sans-serif; margin: 0; }
.cover-title { font-size: 40pt; line-height: 1.05; margin: 0.2em 0 0; color: #0d2a4a; }
.cover-phase { font-size: 16pt; color: #14508c; font-family: "DejaVu Sans", sans-serif; margin: 0.4em 0; }
.cover-rule { width: 46%; border: none; border-top: 2px solid #c7d0db; margin: 1.1em auto; }
.cover-sub { font-size: 12pt; color: #3a4453; max-width: 80%; margin: 0.3em auto; }
.cover-date, .cover-author { font-family: "DejaVu Sans", sans-serif; color: #4a5563;
                             margin: 0.15em 0; font-size: 10.5pt; }
.cover-author { margin-top: 0.8em; font-weight: bold; }
.pagebreak { page-break-after: always; }

/* tables */
table { border-collapse: collapse; width: 100%; margin: 0.8em 0; font-size: 9pt;
        font-family: "DejaVu Sans", sans-serif;
        page-break-inside: avoid; }
th, td { border: 1px solid #cfd7e1; padding: 4px 7px; text-align: left; }
th { background: #eef2f7; color: #12395f; font-weight: bold; }
tr:nth-child(even) td { background: #f8fafc; }

/* figures */
img { max-width: 92%; display: block; margin: 0.6em auto 0.2em; border: 1px solid #e3e8ee; }

/* callouts / code */
blockquote { background: #fff8e6; border-left: 4px solid #e0a800; margin: 0.8em 0; padding: 0.5em 0.9em;
             font-size: 9.4pt; color: #4a3d10; page-break-inside: avoid; }
blockquote p { text-align: left; margin: 0.2em 0; }
code { font-family: "DejaVu Sans Mono", monospace; font-size: 8.6pt; background: #f0f3f6;
       padding: 0 3px; border-radius: 2px; }
pre { background: #f6f8fa; border: 1px solid #e3e8ee; border-radius: 4px; padding: 0.7em; overflow-x: auto;
      page-break-inside: avoid; }
pre code { background: none; font-size: 8pt; line-height: 1.3; }
"""


def render(md_path: Path, pdf_path: Path) -> None:
    text = md_path.read_text(encoding="utf-8")
    body = markdown.markdown(text, extensions=["tables", "fenced_code", "attr_list", "md_in_html"])
    html = f"<html><head><meta charset='utf-8'><style>{CSS}</style></head><body>{body}</body></html>"
    # base_url = the Markdown file's dir, so relative image paths (../report-figures/...) resolve
    HTML(string=html, base_url=str(md_path.resolve().parent)).write_pdf(str(pdf_path))
    print(f"wrote {pdf_path}  ({pdf_path.stat().st_size // 1024} KB)")


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: render_report_pdf.py <report.md> [out.pdf]")
        return 2
    md = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else md.with_suffix(".pdf")
    render(md, out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
