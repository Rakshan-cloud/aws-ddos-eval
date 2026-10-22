#!/usr/bin/env python3
"""Fill NCI's Weekly Progress Monitoring template with this week's summary.

Edits the supplied .docx rather than recreating it, so the College's layout,
fonts and bordered answer boxes are preserved exactly. The answer areas are
consecutive paragraphs sharing an identical border definition, which is what
makes Word render them as one continuous box — so text is injected into those
existing paragraphs rather than appended as new ones.

Three things are removed or left blank deliberately:
  - the underscore rule after "Week Commencing", which reads as an unfilled
    field on a submitted document
  - the template's own instruction paragraph, which tells the student what to
    write and has no place on a completed form
  - Supervisor Feedback, completed after the supervision meeting

    ./.venv/bin/python scripts/fill_weekly_form.py --summary docs/week-06-summary.txt
"""
import argparse
import re
import shutil
import subprocess
import sys
import tempfile
import zipfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

NAME = "Deekonda Rakshan"
SID = "x25180754"
TEMPLATE = Path.home() / "Downloads" / "MSc CC - Weekly Progress Monitoring Template.docx"


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--summary", required=True,
                    help="text file; blank lines separate paragraphs")
    ap.add_argument("--template", default=str(TEMPLATE))
    ap.add_argument("--out", default=str(
        Path.home() / "Downloads" / "MSc CC - Weekly Progress Monitoring - Deekonda Rakshan.docx"))
    a = ap.parse_args()

    tpl = Path(a.template)
    if not tpl.exists():
        sys.exit(f"template not found: {tpl}")

    paragraphs = [p.strip().replace("\n", " ")
                  for p in Path(a.summary).read_text().split("\n\n") if p.strip()]
    if not paragraphs:
        sys.exit("summary file is empty")

    work = Path(tempfile.mkdtemp())
    with zipfile.ZipFile(tpl) as z:
        z.extractall(work)

    doc = work / "word" / "document.xml"
    x = doc.read_text()
    paras = re.findall(r"<w:p\b.*?</w:p>", x, re.S)

    # --- student details ---------------------------------------------------
    p4 = paras[4]
    new4 = (p4.replace("Student Name: ______________________", f"Student Name: {esc(NAME)}")
              .replace("Student ID: _____________________", f"Student ID: {esc(SID)}"))
    x = x.replace(p4, new4, 1)

    # --- strip the placeholder rule and the instruction paragraph ----------
    p6 = paras[6]
    x = x.replace(p6, p6.replace("Week Commencing:___________________",
                                 "Week Commencing:"), 1)
    x = x.replace(paras[8], "", 1)

    # --- summary, into the bordered answer box -----------------------------
    BOX_START, BOX_END = 12, 37          # 37 is the Supervisor Feedback heading
    shape = paras[13]
    pPr = re.search(r"<w:pPr>.*?</w:pPr>", shape, re.S).group(0)
    rPr_m = re.search(r"<w:rPr>.*?</w:rPr>", pPr, re.S)
    rPr = rPr_m.group(0) if rPr_m else ""

    def make(text):
        run = f'<w:r>{rPr}<w:t xml:space="preserve">{esc(text)}</w:t></w:r>' if text else ""
        return f"<w:p>{pPr}{run}</w:p>"

    filled = [make(t) for t in paragraphs]
    # Retain the leftover blank lines so the box keeps its height on the page
    # rather than collapsing around the text.
    filled += [make("") for _ in range(max(0, (BOX_END - BOX_START) - len(filled)))]

    old_block = "".join(paras[BOX_START:BOX_END])
    if old_block not in x:
        sys.exit("could not locate the answer box paragraphs verbatim")
    x = x.replace(old_block, "".join(filled), 1)

    doc.write_text(x)

    out = Path(a.out)
    if out.exists():
        out.unlink()
    subprocess.run(["zip", "-Xqr", str(out), "."], cwd=work, check=True)
    shutil.rmtree(work, ignore_errors=True)

    print(f"filled {len(paragraphs)} paragraph(s)")
    print(f"  name and ID set, Week Commencing left blank")
    print(f"  instruction paragraph removed, Supervisor Feedback left empty")
    print(f"  -> {out}")


if __name__ == "__main__":
    main()
