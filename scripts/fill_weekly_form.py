#!/usr/bin/env python3
"""Fill NCI's Weekly Progress Monitoring template with this period's summary.

Edits the supplied .docx rather than recreating it, so the College's layout,
fonts and bordered answer boxes are preserved exactly. The answer areas are
consecutive paragraphs sharing an identical border definition, which is what
makes Word render them as one continuous box -- so text is injected into those
existing paragraphs rather than appended as new ones.

Two things make this harder than a string replacement:

  - Word splits a single visible line across many <w:t> runs. "Student Name:
    ______" is six runs, so replacing the literal string "Student Name: ______"
    matches nothing. Substitutions are therefore made per run, on the
    underscore sequences themselves.

  - Paragraphs are located by their visible text, not by index. An earlier
    version used fixed indices; when the template was re-downloaded, the
    replacements silently matched nothing and the script still reported
    success, producing a form with the student's name left blank.

Every substitution is asserted. This script fails loudly or not at all.

Three things are removed or left blank deliberately:
  - the underscore rule after "Week Commencing", which reads as an unfilled
    field on a submitted document
  - the template's own instruction paragraph, which tells the student what to
    write and has no place on a completed form
  - Supervisor Feedback, completed after the supervision meeting

    ./.venv/bin/python scripts/fill_weekly_form.py --summary docs/week-07-summary.txt
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

P_RE = re.compile(r"<w:p\b.*?</w:p>", re.S)
T_RE = re.compile(r"(<w:t\b[^>]*>)(.*?)(</w:t>)", re.S)
BLANK = re.compile(r"_{3,}")


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def para_text(p: str) -> str:
    """The visible text of a paragraph, reassembled from its runs."""
    return "".join(m.group(2) for m in T_RE.finditer(p))


def find_para(paras: list[str], needle: str, start: int = 0) -> int:
    """Index of the first paragraph at or after `start` containing `needle`.

    `start` matters: the template's instruction paragraph quotes several of
    the headings verbatim, so "Supervisor Feedback" matches the instructions
    before it matches the heading of that name.
    """
    for i in range(start, len(paras)):
        if needle in para_text(paras[i]):
            return i
    sys.exit(f"could not find a paragraph containing {needle!r} -- "
             "the template layout has changed")


def fill_blanks(p: str, values: list[str]) -> tuple[str, int]:
    """Replace successive underscore runs with values, in document order.

    Returns the new paragraph and how many substitutions were made, so the
    caller can verify that the template still had the fields it expected.
    """
    pending = list(values)
    made = 0

    def on_run(m):
        nonlocal made
        open_tag, text, close_tag = m.groups()

        def on_blank(_):
            nonlocal made
            if not pending:
                return _.group(0)
            made += 1
            return esc(pending.pop(0))

        return open_tag + BLANK.sub(on_blank, text) + close_tag

    return T_RE.sub(on_run, p), made


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
    paras = P_RE.findall(x)

    # --- student details ---------------------------------------------------
    i = find_para(paras, "Student Name")
    new, made = fill_blanks(paras[i], [NAME, SID])
    if made != 2:
        sys.exit(f"expected two blanks in the student details line, filled {made}")
    x = x.replace(paras[i], new, 1)

    # --- strip the placeholder rule ----------------------------------------
    i = find_para(paras, "Week Commencing")
    new, made = fill_blanks(paras[i], [""])
    if made != 1:
        sys.exit("the Week Commencing rule was not where it was expected")
    x = x.replace(paras[i], new, 1)

    # --- remove the template's own instruction paragraph -------------------
    i = find_para(paras, "weekly progress monitoring is a half a page report")
    x = x.replace(paras[i], "", 1)

    # --- summary, into the bordered answer box -----------------------------
    box_start = find_para(paras, "Summary of research activities") + 1
    box_end = find_para(paras, "Supervisor Feedback", start=box_start)
    if box_end <= box_start:
        sys.exit("the answer box boundaries look wrong")

    shape = paras[box_start + 1]
    pPr_m = re.search(r"<w:pPr>.*?</w:pPr>", shape, re.S)
    if not pPr_m:
        sys.exit("could not read the answer box paragraph formatting")
    pPr = pPr_m.group(0)
    rPr_m = re.search(r"<w:rPr>.*?</w:rPr>", pPr, re.S)
    rPr = rPr_m.group(0) if rPr_m else ""

    def make(text):
        run = f'<w:r>{rPr}<w:t xml:space="preserve">{esc(text)}</w:t></w:r>' if text else ""
        return f"<w:p>{pPr}{run}</w:p>"

    filled = [make(t) for t in paragraphs]
    # Retain the leftover blank lines so the box keeps its height on the page
    # rather than collapsing around the text.
    filled += [make("") for _ in range(max(0, (box_end - box_start) - len(filled)))]

    old_block = "".join(paras[box_start:box_end])
    if old_block not in x:
        sys.exit("could not locate the answer box paragraphs verbatim")
    x = x.replace(old_block, "".join(filled), 1)

    doc.write_text(x)

    out = Path(a.out)
    if out.exists():
        out.unlink()
    subprocess.run(["zip", "-Xqr", str(out), "."], cwd=work, check=True)
    shutil.rmtree(work, ignore_errors=True)

    print(f"filled {len(paragraphs)} paragraph(s) into the answer box")
    print(f"  student details set: {NAME}, {SID}")
    print("  Week Commencing rule removed, instruction paragraph removed")
    print("  Supervisor Feedback left empty")
    print(f"  -> {out}")


if __name__ == "__main__":
    main()
