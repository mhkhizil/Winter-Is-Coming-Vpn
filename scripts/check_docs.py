#!/usr/bin/env python3
"""Documentation lint used by CI.

* every relative Markdown link must resolve
* no tab characters in Markdown
* every docs/DECISIONS/ADR-*.md must follow the ADR-NNNN-title.md convention
* the normative docs listed in docs/README.md must exist
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
REQUIRED = [
    "docs/README.md",
    "docs/ARCHITECTURE.md",
    "docs/PROTOCOL.md",
    "docs/THREAT_MODEL.md",
    "docs/DATA_MODEL.md",
    "docs/API.md",
    "docs/api/openapi.yaml",
    "docs/CLIENT_INTEGRATION.md",
    "docs/DEPLOYMENT.md",
    "docs/RUNBOOK.md",
    "docs/CAPACITY.md",
    "docs/BUILDING.md",
    "docs/CPP_CONVENTIONS.md",
    "docs/ROADMAP.md",
    "CONTRIBUTING.md",
    "SECURITY.md",
]

problems: list[str] = []

for rel in REQUIRED:
    if not (ROOT / rel).exists():
        problems.append(f"missing required document: {rel}")

link_re = re.compile(r"\]\(([^)#\s][^)\s]*)\)")
adr_re = re.compile(r"^ADR-\d{4}-[a-z0-9-]+\.md$")

for md in sorted(ROOT.rglob("*.md")):
    if ".git" in md.parts:
        continue
    text = md.read_text(encoding="utf-8", errors="replace")
    rel = md.relative_to(ROOT)

    if "\t" in text:
        problems.append(f"{rel}: tab character in Markdown")

    for target in link_re.findall(text):
        if target.startswith(("http://", "https://", "mailto:")):
            continue
        base = target.split("#")[0]
        if base and not (md.parent / base).resolve().exists():
            problems.append(f"{rel}: broken link -> {target}")

    if md.parent.name == "DECISIONS" and md.name != "README.md" and not adr_re.match(md.name):
        problems.append(f"{rel}: ADR filename must match ADR-NNNN-lowercase-title.md")

    if md.parent.name == "DECISIONS" and adr_re.match(md.name):
        for heading in ("## Context", "## Decision", "## Consequences"):
            if heading not in text:
                problems.append(f"{rel}: missing section '{heading}'")
        if "Status:" not in text:
            problems.append(f"{rel}: missing 'Status:' line")

if problems:
    print(f"FAILED: {len(problems)} documentation problem(s)")
    for p in problems:
        print("  *", p)
    sys.exit(1)

print("OK: documentation lint passed")
