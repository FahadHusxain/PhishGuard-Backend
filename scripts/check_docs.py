"""Fail when a local Markdown link points outside the repository or is missing."""

import re
from pathlib import Path
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parent.parent
MARKDOWN_LINK = re.compile(r"(?<!!)\[[^]]+\]\(([^)]+)\)")


def local_target(document: Path, raw_target: str) -> Path | None:
    target = raw_target.strip().split(maxsplit=1)[0].strip("<>")
    if not target or target.startswith("#") or "://" in target:
        return None
    relative_path = unquote(target.split("#", 1)[0])
    return (document.parent / relative_path).resolve()


def main() -> None:
    failures = []
    documents = [
        document
        for document in sorted(ROOT.rglob("*.md"))
        if not any(part.startswith(".") for part in document.relative_to(ROOT).parts)
    ]
    for document in documents:
        for target_text in MARKDOWN_LINK.findall(document.read_text(encoding="utf-8")):
            target = local_target(document, target_text)
            if target is None:
                continue
            if not target.is_relative_to(ROOT):
                failures.append(f"{document.relative_to(ROOT)}: outside repository")
            elif not target.exists():
                failures.append(f"{document.relative_to(ROOT)}: missing {target_text}")

    if failures:
        raise SystemExit("Broken documentation links:\n" + "\n".join(failures))
    print(f"Documentation links valid across {len(documents)} Markdown files.")


if __name__ == "__main__":
    main()
