"""Reject high-confidence secrets and private artifacts from the tracked tree."""

import re
import subprocess
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parent.parent
ALLOWED_ENV_FILES = {".env.example", ".env.compose.example"}
FORBIDDEN_SUFFIXES = {
    ".key",
    ".log",
    ".p12",
    ".pem",
    ".pfx",
    ".sqlite",
    ".sqlite3",
}
FORBIDDEN_NAMES = {".coverage", "db.sqlite3"}
FORBIDDEN_PARTS = {
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "backups",
    "htmlcov",
    "media",
    "staticfiles",
}

# Build a few signatures from fragments so this validator does not match itself.
SECRET_PATTERNS = {
    "AWS access-key identifier": re.compile(b"AK" + b"IA[0-9A-Z]{16}"),
    "GitHub access token": re.compile(b"gh" + b"[pousr]_[A-Za-z0-9_]{20,}"),
    "private key": re.compile(
        b"-----BEGIN " + b"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
    ),
    "Slack token": re.compile(b"xox" + b"[abprs]-[A-Za-z0-9-]{10,}"),
}
DJANGO_SECRET_PATTERN = re.compile(
    rb"(?m)^\s*SECRET_KEY\s*=\s*['\"]([^'\"\r\n]+)['\"]\s*$"
)
ALLOWED_DJANGO_SECRETS = {
    b"django-insecure-local-development-only-change-before-deployment"
}


def tracked_paths() -> list[PurePosixPath]:
    result = subprocess.run(
        ["git", "ls-files", "-z"],  # noqa: S607
        cwd=ROOT,
        check=True,
        capture_output=True,
    )
    return [
        PurePosixPath(raw.decode("utf-8")) for raw in result.stdout.split(b"\0") if raw
    ]


def unsafe_path(path: PurePosixPath) -> str | None:
    if path.name.startswith(".env") and path.name not in ALLOWED_ENV_FILES:
        return "environment file"
    if path.name in FORBIDDEN_NAMES or path.suffix.lower() in FORBIDDEN_SUFFIXES:
        return "private runtime artifact"
    if any(part in FORBIDDEN_PARTS for part in path.parts):
        return "generated or private directory"
    return None


def main() -> None:
    failures = []
    paths = tracked_paths()
    for path in paths:
        path_failure = unsafe_path(path)
        if path_failure:
            failures.append(f"{path}: tracked {path_failure}")
            continue

        filesystem_path = ROOT.joinpath(*path.parts)
        if filesystem_path.is_symlink():
            failures.append(f"{path}: symbolic links require explicit review")
            continue
        data = filesystem_path.read_bytes()
        for label, pattern in SECRET_PATTERNS.items():
            if pattern.search(data):
                failures.append(f"{path}: possible {label}")
        for match in DJANGO_SECRET_PATTERN.finditer(data):
            if match.group(1) not in ALLOWED_DJANGO_SECRETS:
                failures.append(f"{path}: possible hard-coded Django secret")

    if failures:
        raise SystemExit("Repository hygiene check failed:\n" + "\n".join(failures))
    print(f"Repository hygiene valid across {len(paths)} tracked files.")


if __name__ == "__main__":
    main()
