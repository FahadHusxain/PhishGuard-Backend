"""Validate the unpacked browser extension's security-sensitive contract."""

import json
import re
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
EXTENSION = ROOT / "browser-extension"
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"
EXPECTED_ICONS = {16, 32, 48, 128}
FORBIDDEN_JAVASCRIPT = ("innerHTML", "outerHTML", "eval(", "new Function(")


def fail(message: str) -> None:
    raise SystemExit(f"Browser extension validation failed: {message}")


def validate_icon(path: Path, expected_size: int) -> None:
    data = path.read_bytes()
    if not data.startswith(PNG_SIGNATURE) or len(data) < 24:
        fail(f"{path.relative_to(ROOT)} is not a valid PNG")
    width, height = struct.unpack(">II", data[16:24])
    if (width, height) != (expected_size, expected_size):
        fail(f"{path.relative_to(ROOT)} must be {expected_size}x{expected_size}")


def validate_html(path: Path) -> None:
    content = path.read_text(encoding="utf-8")
    if re.search(r"<script(?![^>]*\bsrc=)[^>]*>", content, re.IGNORECASE):
        fail(f"{path.relative_to(ROOT)} contains an inline script")
    if re.search(r"\son[a-z]+\s*=", content, re.IGNORECASE):
        fail(f"{path.relative_to(ROOT)} contains an inline event handler")
    if re.search(r"<style\b|\sstyle\s*=", content, re.IGNORECASE):
        fail(f"{path.relative_to(ROOT)} contains inline styles")


def main() -> None:
    manifest_path = EXTENSION / "manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("manifest_version") != 3:
        fail("manifest_version must be 3")
    if set(manifest.get("permissions", [])) != {"activeTab", "storage"}:
        fail("named permissions must remain limited to activeTab and storage")
    if set(manifest.get("host_permissions", [])) != {
        "http://127.0.0.1/*",
        "http://localhost/*",
    }:
        fail("required host permissions must remain loopback-only")
    if manifest.get("optional_host_permissions") != ["https://*/*"]:
        fail("remote host access must remain HTTPS-only and optional")
    expected_csp = "script-src 'self'; object-src 'self'"
    extension_csp = manifest.get("content_security_policy", {}).get("extension_pages")
    if extension_csp != expected_csp:
        fail("extension page CSP changed unexpectedly")

    referenced_icons = {
        int(size): EXTENSION / relative_path
        for size, relative_path in manifest.get("icons", {}).items()
    }
    if set(referenced_icons) != EXPECTED_ICONS:
        fail("manifest must reference 16, 32, 48, and 128 px icons")
    for size, path in referenced_icons.items():
        if not path.is_file():
            fail(f"missing icon {path.relative_to(ROOT)}")
        validate_icon(path, size)

    for filename in ("popup.html", "options.html"):
        validate_html(EXTENSION / filename)
    for path in sorted(EXTENSION.rglob("*.js")):
        content = path.read_text(encoding="utf-8")
        for forbidden in FORBIDDEN_JAVASCRIPT:
            if forbidden in content:
                fail(
                    f"{path.relative_to(ROOT)} contains forbidden JavaScript: "
                    f"{forbidden}"
                )
        if re.search(r"(?:import|src\s*=).*https?://", content):
            fail(f"{path.relative_to(ROOT)} references remote executable code")

    print("Browser extension manifest, CSP, assets, and permissions are valid.")


if __name__ == "__main__":
    main()
