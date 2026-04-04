#!/usr/bin/env python3
"""
update_sdk.py — Poll Apple's software update catalog for a new macOS SDK,
                extract it, and re-run parse.py if an update is found.

Usage:
    python3 update_sdk.py [--dry-run] [--force]

Intended to be run on a schedule (e.g. cron, systemd timer, launchd) on any
machine serving the endpointsecurity site. Requires xar and bsdtar for .pkg extraction:

    macOS:         xar and bsdtar are available via Xcode Command Line Tools
    Debian/Ubuntu: apt install xar libarchive-tools

No third-party Python dependencies — stdlib only.
"""

import argparse
import plistlib
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

# ─── Config ───────────────────────────────────────────────────────────────────

# Apple's merged software update catalog (covers macOS 10.9 → current)
SUCATALOG_URL = (
    "https://swscan.apple.com/content/catalogs/others/"
    "index-15-14-13-12-10.16-10.15-10.14-10.13-10.12-10.11-10.10-10.9"
    "-mountainlion-lion-snowleopard-leopard.merged-1.sucatalog.gz"
)

# Preferred package identifier; fall back to the non-N variant
SDK_PKG_NAMES = ["CLTools_macOSNMOS_SDK", "CLTools_macOS_SDK"]

STATE_DIR = Path.home() / ".local" / "share" / "endpointsecurity"
STATE_FILE = STATE_DIR / "last_sdk_url"

REPO_ROOT = Path(__file__).parent
PARSE_SCRIPT = REPO_ROOT / "parse.py"


# ─── Catalog ──────────────────────────────────────────────────────────────────


def fetch_catalog() -> dict:
    """Download and parse the SUCatalog plist (gzip-compressed)."""
    import gzip

    print(f"Fetching catalog: {SUCATALOG_URL}")
    with urllib.request.urlopen(SUCATALOG_URL, timeout=30) as resp:
        raw = resp.read()

    # The catalog is gzip-compressed
    try:
        raw = gzip.decompress(raw)
    except Exception:
        pass  # Some mirrors serve it uncompressed

    return plistlib.loads(raw)


def find_latest_sdk_pkg(catalog: dict) -> tuple[str, str] | None:
    """
    Scan the catalog for the most recent SDK package.
    Returns (pkg_url, post_date_str) or None.
    """

    best_url = None
    best_date = None

    products = catalog.get("Products", {})
    for product_id, product in products.items():
        packages = product.get("Packages", [])
        post_date = product.get("PostDate")

        for pkg in packages:
            url: str = pkg.get("URL", "")
            for name in SDK_PKG_NAMES:
                if name in url:
                    if best_date is None or post_date > best_date:
                        best_date = post_date
                        best_url = url
                    break

    if best_url is None:
        return None

    # Normalise date to a readable string
    date_str = best_date.strftime("%Y-%m-%d") if best_date else "unknown"
    return best_url, date_str


# ─── State ────────────────────────────────────────────────────────────────────


def read_last_url() -> str:
    try:
        return STATE_FILE.read_text().strip()
    except FileNotFoundError:
        return ""


def write_last_url(url: str) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(url)


# ─── Download ─────────────────────────────────────────────────────────────────


def download_pkg(url: str, dest: Path) -> None:
    """Stream-download a .pkg to dest, printing progress."""
    print(f"Downloading: {url}")
    with urllib.request.urlopen(url, timeout=60) as resp:
        total = int(resp.headers.get("Content-Length", 0))
        downloaded = 0
        chunk = 1024 * 1024  # 1 MiB
        with dest.open("wb") as f:
            while True:
                block = resp.read(chunk)
                if not block:
                    break
                f.write(block)
                downloaded += len(block)
                if total:
                    pct = downloaded * 100 // total
                    print(
                        f"  {downloaded // (1024 * 1024)} / {total // (1024 * 1024)} MiB ({pct}%)",
                        end="\r",
                        flush=True,
                    )
    print()  # newline after progress


# ─── Extraction ───────────────────────────────────────────────────────────────


def extract_pkg(pkg_path: Path, extract_dir: Path) -> Path:
    """
    Extract a macOS .pkg on Linux using xar + bsdtar.
    Returns the SDK root (directory containing usr/include/EndpointSecurity/).
    """
    print(f"Extracting: {pkg_path.name}")

    # xar expands the .pkg container into its component directories
    subprocess.run(
        ["xar", "-xf", str(pkg_path), "-C", str(extract_dir)],
        check=True,
        capture_output=True,
    )

    # Each component has a Payload file — find the one containing ES headers
    for payload in extract_dir.rglob("Payload"):
        payload_dir = payload.parent / "payload_contents"
        payload_dir.mkdir(exist_ok=True)
        result = subprocess.run(
            ["bsdtar", "-xf", str(payload), "-C", str(payload_dir)],
            capture_output=True,
        )
        if result.returncode != 0:
            continue

        # Locate ESTypes.h to find the SDK root
        for header in payload_dir.rglob("ESTypes.h"):
            # ESTypes.h lives at <sdk_root>/usr/include/EndpointSecurity/ESTypes.h
            sdk_root = header.parent.parent.parent.parent
            if (sdk_root / "usr" / "include" / "EndpointSecurity").is_dir():
                return sdk_root

    raise RuntimeError("Could not find EndpointSecurity headers in extracted .pkg")


# ─── Parse ────────────────────────────────────────────────────────────────────


def run_parse(sdk_root: Path) -> None:
    """Run parse.py against the extracted SDK root."""
    print(f"Running parse.py --sdk-path {sdk_root}")
    subprocess.run(
        [sys.executable, str(PARSE_SCRIPT), "--sdk-path", str(sdk_root)],
        check=True,
    )


# ─── Main ─────────────────────────────────────────────────────────────────────


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Poll Apple's SUCatalog and update EndpointSecurity data"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Check for updates only; do not download or parse",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Re-download and re-parse even if the SDK URL is unchanged",
    )
    args = parser.parse_args()

    # 1. Fetch catalog
    try:
        catalog = fetch_catalog()
    except Exception as e:
        print(f"ERROR: Failed to fetch catalog: {e}", file=sys.stderr)
        sys.exit(1)

    # 2. Find latest SDK package
    result = find_latest_sdk_pkg(catalog)
    if result is None:
        print("ERROR: No SDK package found in catalog.", file=sys.stderr)
        sys.exit(1)

    pkg_url, pkg_date = result
    print(f"Latest SDK package ({pkg_date}): {pkg_url}")

    # 3. Compare with last known URL
    last_url = read_last_url()
    if pkg_url == last_url and not args.force:
        print("No update — SDK URL is unchanged.")
        return

    if pkg_url != last_url:
        print(
            "New SDK detected."
            if not args.dry_run
            else "New SDK detected (dry-run, stopping here)."
        )
    elif args.force:
        print(
            "Forcing re-download (--force)."
            if not args.dry_run
            else "Would re-download (--dry-run --force)."
        )

    if args.dry_run:
        return

    # 4. Download, extract, parse
    with tempfile.TemporaryDirectory(prefix="endpointsecurity-sdk-") as tmp:
        tmp_path = Path(tmp)
        pkg_file = tmp_path / "sdk.pkg"

        try:
            download_pkg(pkg_url, pkg_file)
        except Exception as e:
            print(f"ERROR: Download failed: {e}", file=sys.stderr)
            sys.exit(1)

        try:
            sdk_root = extract_pkg(pkg_file, tmp_path / "extracted")
        except Exception as e:
            print(f"ERROR: Extraction failed: {e}", file=sys.stderr)
            sys.exit(1)

        try:
            run_parse(sdk_root)
        except subprocess.CalledProcessError as e:
            print(f"ERROR: parse.py failed (exit {e.returncode})", file=sys.stderr)
            sys.exit(1)

    # 5. Record the new URL
    write_last_url(pkg_url)
    print("Done.")


if __name__ == "__main__":
    main()
