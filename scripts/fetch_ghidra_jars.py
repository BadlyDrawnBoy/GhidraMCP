#!/usr/bin/env python3
"""Download required Ghidra system JARs into lib/ for Maven builds."""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import sys
import zipfile
from pathlib import Path
from typing import Iterable, Tuple
from urllib.request import urlopen

DEFAULT_TAG = "Ghidra_11.4.2_build"
GITHUB_RELEASES_API = "https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/tags/{tag}"

# Each tuple is (zip member path suffix, destination filename)
REQUIRED_JARS: Tuple[Tuple[str, str], ...] = (
    ("Framework/Generic/lib/Generic.jar", "Generic.jar"),
    ("Framework/SoftwareModeling/lib/SoftwareModeling.jar", "SoftwareModeling.jar"),
    ("Framework/Project/lib/Project.jar", "Project.jar"),
    ("Framework/Docking/lib/Docking.jar", "Docking.jar"),
    ("Features/Decompiler/lib/Decompiler.jar", "Decompiler.jar"),
    ("Framework/Utility/lib/Utility.jar", "Utility.jar"),
    ("Features/Base/lib/Base.jar", "Base.jar"),
    ("Framework/Gui/lib/Gui.jar", "Gui.jar"),
)


class DownloadError(RuntimeError):
    pass


def resolve_release_asset(tag: str) -> str:
    api_url = GITHUB_RELEASES_API.format(tag=tag)
    try:
        with urlopen(api_url) as resp:
            if resp.status != 200:
                raise DownloadError(f"HTTP {resp.status} when resolving tag {tag}")
            payload = json.load(resp)
    except Exception as exc:  # pragma: no cover
        raise DownloadError(f"Failed to query GitHub releases API: {exc}") from exc

    assets = payload.get("assets", [])
    if not assets:
        raise DownloadError(f"No assets found for release tag {tag}")

    asset = next((a for a in assets if a.get("browser_download_url", "").endswith(".zip")), assets[0])
    url = asset.get("browser_download_url")
    if not url:
        raise DownloadError(f"Asset entry missing download URL for tag {tag}")
    return url


def fetch_zip(url: str) -> bytes:
    try:
        with urlopen(url) as resp:
            if resp.status != 200:
                raise DownloadError(f"HTTP {resp.status} when downloading {url}")
            return resp.read()
    except Exception as exc:  # pragma: no cover - best effort error reporting
        raise DownloadError(f"Failed to download {url}: {exc}") from exc


def extract_required_jars(zip_bytes: bytes, dest_dir: Path) -> Iterable[Path]:
    extracted = []
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        prefix = None
        for member in zf.namelist():
            if member.endswith("/Ghidra"):  # Directory entry we can use to detect prefix
                prefix = member.split("Ghidra")[0]
                break
        if prefix is None:
            # Fallback: assume first component is top-level directory
            first = zf.namelist()[0]
            prefix = first.split("/")[0] + "/"
        for suffix, dest_name in REQUIRED_JARS:
            candidate = f"{prefix}Ghidra/{suffix}"
            try:
                data = zf.read(candidate)
            except KeyError as exc:
                raise DownloadError(f"Archive missing required member: {candidate}") from exc
            dest_path = dest_dir / dest_name
            dest_path.write_bytes(data)
            extracted.append(dest_path)
    return extracted


def ensure_destination(dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)
    if not os.access(dest_dir, os.W_OK):
        raise PermissionError(f"Destination {dest_dir} is not writable")


def sha256sum(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--url",
        help="Direct URL to a Ghidra release ZIP containing the required jars",
    )
    parser.add_argument(
        "--tag",
        default=DEFAULT_TAG,
        help="GitHub release tag to resolve when --url is not provided (default: %(default)s)",
    )
    parser.add_argument(
        "--dest",
        type=Path,
        default=Path(__file__).resolve().parent.parent / "lib",
        help="Directory where jars should be written (default: project lib/)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Download and list jars without writing them to disk",
    )
    args = parser.parse_args(argv)

    ensure_destination(args.dest)

    url = args.url or resolve_release_asset(args.tag)
    print(f"Downloading Ghidra archive from {url}…", file=sys.stderr)
    zip_bytes = fetch_zip(url)
    print(f"Downloaded {len(zip_bytes):,} bytes", file=sys.stderr)

    if args.dry_run:
        with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
            print("Archive contains:", file=sys.stderr)
            for suffix, _ in REQUIRED_JARS:
                candidate = next(
                    (name for name in zf.namelist() if name.endswith(suffix)),
                    None,
                )
                if candidate:
                    print(f" - {candidate}", file=sys.stderr)
                else:
                    print(f" ! Missing {suffix}", file=sys.stderr)
        return 0

    print(f"Extracting jars into {args.dest}…", file=sys.stderr)
    extracted = extract_required_jars(zip_bytes, args.dest)
    for path in extracted:
        print(f"Wrote {path.name} ({path.stat().st_size:,} bytes, sha256={sha256sum(path)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
