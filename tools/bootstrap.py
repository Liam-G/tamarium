#!/usr/bin/env python3
"""Install the checksum-pinned Linux x86_64 proof tools into this project."""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import platform
import tarfile
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def install() -> None:
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "AMD64"):
        raise SystemExit("Pinned bootstrap supports Linux x86_64; use Tamarin's official installation instructions on other systems.")
    pins = json.loads((ROOT / "toolchain.json").read_text())
    for name, pin in pins.items():
        destination = ROOT / ".tools" / ("bin" if name == "tamarin" else "maude")
        cache = ROOT / ".tools" / "downloads" / ("tamarin.tar.gz" if name == "tamarin" else "maude.zip")
        cache.parent.mkdir(parents=True, exist_ok=True)
        if cache.exists():
            data = cache.read_bytes()
        else:
            print(f"Downloading {name} {pin['version']}", flush=True)
            request = urllib.request.Request(pin["url"], headers={"User-Agent": "Tamarium-bootstrap"})
            with urllib.request.urlopen(request, timeout=60) as response:
                data = response.read(100_000_001)
            if len(data) > 100_000_000:
                raise SystemExit(f"Oversized {name} archive")
        if hashlib.sha256(data).hexdigest() != pin["sha256"]:
            raise SystemExit(f"SHA-256 mismatch for {name}; archive was not extracted")
        cache.write_bytes(data)
        destination.mkdir(parents=True, exist_ok=True)
        if name == "tamarin":
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                member = archive.getmember("tamarin-prover")
                if not member.isfile():
                    raise SystemExit("Tamarin executable is not a regular file")
                executable = archive.extractfile(member)
                assert executable is not None
                (destination / "tamarin-prover").write_bytes(executable.read())
            (destination / "tamarin-prover").chmod(0o755)
        else:
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.infolist():
                    relative = Path(member.filename)
                    if relative.is_absolute() or ".." in relative.parts or len(relative.parts) != 1:
                        raise SystemExit(f"Unexpected Maude archive path: {relative}")
                    if member.is_dir():
                        continue
                    (destination / relative).write_bytes(archive.read(member))
            (destination / "maude").chmod(0o755)
        print(f"Ready: {name} {pin['version']} (SHA-256 verified)")
    if not os.access(ROOT / ".tools/bin/tamarin-prover", os.X_OK):
        raise SystemExit("Tamarin executable is unavailable")


if __name__ == "__main__":
    install()
