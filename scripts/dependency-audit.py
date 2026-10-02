#!/usr/bin/env python3
"""Generate a small CycloneDX SBOM and audit licenses for Go modules."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import subprocess
import sys
import uuid

LICENSE_NAMES = ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING", "COPYING.txt", "NOTICE")


def read_modules(root: pathlib.Path) -> list[dict]:
    raw = subprocess.check_output(
        ["go", "list", "-m", "-json", "all"], cwd=root, text=True
    )
    decoder = json.JSONDecoder()
    modules: list[dict] = []
    index = 0
    while index < len(raw):
        while index < len(raw) and raw[index].isspace():
            index += 1
        if index >= len(raw):
            break
        module, end = decoder.raw_decode(raw, index)
        modules.append(module)
        index = end
    return modules


def module_directory(root: pathlib.Path, module: dict) -> pathlib.Path:
    directory = module.get("Dir", "")
    if directory:
        return pathlib.Path(directory)
    path = module.get("Path", "")
    version = module.get("Version", "")
    if not path or not version:
        return pathlib.Path()
    try:
        downloaded = subprocess.check_output(
            ["go", "mod", "download", "-json", f"{path}@{version}"],
            cwd=root,
            text=True,
        )
        return pathlib.Path(json.loads(downloaded).get("Dir", ""))
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return pathlib.Path()


def detect_license(directory: pathlib.Path) -> tuple[str, str]:
    if not directory:
        return "NOASSERTION", "module directory unavailable"
    for name in LICENSE_NAMES:
        candidate = directory / name
        if not candidate.is_file():
            continue
        text = candidate.read_text(errors="replace")[:12000].upper()
        if "ISC LICENSE" in text:
            return "ISC", str(candidate)
        if "APACHE LICENSE" in text:
            return "Apache-2.0", str(candidate)
        if "MIT LICENSE" in text or "PERMISSION IS HEREBY GRANTED" in text:
            return "MIT", str(candidate)
        if "MOZILLA PUBLIC LICENSE" in text:
            return "MPL-2.0", str(candidate)
        if "GNU LESSER GENERAL PUBLIC LICENSE" in text:
            return "LGPL-3.0-or-later", str(candidate)
        if "GNU GENERAL PUBLIC LICENSE" in text:
            return "GPL-3.0-or-later", str(candidate)
        if "REDISTRIBUTION AND USE IN SOURCE AND BINARY FORMS" in text:
            return "BSD-3-Clause", str(candidate)
        return "NOASSERTION", str(candidate)
    return "NOASSERTION", "no recognized license file"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-dir", default="dist")
    parser.add_argument("--sbom")
    parser.add_argument("--report")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()

    output_dir = pathlib.Path(args.output_dir)
    sbom_name = args.sbom or str(output_dir / "sbom.cdx.json")
    report_name = args.report or str(output_dir / "license-audit.txt")

    root = pathlib.Path(__file__).resolve().parent.parent
    modules = read_modules(root)
    components = []
    audit_rows = []
    unknown = []
    for module in modules:
        if module.get("Main"):
            continue
        path = module.get("Path", "")
        version = module.get("Version", "")
        license_id, source = detect_license(module_directory(root, module))
        components.append(
            {
                "type": "library",
                "name": path,
                "version": version,
                "purl": f"pkg:golang/{path}@{version}",
                "licenses": [{"license": {"id": license_id}}],
            }
        )
        audit_rows.append(f"{path}\t{version}\t{license_id}\t{source}")
        if license_id == "NOASSERTION":
            unknown.append(f"{path} {version}: {license_id} ({source})")

    timestamp = dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "tools": [{"vendor": "vpnfront", "name": "dependency-audit.py", "version": "1"}],
        },
        "components": components,
    }
    sbom_path = root / sbom_name
    report_path = root / report_name
    sbom_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    sbom_path.write_text(json.dumps(sbom, indent=2) + "\n")
    report = ["module\tversion\tlicense\tsource", *sorted(audit_rows)]
    if unknown:
        report.extend(["", "UNRESOLVED_LICENSES", *sorted(unknown)])
    report_path.write_text("\n".join(report) + "\n")
    print(f"SBOM: {sbom_path}")
    print(f"License report: {report_path}")
    if args.check and unknown:
        print("license audit failed:", file=sys.stderr)
        for item in sorted(unknown):
            print(f"  {item}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
