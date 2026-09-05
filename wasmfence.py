from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

MAX_BYTES = 10 * 1024 * 1024


def parse(path: Path) -> dict[str, Any]:
    if path.stat().st_size >= MAX_BYTES:
        raise ValueError("module exceeds 10 MiB")
    if path.suffix.lower() == ".json":
        document = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(document, dict) or not isinstance(document.get("imports"), list) or not isinstance(document.get("exports"), list):
            raise ValueError("manifest must contain imports and exports arrays")
        return {"imports": document["imports"], "exports": sorted({str(item) for item in document["exports"]})}
    text = path.read_text(encoding="utf-8")
    imports = [{"module": match.group(1), "name": match.group(2)} for match in re.finditer(r'\(import\s+"([^"]+)"\s+"([^"]+)"', text)]
    exports = sorted({match.group(1) for match in re.finditer(r'\(export\s+"([^"]+)"', text)})
    return {"imports": imports, "exports": exports}


def finding(code: str, severity: str, location: str, message: str) -> dict[str, str]:
    fingerprint = hashlib.sha256(f"{code}|{location}|{message}".encode()).hexdigest()[:16]
    return {"code": code, "severity": severity, "location": location, "message": message, "fingerprint": fingerprint}


def audit(module: dict[str, Any], policy: dict[str, Any]) -> dict[str, Any]:
    findings: list[dict[str, str]] = []
    allowed = {str(item) for item in policy.get("allowed_imports", [])}
    forbidden_modules = {str(item) for item in policy.get("forbidden_modules", [])}
    required = {str(item) for item in policy.get("required_exports", [])}
    allowed_exports = {str(item) for item in policy.get("allowed_exports", [])}
    max_imports = int(policy.get("max_imports", 32))
    for index, item in enumerate(module["imports"]):
        if not isinstance(item, dict) or not isinstance(item.get("module"), str) or not isinstance(item.get("name"), str):
            findings.append(finding("WF000", "high", f"imports[{index}]", "import declaration must contain module and name"))
            continue
        reference = f"{item['module']}.{item['name']}"
        if item["module"] in forbidden_modules:
            findings.append(finding("WF004", "critical", f"imports[{index}]", f"import namespace is forbidden: {item['module']}"))
        elif reference not in allowed:
            findings.append(finding("WF001", "high", f"imports[{index}]", f"capability import is not allowed: {reference}"))
    for name in sorted(required - set(module["exports"])):
        findings.append(finding("WF002", "high", "exports", f"required export is missing: {name}"))
    if allowed_exports:
        for name in sorted(set(module["exports"]) - allowed_exports):
            findings.append(finding("WF005", "medium", "exports", f"export is not in the public interface: {name}"))
    if len(module["imports"]) > max_imports:
        findings.append(finding("WF003", "medium", "imports", f"import surface exceeds {max_imports}"))
    findings.sort(key=lambda item: (item["code"], item["location"], item["fingerprint"]))
    return {"schema_version": 2, "imports": module["imports"], "exports": module["exports"], "findings": findings}


def to_sarif(report: dict[str, Any]) -> dict[str, Any]:
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "WasmFence", "version": "1.0.0"}}, "results": [{"ruleId": item["code"], "level": "error" if item["severity"] in {"critical", "high"} else "warning", "message": {"text": item["message"]}, "properties": {"location": item["location"], "fingerprint": item["fingerprint"]}} for item in report["findings"]]}]}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Audit WebAssembly capability imports and exports without executing the module")
    parser.add_argument("module", type=Path)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--format", choices=["json", "markdown", "sarif"], default="markdown")
    args = parser.parse_args(argv)
    try:
        report = audit(parse(args.module), json.loads(args.policy.read_text(encoding="utf-8")))
    except (OSError, ValueError, json.JSONDecodeError, TypeError) as exc:
        print(f"WasmFence error: {exc}", file=sys.stderr)
        return 2
    if args.format == "json":
        print(json.dumps(report, indent=2, sort_keys=True))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(report), indent=2, sort_keys=True))
    else:
        print(f"# WasmFence\n\nImports: **{len(report['imports'])}** | Exports: **{len(report['exports'])}** | Findings: **{len(report['findings'])}**\n\n| Code | Severity | Message |\n|---|---|---|")
        for item in report["findings"]:
            print(f"| `{item['code']}` | {item['severity']} | {item['message']} |")
    return 1 if report["findings"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
