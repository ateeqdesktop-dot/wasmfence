import json
from pathlib import Path

from wasmfence import audit, parse, to_sarif

R = Path(__file__).parents[1]


def test_policy():
    result = audit(parse(R / "fixtures/module.wat"), json.loads((R / "fixtures/policy.json").read_text()))
    assert [item["code"] for item in result["findings"]] == ["WF001"]
    assert result["schema_version"] == 2


def test_forbidden_namespace_and_export_surface():
    result = audit({"imports": [{"module": "wasi_snapshot_preview1", "name": "fd_write"}], "exports": ["debug"]}, {"forbidden_modules": ["wasi_snapshot_preview1"], "allowed_exports": ["run"]})
    assert {item["code"] for item in result["findings"]} == {"WF004", "WF005"}


def test_json_manifest_parse():
    path = R / "fixtures" / "manifest.json"
    parsed = parse(path)
    assert parsed["imports"][0]["module"] == "env"
    assert parsed["exports"] == ["run"]


def test_sarif_contract():
    sarif = to_sarif(audit({"imports": [], "exports": []}, {}))
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "WasmFence"


def test_size(tmp_path):
    path = tmp_path / "x.wat"
    path.write_text("x" * (10 * 1024 * 1024))
    try:
        parse(path)
        assert False
    except ValueError:
        pass
