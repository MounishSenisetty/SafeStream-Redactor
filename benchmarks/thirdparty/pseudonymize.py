"""Replace third-party tool names in an audit result with stable pseudonyms (T1, T2, ...).

The study's disclosure rule (paper/conference/PROTOCOL.md, Amendment 1): a tool is
named alongside a finding only after its maintainers have been told privately. Until
then, results are committed under pseudonyms, and the mapping lives only in the
git-ignored install folder.

    python -m benchmarks.thirdparty.pseudonymize RAW.json OUT.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MAPPING = ROOT / "benchmarks" / "data" / "external" / "mcp_servers" / "PSEUDONYMS.json"
KEEP = {"safestream"}  # the authors' own tool is always named
# tool function names identify a product too; third-party tools get role labels
ROLE = {
    "sanitize_text": "anonymize",
    "anonymize_text": "anonymize",
    "analyze_text": "detect",
    "scan_text": "detect",
    "reveal_text": "restore",
    "deanonymize_text": "restore",
    "get_mapping": "mapping",
    "analyze_structured_data": "detect_structured",
    "anonymize_structured_data": "anonymize_structured",
}


def mapping(names: list[str]) -> dict[str, str]:
    known: dict[str, str] = json.loads(MAPPING.read_text()) if MAPPING.exists() else {}
    for n in sorted(set(names) - KEEP - set(known)):
        known[n] = f"T{len(known) + 1}"
    MAPPING.write_text(json.dumps(known, indent=1) + "\n")
    return known


def scrub(text: str, names: dict[str, str], extra: dict[str, str]) -> str:
    for real, alias in sorted({**names, **extra}.items(), key=lambda kv: -len(kv[0])):
        text = text.replace(real, alias)
    return text


def main() -> None:
    src, dst = Path(sys.argv[1]), Path(sys.argv[2])
    data = json.loads(src.read_text())
    servers = {k.split("|")[0] for k in data["results"]}
    names = mapping(sorted(servers))
    # identifying strings that would reveal a tool: its source, version and packages
    extra: dict[str, str] = {"entityMap": "value_map"}  # a field name unique to one tool
    if any(k.endswith(("|injected", "|benign")) for k in data["results"]):
        # agent experiment (C-RQ6): per-run records name the tools the agent was given
        for key, summary in data["results"].items():
            for run in summary.get("per_run", []):
                tools = run.pop("tools_exposed", [])
                if key.split("|")[0] not in KEEP:
                    run["tools_exposed_roles"] = sorted({ROLE.get(t, "other") for t in tools})
        dst.write_text(scrub(json.dumps(data, indent=1), names, extra) + "\n")
        print(f"wrote {dst}: {', '.join(sorted(names.values()))}")
        return
    for key, rep in data["results"].items():
        if key.split("|")[0] in KEEP:
            continue
        rep.pop("tools_listed", None)
        rep["tools_audited"] = {ROLE.get(t, t): a for t, a in rep.get("tools_audited", {}).items()}
        rep["results"] = {ROLE.get(t, t): r for t, r in rep.get("results", {}).items()}
        if "restore" in rep:
            rec = rep["restore"]["recovered"]
            rep["restore"]["recovered"] = {ROLE.get(t, t): v for t, v in rec.items()}
        s = rep.get("server", {})
        alias = names.get(key.split("|")[0])
        if alias:
            for field in ("source", "version"):
                if s.get(field):
                    extra[s[field]] = f"{alias} ({field} withheld)"
    dst.write_text(scrub(json.dumps(data, indent=1), names, extra) + "\n")
    print(f"wrote {dst}: {', '.join(f'{v}' for v in sorted(names.values()))}")


if __name__ == "__main__":
    main()
