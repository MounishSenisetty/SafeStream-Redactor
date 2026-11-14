"""Audit the Loghub template-slot labels against the values the slots actually hold.

Independent of the person who checked the labels: for every slot of every template
(OpenSSH and Linux), it collects the values the slot takes in the real lines and
flags any contradiction with its label. A slot labelled HOST must hold IP addresses
or host names; a slot labelled USER must hold account-name-shaped values (no
whitespace, not an IP address, not purely numeric); an unlabelled slot that ever
holds an IP address, or that sits where the documented sshd/PAM formats put an
account name, is a candidate missed label. Writes a JSON report.

    python -m benchmarks.loghub_label_audit --json out.json
"""

from __future__ import annotations

import argparse
import csv
import ipaddress
import json
import re
from collections import defaultdict
from pathlib import Path
from typing import Any

from benchmarks import corpora

_HOSTNAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?(?:\.[A-Za-z0-9-]+)+$")
_NAME = re.compile(r"^[^\s]{1,64}$")
# where the documented formats put an account name (before the slot)
_USER_CUE = re.compile(
    r"(?:for(?: invalid| illegal)? user|[Ii]nvalid user|[Ii]llegal user|for|user=|logname=|"
    r"ruser=|session (?:opened|closed) for user|by|LOGIN ON \S+ BY|FOR|\(to \S+\)|User)\s?$"
)


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def audit(system: str, labels: dict[str, Any]) -> dict[str, Any]:
    d = corpora.EXTERNAL / "loghub" / system
    with (d / f"{system}_2k.log_structured.csv").open(
        encoding="utf-8", errors="replace", newline=""
    ) as f:
        rows = list(csv.DictReader(f))
    values: dict[tuple[str, int], list[str]] = defaultdict(list)
    templates: dict[str, str] = {}
    for row in rows:
        tpl = row["EventTemplate"]
        templates[row["EventId"]] = tpl
        rx = re.escape(tpl).replace(re.escape("<*>"), "(.*?)")
        m = re.fullmatch(rx, row["Content"])
        if m:
            for k, v in enumerate(m.groups(), 1):
                values[(row["EventId"], k)].append(v)
    problems, checked = [], 0
    for (tid, k), vals in sorted(values.items()):
        checked += 1
        slots = (labels.get(tid) or {}).get("slots", [])
        label = slots[k - 1] if k - 1 < len(slots) else None
        before = templates[tid].split("<*>")[k - 1]
        ips = sum(_is_ip(v) for v in vals)
        if label == "HOST":
            bad = [v for v in vals if not (_is_ip(v) or _HOSTNAME.match(v))]
            if bad:
                problems.append(
                    {
                        "template": tid,
                        "slot": k,
                        "label": "HOST",
                        "issue": "values that are neither IPs nor host names",
                        "examples": sorted(set(bad))[:5],
                        "count": len(bad),
                    }
                )
        elif label == "USER":
            bad = [v for v in vals if not _NAME.match(v) or _is_ip(v) or v.isdigit()]
            if bad:
                problems.append(
                    {
                        "template": tid,
                        "slot": k,
                        "label": "USER",
                        "issue": "values not shaped like account names",
                        "examples": sorted(set(bad))[:5],
                        "count": len(bad),
                    }
                )
        else:
            if ips:
                problems.append(
                    {
                        "template": tid,
                        "slot": k,
                        "label": None,
                        "issue": "unlabelled slot holds IP addresses",
                        "examples": sorted(set(v for v in vals if _is_ip(v)))[:5],
                        "count": ips,
                    }
                )
            elif (
                _USER_CUE.search(before)
                and all(_NAME.match(v) for v in vals)
                and not all(v.isdigit() for v in vals)
            ):
                problems.append(
                    {
                        "template": tid,
                        "slot": k,
                        "label": None,
                        "issue": "unlabelled slot after an account-name cue",
                        "context": before[-40:],
                        "examples": sorted(set(vals))[:5],
                        "count": len(vals),
                    }
                )
    return {"system": system, "slots_checked": checked, "lines": len(rows), "flags": problems}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    out = []
    for system, path in (("OpenSSH", corpora.LOGHUB_SLOTS), ("Linux", corpora.LOGHUB_SLOTS_LINUX)):
        labels = json.loads(path.read_text(encoding="utf-8"))[system]
        res = audit(system, labels)
        out.append(res)
        print(f"{system}: {res['slots_checked']} slots, {len(res['flags'])} flagged")
        for p in res["flags"]:
            print(
                "  ",
                p["template"],
                p["slot"],
                p["label"],
                p["issue"],
                p.get("context", ""),
                p["examples"],
            )
    args.json.write_text(json.dumps(out, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
