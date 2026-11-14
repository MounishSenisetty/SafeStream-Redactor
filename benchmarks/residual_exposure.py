"""Residual exposure through ``redact``: what an agent still sees after redaction.

For each redaction mode and corpus, the share of gold values (at least 4 characters)
that still appear verbatim in the redacted text returned to the agent, next to the
share of gold values not fully covered by any detection (``1 - covered recall``).
For replace, hash, pseudonymize, encrypt and fictionalize the two should agree: a
value leaks only if detection misses it. For mask, the number of characters of
covered values left visible (the kept suffix) is reported as well.

    python -m benchmarks.residual_exposure --corpus agent_traces wnut17 --json out.json
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from benchmarks import corpora
from benchmarks.policy_overhead import MODES, policy

MIN_LEN = 4


def exposure(docs: list[corpora.Doc], tiers: dict[str, Any]) -> dict[str, Any]:
    from safestream_redactor import Redactor

    base = Redactor(load_plugins=False, backend="native", **tiers)
    dets = [base.detect(d.text) for d in docs]
    values = 0
    uncovered = 0
    for d, ds in zip(docs, dets, strict=True):
        mask = bytearray(len(d.text))
        for x in ds:
            mask[x.start : x.end] = b"\x01" * (x.end - x.start)
        for g in d.spans:
            if g.end - g.start >= MIN_LEN:
                values += 1
                uncovered += not all(mask[g.start : g.end])
    out: dict[str, Any] = {"values": values, "not_fully_covered": uncovered / max(1, values)}
    for mode in MODES:
        pol = policy(mode)
        verbatim = 0
        for d, ds in zip(docs, dets, strict=True):
            red = pol.apply(d.text, ds)
            verbatim += sum(
                1 for g in d.spans if g.end - g.start >= MIN_LEN and d.text[g.start : g.end] in red
            )
        out[mode] = verbatim / max(1, values)
    # mask: characters of fully covered gold values shown by the kept suffix
    shown = total = 0
    pol = policy("mask")
    for d, ds in zip(docs, dets, strict=True):
        for x in ds:
            n = x.end - x.start
            keep = min(max(0, pol.mask_keep_last), n // 2)
            for g in d.spans:
                if x.start <= g.start and g.end <= x.end:
                    total += g.end - g.start
                    shown += max(0, min(g.end, x.end) - max(g.start, x.end - keep))
    out["mask_visible_char_share_of_covered_values"] = shown / max(1, total)
    return out


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--corpus", nargs="+", required=True)
    ap.add_argument("--split", default="test")
    ap.add_argument("--json", type=Path, required=True)
    args = ap.parse_args()
    from benchmarks.mcp_egress_audit import TIERS

    report: dict[str, Any] = {"min_len": MIN_LEN, "results": {}}
    for tier in ("pattern", "onnx"):
        for name in args.corpus:
            split = "all" if name == "agent_traces" else args.split
            res = exposure(corpora.load(name, split).docs, TIERS[tier])
            report["results"][f"{tier}|{name}"] = res
            print(
                tier, name, {k: round(v, 4) if isinstance(v, float) else v for k, v in res.items()}
            )
    args.json.parent.mkdir(parents=True, exist_ok=True)
    args.json.write_text(json.dumps(report, indent=1) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
