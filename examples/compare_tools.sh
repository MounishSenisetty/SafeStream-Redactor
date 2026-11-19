#!/usr/bin/env bash
# Run gitleaks, TruffleHog, Presidio and SafeStream on the same files, side by side.
#
#   python examples/make_demo_logs.py          # fake logs in demo_logs/
#   examples/compare_tools.sh                  # every log in demo_logs/
#   examples/compare_tools.sh demo_logs/prod.env
#
# Needs on PATH: safestream, gitleaks (v8.19+), trufflehog (v3), and for Presidio
#   pip install presidio-analyzer presidio-anonymizer && python -m spacy download en_core_web_lg
# A missing tool is reported as "not installed" and skipped, never faked.
# TruffleHog runs with --no-verification: no key is ever sent to a provider.
set -uo pipefail

files=("$@")
[ ${#files[@]} -eq 0 ] && files=(demo_logs/*.log demo_logs/*.jsonl demo_logs/*.env)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

# Findings in a JSON array or JSON-lines report: the total, then the commonest types.
count() { python3 -c 'import json,sys,collections
t=open(sys.argv[1]).read().strip()
rows=[] if not t else json.loads(t) if t[0]=="[" else [json.loads(x) for x in t.splitlines()]
kinds=collections.Counter(r.get("RuleID") or r.get("DetectorName") or r.get("type") for r in rows)
print(f"{len(rows):6} findings  ", ", ".join(f"{k}={n}" for k,n in kinds.most_common(5)))' "$1"; }

# run NAME NEEDS CMD... : skip if NEEDS is missing, else time CMD and summarise its report.
run() {
  local name=$1 needs=$2; shift 2
  if ! eval "$needs" >/dev/null 2>&1; then printf '  %-11s not installed\n' "$name"; return; fi
  local t0=$(date +%s.%N)
  "$@" >"$tmp/out" 2>"$tmp/err" || { printf '  %-11s failed: %s\n' "$name" "$(head -c 200 "$tmp/err")"; return; }
  local secs=$(python3 -c "print(f'{$(date +%s.%N)-$t0:6.2f}')")
  printf '  %-11s %ss %s\n' "$name" "$secs" "$(count "$tmp/report")"
}

presidio() {  # writes findings to $tmp/report and the anonymized text to $tmp/presidio.txt
  python3 - "$1" "$tmp" <<'EOF'
import json, sys
from presidio_analyzer import AnalyzerEngine
from presidio_anonymizer import AnonymizerEngine
text = open(sys.argv[1], encoding="utf-8").read()
analyzer = AnalyzerEngine()
analyzer.nlp_engine.nlp["en"].max_length = max(len(text) + 1, 1_000_000)
results = analyzer.analyze(text=text, language="en")
json.dump([{"type": r.entity_type, "start": r.start, "end": r.end} for r in results],
          open(f"{sys.argv[2]}/report", "w"))
open(f"{sys.argv[2]}/presidio.txt", "w").write(AnonymizerEngine().anonymize(text=text, analyzer_results=results).text)
EOF
}

for f in "${files[@]}"; do
  [ -f "$f" ] || continue
  echo "== $f ($(wc -c <"$f") bytes)"
  run gitleaks   'command -v gitleaks'   bash -c 'gitleaks dir "$1" --report-format json --report-path "$2/report" --no-banner --log-level error --exit-code 0' _ "$f" "$tmp"
  run trufflehog 'command -v trufflehog' bash -c 'trufflehog filesystem "$1" --json --no-verification --no-update --log-level=-1 >"$2/report"' _ "$f" "$tmp"
  run presidio   'python3 -c "import presidio_analyzer"' presidio "$f"
  run safestream 'command -v safestream' bash -c 'safestream detect "$1" --json >"$2/report"' _ "$f" "$tmp"
done

# The difference a detector count cannot show: who hands you a redacted file.
f=${files[0]}
echo
echo "== Redacted output of $f (first 5 lines)"
echo "-- gitleaks / trufflehog: detect only, no redacted output"
if presidio "$f" 2>/dev/null; then echo "-- presidio"; head -5 "$tmp/presidio.txt"; else echo "-- presidio: unavailable (see above)"; fi
if command -v safestream >/dev/null; then echo "-- safestream"; safestream redact "$f" -o - | head -5; fi
