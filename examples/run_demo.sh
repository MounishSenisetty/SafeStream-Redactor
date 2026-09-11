#!/usr/bin/env bash
#
# SafeStream-Redactor — one-command feature demo.
#
# Runs the whole feature surface against a small, self-generated sample so a
# reviewer can see everything working without downloading a corpus or wiring up
# anything. No network access is required and no real secrets are used — every
# value below is a canonical fake/example constant.
#
#   Usage:
#     examples/run_demo.sh          # the fast feature tour (default)
#     examples/run_demo.sh --bench  # also generate a tiny corpus + run the benchmark
#
# The companion four-method walkthrough (PyPI / clone / Docker / REST API,
# datasets and benchmarks in full) lives in docs/DEMO.md.

set -euo pipefail

# ---------------------------------------------------------------------------
# Resolve how to invoke the tool: prefer the installed `safestream` console
# script, fall back to `python -m safestream_redactor` from a clone.
# ---------------------------------------------------------------------------
if command -v safestream >/dev/null 2>&1; then
    SS=(safestream)
elif python -c "import safestream_redactor" >/dev/null 2>&1; then
    SS=(python -m safestream_redactor)
else
    echo "error: safestream is not installed. Run 'pip install safestream-redactor'" >&2
    echo "       or, from a clone, 'pip install -e .'." >&2
    exit 1
fi

# Repo root (this script lives in examples/), used to find examples/policy.toml.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# Scratch workspace, cleaned up on exit.
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

hr()  { printf '\n\033[1;36m== %s\033[0m\n' "$*"; }
run() { printf '\033[0;90m$ %s\033[0m\n' "$*"; }

echo "SafeStream-Redactor demo — using: ${SS[*]}"
"${SS[@]}" --version

# ---------------------------------------------------------------------------
# A tiny sample containing one of each major entity type, plus a benign
# "test" line to show contextual suppression. All values are fake examples.
# ---------------------------------------------------------------------------
SAMPLE="$WORK/sample.txt"
cat > "$SAMPLE" <<'EOF'
Customer Maria Garcia <maria.garcia@corpmail.com> called from +1 415 555 0132.
Card on file 4111 1111 1111 1111, SSN 123-45-6789, last login from 10.20.30.40 (v6 2001:db8::8a2e:370:7334).
Deploy creds: AWS AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
GitHub token ghp_1234567890abcdefghijklmnopqrstuvwxyz, Slack xoxb-1234-5678-abcdefghijklmnop, Stripe sk_live_1234567890abcdefghijklmnop.
Session jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U
Internal ref ProjectFalcon, employee EMP-40921.
NOTE: this is a test example value: 123-45-0000 should be suppressed by context.
EOF

hr "The sample input"
cat "$SAMPLE"

hr "1. detect — list every detection as JSON (nothing is redacted)"
run "${SS[*]} detect \"\$SAMPLE\" --json"
"${SS[@]}" detect "$SAMPLE" --json

hr "2. redact — default (replace matches with [REDACTED])"
run "${SS[*]} redact \"\$SAMPLE\" -o -"
"${SS[@]}" redact "$SAMPLE" -o -

hr "3. redact --mode mask --keep-last 4 (keep the trailing 4 chars visible)"
run "${SS[*]} redact \"\$SAMPLE\" -o - --mode mask --keep-last 4"
"${SS[@]}" redact "$SAMPLE" -o - --mode mask --keep-last 4

hr "4. redact --mode pseudonymize (deterministic keyed tokens — same in == same token)"
run "${SS[*]} redact \"\$SAMPLE\" -o - --mode pseudonymize --hmac-key demo-key"
"${SS[@]}" redact "$SAMPLE" -o - --mode pseudonymize --hmac-key demo-key

hr "5. per-type replacement + type filter (only emails and SSNs, custom labels)"
run "${SS[*]} redact \"\$SAMPLE\" -o - --types email,ssn --replace-type email='<EMAIL>' --replace-type ssn='<SSN>'"
"${SS[@]}" redact "$SAMPLE" -o - --types email,ssn \
    --replace-type "email=<EMAIL>" --replace-type "ssn=<SSN>"

hr "6. custom word + custom regex (redact a codename and an employee-id format)"
run "${SS[*]} redact \"\$SAMPLE\" -o - --custom-word ProjectFalcon --custom-regex 'EMP-[0-9]+'"
"${SS[@]}" redact "$SAMPLE" -o - --custom-word ProjectFalcon --custom-regex 'EMP-[0-9]+'

hr "7. TOML policy file (a policy drives detection + redaction from config)"
# A self-contained, NER-free policy so this step runs on the core install.
# The fuller examples/policy.toml additionally enables the spaCy NER tier
# (needs the [ner] extra) and ships more custom patterns — see docs/DEMO.md.
DEMO_POLICY="$WORK/demo-policy.toml"
cat > "$DEMO_POLICY" <<'EOF'
[detection]
types = ["email", "ssn", "credit_card", "aws_key", "github_token"]
min_confidence = 0.5
use_entropy = true
use_ner = false

[redaction]
mode = "mask"
mask_char = "#"
mask_keep_last = 4

[redaction.replacements]
email = "<EMAIL-REMOVED>"

[custom]
patterns = ["EMP-[0-9]+"]
EOF
run "${SS[*]} redact \"\$SAMPLE\" -o - --config demo-policy.toml"
echo "--- policy used ---"; cat "$DEMO_POLICY"; echo "--- output ---"
"${SS[@]}" redact "$SAMPLE" -o - --config "$DEMO_POLICY"

hr "8. streaming through a pipe (stdin '-' to stdout '-')"
run "cat \"\$SAMPLE\" | ${SS[*]} redact - -o -"
cat "$SAMPLE" | "${SS[@]}" redact - -o -

hr "9. --stats + content-free JSON run report (counts and sizes only, never matched text)"
run "${SS[*]} redact \"\$SAMPLE\" -o \"\$WORK/out.txt\" --stats --report \"\$WORK/report.json\""
"${SS[@]}" redact "$SAMPLE" -o "$WORK/out.txt" --stats --report "$WORK/report.json"
echo "--- report.json ---"
cat "$WORK/report.json"; echo

hr "10. detect --fail-on-detect (CI / pre-commit secret gate: non-zero exit on any hit)"
run "${SS[*]} detect \"\$SAMPLE\" --fail-on-detect ; echo \"exit=\$?\""
set +e
"${SS[@]}" detect "$SAMPLE" --fail-on-detect >/dev/null 2>&1
echo "exit status = $?   (non-zero because secrets were found — the gate works)"
set -e

hr "11. init-config — emit a documented, schema-validated starter policy"
run "${SS[*]} init-config -o \"\$WORK/starter-policy.toml\""
"${SS[@]}" init-config -o "$WORK/starter-policy.toml"
echo "wrote $WORK/starter-policy.toml ($(wc -l < "$WORK/starter-policy.toml") lines)"

hr "12. MCP server (for AI agents) — stdio JSON-RPC 2.0, secret never crosses the tool boundary"
run "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{\"name\":\"scan\",...}}' | ${SS[*]} mcp-serve"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"scan","arguments":{"text":"key AKIAIOSFODNN7EXAMPLE ssn 123-45-6789"}}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"redact","arguments":{"text":"key AKIAIOSFODNN7EXAMPLE ssn 123-45-6789"}}}' \
  | "${SS[@]}" mcp-serve 2>/dev/null
echo "(scan returns type/offsets/severity only — never the secret; redact returns text with secrets removed)"

# ---------------------------------------------------------------------------
# Optional: generate a tiny corpus and run the regression benchmark. Skipped
# unless --bench is passed and the benchmark scripts are present (i.e. a clone).
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--bench" ]; then
    if [ -f "$REPO_ROOT/benchmarks/generate_dataset.py" ]; then
        hr "13. benchmark — generate a small labeled corpus, then score the detector"
        run "python benchmarks/generate_dataset.py --size-mb 1 --out \"\$WORK/data\""
        python "$REPO_ROOT/benchmarks/generate_dataset.py" --size-mb 1 --out "$WORK/data"
        run "python benchmarks/run_benchmark.py --data \"\$WORK/data\""
        python "$REPO_ROOT/benchmarks/run_benchmark.py" --data "$WORK/data"
    else
        echo "(--bench requested but benchmarks/ is not present; run from a git clone)" >&2
    fi
fi

hr "Done"
echo "Full five-method walkthrough (PyPI / clone / Docker / REST API / MCP server),"
echo "optional native + ONNX tiers, dataset generation, and benchmarks: docs/DEMO.md"
