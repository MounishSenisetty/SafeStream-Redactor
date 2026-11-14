#!/usr/bin/env bash
# Build the IJIS manuscript, Online Resource 1 and the cover letter, check the logs,
# and write the upload package to submission/ (ignored by git).
set -euo pipefail
cd "$(dirname "$0")"

latex() { pdflatex -no-shell-escape -interaction=nonstopmode -halt-on-error "$1" >/dev/null; }

check() {  # fail on errors, undefined references, bad boxes or a pending rerun
  local log="$1.log"
  if grep -nE '^!|Undefined|undefined|Overfull|Underfull|Rerun to get' "$log" \
      | grep -v 'rerunfilecheck'; then
    echo "problems in $log" >&2
    exit 1
  fi
}

rm -f main.aux main.bbl
latex main; bibtex main >/dev/null; latex main; latex main; check main
for doc in supplementary cover_letter; do latex "$doc"; latex "$doc"; check "$doc"; done

out=submission
rm -rf "$out"; mkdir -p "$out"
cp main.pdf supplementary.pdf cover_letter.pdf "$out/"
zip -q -j "$out/source.zip" main.tex main.bbl refs.bib sn-jnl.cls sn-mathphys-num.bst \
  fig_architecture.pdf fig_memory.pdf

# the source package must build on its own
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
unzip -q "$out/source.zip" -d "$tmp"
(cd "$tmp" && latex main && latex main && check main)

for f in main supplementary cover_letter; do
  printf '%-16s %s pages\n' "$f.pdf" "$(pdfinfo "$f.pdf" 2>/dev/null | awk '/^Pages/{print $2}')"
done
rm -f ./*.aux ./*.log ./*.blg ./*.out ./*.spl
echo "upload package: $(pwd)/$out"
