#!/usr/bin/env bash
# Build every wrapper of a paper, normal and anonymous, check the logs, and write a
# self-contained source zip per build.
#
#   paper/make_submission.sh journal            # every wrapper
#   paper/make_submission.sh conference generic # one wrapper
#
# Output: paper/<paper>/build/<wrapper>[-anon]/{main.pdf,main.log,source.zip} and a
# summary table. Fails on a LaTeX error or an undefined reference or citation.
# Overfull boxes are counted and reported, not fatal: a class other than the one
# chosen for submission may set a table wider than its text block.
set -euo pipefail
cd "$(dirname "$0")/$1"
paper=$(pwd)
shift
wrappers=("$@")
[ ${#wrappers[@]} -eq 0 ] && wrappers=($(ls wrappers/*.tex | xargs -n1 basename | sed 's/\.tex$//'))
export TEXINPUTS="$paper:$paper/wrappers:" BIBINPUTS="$paper:" BSTINPUTS="$paper:$paper/wrappers:"
status=0
printf '%-24s %-6s %6s %9s %9s %s\n' wrapper blind pages overfull undefined result
for w in "${wrappers[@]}"; do
  for anon in 0 1; do
    name=$w; pre=""
    if [ $anon = 1 ]; then name=$w-anon; pre='\def\anonymousbuild{}'; fi
    out=build/$name; rm -rf "$out"; mkdir -p "$out"
    latex() { pdflatex -interaction=nonstopmode -halt-on-error -jobname=main \
      -output-directory="$out" "$pre\\input{wrappers/$w.tex}" >/dev/null 2>&1; }
    result=ok
    if latex && (cd "$out" && bibtex main >/dev/null 2>&1) && latex && latex; then
      log=$out/main.log
      undef=$(grep -cE "Warning: (Reference|Citation) .* undefined|There were undefined" "$log" || true)
      over=$(grep -c "^Overfull" "$log" || true)
      pages=$(grep -oE "Output written on .* \(([0-9]+) page" "$log" | grep -oE "[0-9]+ page" | cut -d' ' -f1)
      [ "$undef" != 0 ] && { result=UNDEFINED; status=1; }
      # self-contained source: the wrapper as main.tex at the root, with what it inputs
      src=$(mktemp -d)
      cp "wrappers/$w.tex" "$src/main.tex"
      if [ $anon = 1 ]; then
        { printf '%s\n' '\def\anonymousbuild{}'; cat "wrappers/$w.tex"; } > "$src/main.tex"
      fi
      cp -r content figures meta.tex refs.bib "$src/"
      cp "$out/main.bbl" "$src/"
      find . -maxdepth 1 \( -name '*.cls' -o -name '*.bst' -o -name '*.sty' \) \
        -exec cp {} "$src/" \;
      (cd "$src" && rm -f figures/*.tex && zip -qr "$paper/$out/source.zip" .)
      # the zip must build on its own (no TEXINPUTS help)
      if ! (cd "$src" && env -u TEXINPUTS -u BIBINPUTS -u BSTINPUTS \
            pdflatex -interaction=nonstopmode -halt-on-error main.tex >/dev/null 2>&1); then
        result=ZIP-FAILS; status=1
      fi
      rm -rf "$src"
    else
      result=ERROR; status=1; undef=-; over=-; pages=-
    fi
    printf '%-24s %-6s %6s %9s %9s %s\n' "$w" "$anon" "$pages" "$over" "$undef" "$result"
  done
done
# the supplement (if any) is a plain article of its own: normal and anonymous
if [ -f supplementary.tex ]; then
  for anon in 0 1; do
    pre=""; name=supplement; [ $anon = 1 ] && { pre='\def\anonymousbuild{}'; name=supplement-anon; }
    out=build/$name; rm -rf "$out"; mkdir -p "$out"
    sup() { pdflatex -interaction=nonstopmode -halt-on-error -jobname=supplementary \
      -output-directory="$out" "$pre\\input{supplementary.tex}" >/dev/null 2>&1; }
    if sup && sup; then
      over=$(grep -c "^Overfull" "$out/supplementary.log" || true)
      undef=$(grep -cE "Warning: (Reference|Citation) .* undefined" "$out/supplementary.log" || true)
      pages=$(grep -oE "\(([0-9]+) page" "$out/supplementary.log" | grep -oE "[0-9]+")
      r=ok; [ "$undef" != 0 ] && { r=UNDEFINED; status=1; }
      printf '%-24s %-6s %6s %9s %9s %s\n' supplement "$anon" "$pages" "$over" "$undef" "$r"
    else
      printf '%-24s %-6s %6s %9s %9s %s\n' supplement "$anon" - - - ERROR; status=1
    fi
  done
fi
# main.tex is the single-file copy for Overleaf (paper/flatten.py); it must match the sources
if ! python3 ../flatten.py "$(basename "$paper")" --check >/dev/null; then
  echo "main.tex is out of date: run python paper/flatten.py $(basename "$paper")"; status=1
fi
exit $status
