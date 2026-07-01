#!/usr/bin/env bash
# Render a Markdown doc to PDF using `marked` (MD -> HTML) + headless Google
# Chrome (HTML -> PDF). Chosen because the guide embeds raw HTML/CSS and local
# images, which a browser renders faithfully. No pandoc/LaTeX needed.
#
# Usage:
#   scripts/render-docs-pdf.sh "docs/API Genie - The Guide.md" ["docs/RELEASE_NOTES.md" ...]
#
# The PDF is written next to the source .md (same basename). Relative image
# paths resolve because the intermediate HTML is written into the .md's own
# directory before printing, then removed.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CHROME="${CHROME:-/Applications/Google Chrome.app/Contents/MacOS/Google Chrome}"
if [ ! -x "$CHROME" ]; then
    echo "✗ Google Chrome not found at: $CHROME (set CHROME=... to override)" >&2
    exit 1
fi
command -v npx >/dev/null 2>&1 || { echo "✗ npx (Node.js) is required" >&2; exit 1; }

# Print-CSS wrapper. The guide carries its own <style> (purple accents) inline,
# which marked passes through verbatim; this template only adds page geometry
# and readable defaults so both docs render consistently.
read -r -d '' HEAD_HTML <<'HTML' || true
<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<style>
  @page { size: A4; margin: 18mm 16mm; }
  html { -webkit-print-color-adjust: exact; print-color-adjust: exact; }
  body { font-family: -apple-system, "Segoe UI", Helvetica, Arial, sans-serif;
         font-size: 10.5pt; line-height: 1.5; color: #1a1a1a; }
  h1 { font-size: 22pt; border-bottom: 2px solid #7B2FF7; padding-bottom: .2em;
       margin-top: 1.2em; page-break-before: auto; }
  h2 { font-size: 16pt; border-bottom: 1px solid #ddd; padding-bottom: .15em; margin-top: 1.1em; }
  h3 { font-size: 13pt; margin-top: 1em; }
  code, kbd, samp, pre code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 9pt; }
  pre { background: #f6f6fb; border: 1px solid #e3e3ef; border-radius: 6px;
        padding: 10px 12px; overflow-x: auto; page-break-inside: avoid; }
  code { background: #f2f0fb; padding: 1px 4px; border-radius: 4px; }
  pre code { background: none; padding: 0; }
  table { border-collapse: collapse; width: 100%; margin: 1em 0; font-size: 9.5pt; page-break-inside: avoid; }
  th, td { border: 1px solid #d8d8e0; padding: 6px 9px; text-align: left; vertical-align: top; }
  th { background: #f3eefe; }
  img { max-width: 100%; height: auto; }
  a { color: #7B2FF7; text-decoration: none; }
  blockquote { border-left: 4px solid #7B2FF7; margin: 1em 0; padding: .3em 1em; background: #faf8ff; color: #333; }
  hr { border: none; border-top: 1px solid #ddd; margin: 1.5em 0; }
</style></head><body>
HTML

render_one() {
    local md="$1"
    [ -f "$md" ] || { echo "✗ not found: $md" >&2; return 1; }
    local dir base pdf body html
    dir="$(cd "$(dirname "$md")" && pwd)"
    base="$(basename "${md%.md}")"
    pdf="$dir/$base.pdf"
    body="$dir/.$base.body.html"
    html="$dir/.$base.render.html"

    echo "→ $md"
    echo "  · marked: MD → HTML"
    npx --yes marked@12 --gfm -i "$md" -o "$body"
    echo "  · anchors: inject heading ids (clickable TOC)"
    node "$SCRIPT_DIR/add-heading-ids.mjs" "$body"

    { printf '%s\n' "$HEAD_HTML"; cat "$body"; printf '\n</body></html>\n'; } > "$html"

    echo "  · chrome: HTML → PDF"
    "$CHROME" --headless=new --disable-gpu --no-sandbox \
        --virtual-time-budget=20000 --run-all-compositor-stages-before-draw \
        --print-to-pdf="$pdf" "file://$html" >/dev/null 2>&1

    rm -f "$body" "$html"
    echo "  ✓ wrote: $pdf"
}

if [ "$#" -eq 0 ]; then
    echo "Usage: $0 <file.md> [file2.md ...]" >&2
    exit 2
fi
for f in "$@"; do render_one "$f"; done
echo "Done."
