#!/bin/bash
# Updates the ciphertrust provider version pin (the `version = "..."` line
# in each required_providers block) across every main.tf under sample-scripts/.
set -euo pipefail

SAMPLE_SCRIPTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

read -rp "Enter the ciphertrust provider version to set (e.g. 1.0.1): " NEW_VERSION
if [ -z "$NEW_VERSION" ]; then
  echo "No version entered, aborting." >&2
  exit 1
fi

mapfile -t FILES < <(find "$SAMPLE_SCRIPTS_DIR" -name "main.tf" | sort)

if [ "${#FILES[@]}" -eq 0 ]; then
  echo "No main.tf files found under $SAMPLE_SCRIPTS_DIR." >&2
  exit 1
fi

updated=0
for f in "${FILES[@]}"; do
  tmp="$(mktemp)"
  awk -v ver="$NEW_VERSION" '
    tolower($0) ~ /^[[:space:]]*source[[:space:]]*=[[:space:]]*"[^"]*ciphertrust[^"]*"/ {
      after_source = 1
      print
      next
    }
    after_source && /^[[:space:]]*version[[:space:]]*=[[:space:]]*"[^"]*"/ {
      sub(/version[[:space:]]*=[[:space:]]*"[^"]*"/, "version = \"" ver "\"")
      print
      after_source = 0
      next
    }
    { print }
  ' "$f" >"$tmp"

  if ! cmp -s "$f" "$tmp"; then
    mv "$tmp" "$f"
    updated=$((updated + 1))
  else
    rm -f "$tmp"
  fi
done

echo "Updated $updated file(s) to version \"$NEW_VERSION\"."
