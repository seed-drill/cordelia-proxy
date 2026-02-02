#!/usr/bin/env bash
# Secret scanner for CI and optional pre-commit use.
# Scans tracked/staged files for patterns that should never be committed.
# Exit 0 = clean, Exit 1 = secrets found.

set -euo pipefail

# Security: Use fixed, unwriteable directories only (prevents PATH injection attacks)
PATH="/usr/local/bin:/usr/bin:/bin"
export PATH

REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"

# Patterns that indicate real secrets (not references/docs/env var names)
PATTERNS=(
  '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY'
  'AKIA[0-9A-Z]{16}'                          # AWS access key
  'sk-[a-zA-Z0-9]{20,}'                       # OpenAI / Anthropic API key
  'ghp_[a-zA-Z0-9]{36}'                       # GitHub personal access token
  'ghs_[a-zA-Z0-9]{36}'                       # GitHub app token
  'xox[bprs]-[a-zA-Z0-9\-]{10,}'             # Slack token
  'password\s*[:=]\s*["\x27][^\s"'\'']{8,}'   # password = "value"
  'secret\s*[:=]\s*["\x27][^\s"'\'']{8,}'     # secret = "value"
)

# Files to skip (binary, lock files, this script itself)
EXCLUDE_PATTERNS="node_modules|dist|\.git/|package-lock\.json|\.png$|\.jpg$|\.ico$|\.woff|secret-scan\.sh"

FOUND=0

for pattern in "${PATTERNS[@]}"; do
  # Search tracked files only
  MATCHES=$(git -C "$REPO_ROOT" grep -lPi "$pattern" -- ':(exclude)node_modules' ':(exclude)dist' ':(exclude)package-lock.json' ':(exclude)scripts/secret-scan.sh' 2>/dev/null || true)

  if [ -n "$MATCHES" ]; then
    while IFS= read -r file; do
      echo "ALERT: Potential secret in $file (pattern: $pattern)"
      FOUND=1
    done <<< "$MATCHES"
  fi
done

if [ "$FOUND" -eq 1 ]; then
  echo ""
  echo "Secret scan FAILED. Review flagged files above."
  echo "If these are false positives, update scripts/secret-scan.sh exclusions."
  exit 1
fi

echo "Secret scan passed -- no secrets detected."
exit 0
