#!/usr/bin/env bash
# validate.sh - Syntax-check all Groovy files in the seed-jobs repository.
#
# Usage:
#   ./validate.sh                    # check all .groovy files
#   ./validate.sh pipelines/         # check a specific directory
#
# Requirements:
#   - groovy must be on PATH (Groovy 3.x or 4.x)
#   - Run from the root of the seed-jobs repository
#
# Exit code: 0 if all files pass, 1 if any file has a syntax error.
#
# What it checks:
#   groovy --classpath . -e '<parse>' parses each file without executing it.
#   This catches syntax errors (missing brackets, invalid tokens, etc.) but
#   not runtime errors (unresolved symbols, missing pipeline steps, etc.).
#
# What it does not check:
#   - Jenkins-specific DSL validity (jobDsl blocks, pipeline steps)
#   - YAML schema correctness (use a YAML linter or the master seed validation)
#   - @Library imports or shared library calls

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")" && pwd)"
SEARCH_DIR="${1:-$REPO_ROOT}"

# ---------------------------------------------------------------------------
# Locate groovy binary
# ---------------------------------------------------------------------------

GROOVY_BIN=""
if command -v groovy >/dev/null 2>&1; then
    GROOVY_BIN="groovy"
elif [ -n "${GROOVY_HOME:-}" ] && [ -x "${GROOVY_HOME}/bin/groovy" ]; then
    GROOVY_BIN="${GROOVY_HOME}/bin/groovy"
else
    echo "ERROR: groovy not found on PATH and GROOVY_HOME is not set." >&2
    echo "Install Groovy 3.x or 4.x and ensure it is on PATH." >&2
    echo "  macOS:  brew install groovy" >&2
    echo "  Debian: apt-get install groovy" >&2
    exit 2
fi

GROOVY_VERSION=$("$GROOVY_BIN" --version 2>&1 | head -1)
echo "Using: $GROOVY_VERSION"
echo "Scanning: $SEARCH_DIR"
echo ""

# ---------------------------------------------------------------------------
# Find all .groovy files
# ---------------------------------------------------------------------------

mapfile -t GROOVY_FILES < <(find "$SEARCH_DIR" -name '*.groovy' | sort)

if [ ${#GROOVY_FILES[@]} -eq 0 ]; then
    echo "No .groovy files found under $SEARCH_DIR"
    exit 0
fi

echo "Found ${#GROOVY_FILES[@]} file(s) to check."
echo ""

# ---------------------------------------------------------------------------
# Check each file
# ---------------------------------------------------------------------------

PASS=0
FAIL=0
FAILED_FILES=()

for FILE in "${GROOVY_FILES[@]}"; do
    REL="${FILE#$REPO_ROOT/}"

    # groovy -cp . --check <file> parses without executing.
    # The --check flag is available in Groovy 2.5+.
    if "$GROOVY_BIN" -cp "$REPO_ROOT" --check "$FILE" 2>/tmp/groovy_validate_err; then
        echo "  OK  $REL"
        PASS=$((PASS + 1))
    else
        echo "  FAIL $REL"
        # Indent error output for readability
        sed 's/^/       /' /tmp/groovy_validate_err >&2
        FAIL=$((FAIL + 1))
        FAILED_FILES+=("$REL")
    fi
done

rm -f /tmp/groovy_validate_err

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed (${#GROOVY_FILES[@]} total)"

if [ $FAIL -gt 0 ]; then
    echo ""
    echo "Files with syntax errors:"
    for F in "${FAILED_FILES[@]}"; do
        echo "  - $F"
    done
    exit 1
fi

echo "All files passed syntax check."
exit 0
