#!/bin/bash
# Comprehensive linting script for macos-security-audit
# Usage: ./scripts/lint.sh [--fix]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}           macOS Security Audit - Static Analysis              ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
echo

# Track failures
FAILED=0

# -----------------------------------------------------------------------------
# 1. Flake8 - Style & Complexity
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[1/6] Running Flake8 (style & complexity)...${NC}"
if flake8 checks/ utils/ --config=.flake8; then
    echo -e "${GREEN}✓ Flake8 passed${NC}"
else
    echo -e "${RED}✗ Flake8 failed${NC}"
    FAILED=1
fi
echo

# -----------------------------------------------------------------------------
# 2. Pylint - Comprehensive Linting
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[2/6] Running Pylint (comprehensive linting)...${NC}"
if pylint checks/ utils/ --rcfile=pyproject.toml --fail-under=8.0; then
    echo -e "${GREEN}✓ Pylint passed (score >= 8.0)${NC}"
else
    echo -e "${RED}✗ Pylint failed${NC}"
    FAILED=1
fi
echo

# -----------------------------------------------------------------------------
# 3. MyPy - Type Checking
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[3/6] Running MyPy (type checking)...${NC}"
if mypy checks/ utils/ --config-file=pyproject.toml; then
    echo -e "${GREEN}✓ MyPy passed${NC}"
else
    echo -e "${RED}✗ MyPy failed${NC}"
    FAILED=1
fi
echo

# -----------------------------------------------------------------------------
# 4. Bandit - Security Linting
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[4/6] Running Bandit (security analysis)...${NC}"
if bandit -r checks/ utils/ -c pyproject.toml -ll; then
    echo -e "${GREEN}✓ Bandit passed (no medium+ security issues)${NC}"
else
    echo -e "${RED}✗ Bandit found security issues${NC}"
    FAILED=1
fi
echo

# -----------------------------------------------------------------------------
# 5. Semgrep - Vulnerability Patterns
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[5/6] Running Semgrep (vulnerability patterns)...${NC}"
if command -v semgrep &> /dev/null; then
    if semgrep --config p/python --config p/security-audit checks/ utils/ --error --quiet; then
        echo -e "${GREEN}✓ Semgrep passed${NC}"
    else
        echo -e "${RED}✗ Semgrep found vulnerabilities${NC}"
        FAILED=1
    fi
else
    echo -e "${YELLOW}⚠ Semgrep not installed (pip install semgrep)${NC}"
fi
echo

# -----------------------------------------------------------------------------
# 6. Radon - Cyclomatic Complexity
# -----------------------------------------------------------------------------
echo -e "${YELLOW}[6/6] Running Radon (cyclomatic complexity)...${NC}"
echo "Complexity scores (target: all functions <= 10):"
radon cc checks/ utils/ -a -s --total-average

# Check for any function with complexity > 10 (grade D or worse)
if radon cc checks/ utils/ -nc --min D | grep -q .; then
    echo -e "${RED}✗ Functions with complexity > 10 detected:${NC}"
    radon cc checks/ utils/ -nc --min D
    FAILED=1
else
    echo -e "${GREEN}✓ All functions have complexity <= 10${NC}"
fi
echo

# -----------------------------------------------------------------------------
# Summary
# -----------------------------------------------------------------------------
echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
if [ $FAILED -eq 0 ]; then
    echo -e "${GREEN}All static analysis checks passed!${NC}"
    exit 0
else
    echo -e "${RED}Some checks failed. Please fix the issues above.${NC}"
    exit 1
fi
