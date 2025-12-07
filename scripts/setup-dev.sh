#!/bin/bash
# Development environment setup script
# Usage: ./scripts/setup-dev.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_DIR"

echo "═══════════════════════════════════════════════════════════════"
echo "      Setting up development environment for macos-security-audit"
echo "═══════════════════════════════════════════════════════════════"
echo

# -----------------------------------------------------------------------------
# 1. Create virtual environment if it doesn't exist
# -----------------------------------------------------------------------------
if [ ! -d ".venv" ]; then
    echo "[1/4] Creating virtual environment..."
    python3 -m venv .venv
else
    echo "[1/4] Virtual environment already exists"
fi

# Activate virtual environment
source .venv/bin/activate

# -----------------------------------------------------------------------------
# 2. Install dependencies
# -----------------------------------------------------------------------------
echo "[2/4] Installing development dependencies..."
pip install --upgrade pip
pip install -e ".[dev]"

# -----------------------------------------------------------------------------
# 3. Install pre-commit hooks
# -----------------------------------------------------------------------------
echo "[3/4] Installing pre-commit hooks..."
pre-commit install
pre-commit install --hook-type commit-msg

# -----------------------------------------------------------------------------
# 4. Verify installation
# -----------------------------------------------------------------------------
echo "[4/4] Verifying installation..."
echo

echo "Installed tools:"
echo "  - pylint:   $(pylint --version | head -1)"
echo "  - flake8:   $(flake8 --version)"
echo "  - mypy:     $(mypy --version)"
echo "  - bandit:   $(bandit --version | head -1)"
echo "  - radon:    $(radon --version)"

if command -v semgrep &> /dev/null; then
    echo "  - semgrep:  $(semgrep --version)"
else
    echo "  - semgrep:  Not installed (optional, run: pip install semgrep)"
fi

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Setup complete! Development environment is ready."
echo
echo "Usage:"
echo "  source .venv/bin/activate    # Activate virtual environment"
echo "  ./scripts/lint.sh            # Run all linters"
echo "  pre-commit run --all-files   # Run pre-commit hooks"
echo "  pytest                       # Run tests"
echo "═══════════════════════════════════════════════════════════════"
