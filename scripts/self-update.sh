#!/bin/bash
# Self-update script for macOS Security Audit
# Checks for new releases and updates if available
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
REPO_URL="${MACOS_AUDIT_REPO:-https://github.com/your-org/macos-security-audit}"
VERSION_FILE="$PROJECT_ROOT/VERSION"
CURRENT_VERSION="unknown"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC} $1"; }

# Get current version
if [[ -f "$VERSION_FILE" ]]; then
  CURRENT_VERSION=$(cat "$VERSION_FILE" | tr -d '[:space:]')
elif [[ -f "$PROJECT_ROOT/pyproject.toml" ]]; then
  CURRENT_VERSION=$(grep '^version' "$PROJECT_ROOT/pyproject.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
fi

echo "macOS Security Audit - Self Update"
echo "==================================="
echo "Current version: $CURRENT_VERSION"
echo ""

# Check if git is available and we're in a git repo
if ! command -v git &> /dev/null; then
  echo "Error: git is required for auto-update" >&2
  exit 1
fi

if [[ ! -d "$PROJECT_ROOT/.git" ]]; then
  warn "Not a git repository. For auto-update, clone from:"
  echo "  git clone $REPO_URL"
  echo ""
  echo "Or download the latest release manually."
  exit 0
fi

cd "$PROJECT_ROOT"

# Fetch latest changes
echo "Checking for updates..."
git fetch origin --tags 2>/dev/null || {
  warn "Could not fetch from remote. Check network connection."
  exit 1
}

# Get latest tag
LATEST_TAG=$(git describe --tags --abbrev=0 origin/main 2>/dev/null || echo "")
if [[ -z "$LATEST_TAG" ]]; then
  # No tags, check if main has new commits
  LOCAL_COMMIT=$(git rev-parse HEAD)
  REMOTE_COMMIT=$(git rev-parse origin/main 2>/dev/null || echo "")
  
  if [[ "$LOCAL_COMMIT" == "$REMOTE_COMMIT" ]]; then
    info "Already up to date (commit: ${LOCAL_COMMIT:0:7})"
    exit 0
  fi
  
  echo "New commits available on main branch."
  read -p "Update to latest? [y/N] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    git pull origin main
    info "Updated to latest commit"
  fi
else
  # Compare versions
  if [[ "$CURRENT_VERSION" == "$LATEST_TAG" ]] || [[ "v$CURRENT_VERSION" == "$LATEST_TAG" ]]; then
    info "Already on latest version: $LATEST_TAG"
    exit 0
  fi
  
  echo "New version available: $LATEST_TAG"
  read -p "Update from $CURRENT_VERSION to $LATEST_TAG? [y/N] " -n 1 -r
  echo
  if [[ $REPLY =~ ^[Yy]$ ]]; then
    # Check for local changes
    if ! git diff-index --quiet HEAD --; then
      warn "You have local changes. Stashing them..."
      git stash
      STASHED=true
    fi
    
    git checkout "$LATEST_TAG"
    info "Updated to $LATEST_TAG"
    
    if [[ "${STASHED:-false}" == "true" ]]; then
      warn "Your local changes were stashed. Run 'git stash pop' to restore."
    fi
    
    # Update VERSION file
    echo "$LATEST_TAG" | tr -d 'v' > "$VERSION_FILE"
    
    # Re-install launchd agent if it exists
    PLIST_TARGET="$HOME/Library/LaunchAgents/com.macos-security-audit.plist"
    if [[ -f "$PLIST_TARGET" ]]; then
      echo ""
      read -p "Re-install launchd agent with new version? [y/N] " -n 1 -r
      echo
      if [[ $REPLY =~ ^[Yy]$ ]]; then
        "$PROJECT_ROOT/install.sh"
      fi
    fi
  fi
fi

echo ""
echo "Done."
