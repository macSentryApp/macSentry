#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"
AUDIT_SCRIPT="$PROJECT_ROOT/macos_security_audit.py"
PLIST_SOURCE="$PROJECT_ROOT/launchd/com.macos-security-audit.plist"
PLIST_TARGET="$HOME/Library/LaunchAgents/com.macos-security-audit.plist"
LOG_DIR="$HOME/Library/Logs/macos-security-audit"
DOMAIN_TARGET="gui/$(id -u)"

if [[ ! -f "$AUDIT_SCRIPT" ]]; then
  echo "Error: macos_security_audit.py not found at $AUDIT_SCRIPT" >&2
  exit 1
fi

# Warn if installed on external/removable volume
if [[ "$PROJECT_ROOT" == /Volumes/* ]]; then
  echo "⚠  Warning: Project is on an external volume ($PROJECT_ROOT)"
  echo "   launchd may fail to run if the volume is not mounted."
  echo "   Consider moving to ~/Applications or /usr/local for reliable scheduling."
  echo ""
fi

mkdir -p "$LOG_DIR"
cp "$PLIST_SOURCE" "$PLIST_TARGET"
/usr/bin/sed -i '' "s#__SCRIPT_PATH__#${AUDIT_SCRIPT}#g" "$PLIST_TARGET"
/usr/bin/sed -i '' "s#__LOG_DIR__#${LOG_DIR}#g" "$PLIST_TARGET"

# Unload existing agent (try both old and new syntax)
launchctl bootout "$DOMAIN_TARGET/com.macos-security-audit" 2>/dev/null || \
  launchctl unload "$PLIST_TARGET" 2>/dev/null || true

# Load agent (try modern syntax first, fall back to legacy)
LOAD_ERROR=""
if ! LOAD_ERROR=$(launchctl bootstrap "$DOMAIN_TARGET" "$PLIST_TARGET" 2>&1); then
  if ! LOAD_ERROR=$(launchctl load "$PLIST_TARGET" 2>&1); then
    echo "Error: Failed to load LaunchAgent" >&2
    echo "  Error: $LOAD_ERROR" >&2
    echo "  Plist installed at: $PLIST_TARGET" >&2
    echo "  Try: launchctl load -w \"$PLIST_TARGET\"" >&2
    exit 1
  fi
fi

# Verify agent is loaded (may take a moment to register)
LOADED=false
for i in 1 2 3; do
  sleep 1
  if launchctl list 2>/dev/null | grep -q "com.macos-security-audit"; then
    LOADED=true
    break
  fi
done
if [[ "$LOADED" != "true" ]]; then
  echo "Warning: Agent may not have loaded correctly" >&2
  echo "  Check with: launchctl list | grep macos-security-audit" >&2
fi

echo "✓ LaunchAgent installed: $PLIST_TARGET"
echo "✓ Logs directory: $LOG_DIR"
echo ""
echo "Verify with: launchctl list | grep macos-security-audit"
