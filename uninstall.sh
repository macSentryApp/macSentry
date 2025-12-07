#!/bin/bash
set -euo pipefail

PLIST_TARGET="$HOME/Library/LaunchAgents/com.macos-security-audit.plist"
LOG_DIR="$HOME/Library/Logs/macos-security-audit"

echo "Uninstalling macOS Security Audit..."

if launchctl list | grep -q "com.macos-security-audit"; then
  /usr/bin/launchctl unload "$PLIST_TARGET" 2>/dev/null || true
  echo "✓ LaunchAgent unloaded"
else
  echo "- LaunchAgent not loaded (skipping)"
fi

if [[ -f "$PLIST_TARGET" ]]; then
  rm "$PLIST_TARGET"
  echo "✓ Plist removed: $PLIST_TARGET"
else
  echo "- Plist not found (skipping)"
fi

echo ""
echo "Uninstall complete."
echo "Note: Logs in $LOG_DIR were preserved. Delete manually if desired."
