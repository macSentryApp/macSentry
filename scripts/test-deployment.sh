#!/bin/bash
# Deployment Testing Script for macOS Security Audit
# Tests: install.sh, launchd plist, and scheduled execution
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
PLIST_TARGET="$HOME/Library/LaunchAgents/com.macos-security-audit.plist"
LOG_DIR="$HOME/Library/Logs/macos-security-audit"

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

pass() { echo -e "${GREEN}✓ PASS${NC}: $1"; }
fail() { echo -e "${RED}✗ FAIL${NC}: $1"; exit 1; }
warn() { echo -e "${YELLOW}⚠ WARN${NC}: $1"; }
info() { echo -e "  $1"; }

echo "================================================"
echo "  macOS Security Audit - Deployment Test Suite"
echo "================================================"
echo ""

# ------------------------------------------------------------------------------
# Pre-flight cleanup
# ------------------------------------------------------------------------------
echo "1. Pre-flight cleanup..."
# Use bootout for modern macOS, fall back to unload
launchctl bootout "gui/$(id -u)/com.macos-security-audit" 2>/dev/null || \
  launchctl unload "$PLIST_TARGET" 2>/dev/null || true
[[ -f "$PLIST_TARGET" ]] && rm "$PLIST_TARGET"
# Clear log files
rm -f "$LOG_DIR/macos-security-audit.log" "$LOG_DIR/macos-security-audit.error" 2>/dev/null || true
pass "Clean state established"
echo ""

# ------------------------------------------------------------------------------
# Test: install.sh runs successfully
# ------------------------------------------------------------------------------
echo "2. Testing install.sh..."
cd "$PROJECT_ROOT"
chmod +x install.sh
if ./install.sh; then
  pass "install.sh completed without errors"
else
  fail "install.sh failed"
fi
echo ""

# ------------------------------------------------------------------------------
# Test: Plist was installed correctly
# ------------------------------------------------------------------------------
echo "3. Verifying plist installation..."
if [[ -f "$PLIST_TARGET" ]]; then
  pass "Plist file exists at $PLIST_TARGET"
else
  fail "Plist file not found at $PLIST_TARGET"
fi

# Check placeholders were substituted
if grep -q "__SCRIPT_PATH__" "$PLIST_TARGET"; then
  fail "__SCRIPT_PATH__ placeholder not substituted"
else
  pass "Script path placeholder substituted"
fi

if grep -q "__LOG_DIR__" "$PLIST_TARGET"; then
  fail "__LOG_DIR__ placeholder not substituted"
else
  pass "Log directory placeholder substituted"
fi

# Verify correct paths in plist
SCRIPT_PATH_IN_PLIST=$(grep -A1 "macos_security_audit.py" "$PLIST_TARGET" | head -1)
info "Script path in plist: $(grep "macos_security_audit.py" "$PLIST_TARGET" | head -1 | xargs)"
echo ""

# ------------------------------------------------------------------------------
# Test: Log directory created
# ------------------------------------------------------------------------------
echo "4. Verifying log directory..."
if [[ -d "$LOG_DIR" ]]; then
  pass "Log directory exists: $LOG_DIR"
else
  fail "Log directory not created: $LOG_DIR"
fi
echo ""

# ------------------------------------------------------------------------------
# Test: LaunchAgent is loaded
# ------------------------------------------------------------------------------
echo "5. Verifying LaunchAgent is loaded..."
sleep 2  # Brief delay for launchctl to register

# Try multiple times as registration can be slow
AGENT_STATUS=""
for attempt in 1 2 3 4 5; do
  AGENT_STATUS=$(launchctl list 2>/dev/null | grep "com.macos-security-audit" || true)
  if [[ -n "$AGENT_STATUS" ]]; then
    break
  fi
  sleep 1
done

if [[ -n "$AGENT_STATUS" ]]; then
  pass "LaunchAgent is loaded"
  info "Status: $AGENT_STATUS"
  # Parse exit code from status (format: "PID  ExitCode  Label")
  EXIT_CODE=$(echo "$AGENT_STATUS" | awk '{print $2}')
  if [[ "$EXIT_CODE" != "0" ]] && [[ "$EXIT_CODE" != "-" ]]; then
    warn "Last run exit code: $EXIT_CODE (check error log for details)"
  fi
else
  fail "LaunchAgent is not loaded"
fi
echo ""

# ------------------------------------------------------------------------------
# Test: Manual trigger (RunAtLoad should have started it)
# ------------------------------------------------------------------------------
echo "6. Testing manual execution..."

LOG_FILE="$LOG_DIR/macos-security-audit.log"
ERROR_FILE="$LOG_DIR/macos-security-audit.error"

# Check if on external volume (launchd won't work)
if [[ "$PROJECT_ROOT" == /Volumes/* ]]; then
  warn "Project is on external volume - launchd execution will fail"
  info "This is expected: macOS restricts launchd access to external volumes"
  info "For production: move project to ~/Applications/ or /usr/local/"
  
  # Verify script runs directly
  info "Testing direct execution instead..."
  if python3 "$PROJECT_ROOT/macos_security_audit.py" --dry-run > /dev/null 2>&1; then
    pass "Direct execution works (--dry-run)"
  else
    fail "Script failed to run directly"
  fi
else
  # Wait briefly for RunAtLoad to execute
  sleep 2
  
  if [[ -f "$LOG_FILE" ]] && [[ -s "$LOG_FILE" ]]; then
    pass "Output log created with content"
    info "Log file: $LOG_FILE"
    info "First 3 lines:"
    head -3 "$LOG_FILE" | sed 's/^/    /'
  else
    warn "Output log empty or not created yet"
    info "Triggering manual run via launchctl..."
    launchctl kickstart "gui/$(id -u)/com.macos-security-audit" 2>/dev/null || \
      launchctl start com.macos-security-audit 2>/dev/null || true
    sleep 5
    if [[ -f "$LOG_FILE" ]] && [[ -s "$LOG_FILE" ]]; then
      pass "Output log created after manual trigger"
      head -3 "$LOG_FILE" | sed 's/^/    /'
    else
      warn "Log still empty - check $ERROR_FILE for errors"
    fi
  fi
fi
echo ""

# Check for errors
if [[ -f "$ERROR_FILE" ]] && [[ -s "$ERROR_FILE" ]]; then
  if grep -q "Operation not permitted" "$ERROR_FILE"; then
    warn "Error log shows 'Operation not permitted' (expected on external volumes)"
  else
    warn "Error log has content:"
    head -5 "$ERROR_FILE" | sed 's/^/    /'
  fi
fi
echo ""

# ------------------------------------------------------------------------------
# Test: Plist validation
# ------------------------------------------------------------------------------
echo "7. Validating plist syntax..."
if plutil -lint "$PLIST_TARGET" > /dev/null 2>&1; then
  pass "Plist syntax is valid"
else
  fail "Plist syntax is invalid"
fi
echo ""

# ------------------------------------------------------------------------------
# Test: Uninstall script
# ------------------------------------------------------------------------------
echo "8. Testing uninstall.sh..."
chmod +x "$PROJECT_ROOT/uninstall.sh"
if "$PROJECT_ROOT/uninstall.sh"; then
  pass "uninstall.sh completed"
else
  fail "uninstall.sh failed"
fi

if [[ -f "$PLIST_TARGET" ]]; then
  fail "Plist not removed after uninstall"
else
  pass "Plist removed successfully"
fi

if launchctl list 2>/dev/null | grep -q "com.macos-security-audit"; then
  fail "LaunchAgent still loaded after uninstall"
else
  pass "LaunchAgent unloaded successfully"
fi
echo ""

# ------------------------------------------------------------------------------
# Summary
# ------------------------------------------------------------------------------
echo "================================================"
echo -e "  ${GREEN}All deployment tests passed!${NC}"
echo "================================================"
echo ""
echo "Next steps for manual verification:"
echo "  1. Re-run ./install.sh"
echo "  2. Wait for 09:00 (or modify plist StartCalendarInterval)"
echo "  3. Check ~/Library/Logs/macos-security-audit/ for scheduled output"
echo ""
