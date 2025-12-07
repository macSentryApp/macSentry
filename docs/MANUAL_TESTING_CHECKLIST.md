# Manual Testing Checklist

## Overview

This checklist ensures the macOS Security Audit tool is validated across diverse Mac configurations before release. **Minimum requirement: 5 distinct Mac configurations.**

## Test Matrix

### Required Hardware Diversity

| # | Mac Model | Chip | macOS Version | Tester | Date | Status |
|---|-----------|------|---------------|--------|------|--------|
| 1 | MacBook Pro | M1/M2/M3 (Apple Silicon) | macOS 14+ (Sonoma) | | | ⬜ |
| 2 | MacBook Pro/Air | Intel | macOS 13+ (Ventura) | | | ⬜ |
| 3 | Mac Mini | Any | macOS 12+ (Monterey) | | | ⬜ |
| 4 | iMac | Any | Any supported | | | ⬜ |
| 5 | Mac Studio/Pro | Any | Any supported | | | ⬜ |

**Status Legend:** ⬜ Not Started | 🔄 In Progress | ✅ Passed | ❌ Failed

---

## Per-Machine Test Procedure

### 1. Environment Setup

```bash
# Record system information
sw_vers
uname -a
python3 --version
```

**Checklist:**
- [ ] Python 3.10+ installed
- [ ] Script downloaded/cloned
- [ ] Working directory is project root

---

### 2. Basic Functionality Tests

#### 2.1 Help Command
```bash
python3 macos_security_audit.py --help
```
- [ ] Exits with code 0
- [ ] Shows all CLI options
- [ ] No error messages

#### 2.2 Dry Run
```bash
python3 macos_security_audit.py --dry-run
```
- [ ] Lists available checks (20+)
- [ ] Shows categories: encryption, firewall, system_integrity, authentication, privacy, applications, configuration
- [ ] Exits cleanly

#### 2.3 Full Audit (Text)
```bash
time python3 macos_security_audit.py --format text
```
- [ ] Completes without errors
- [ ] Shows summary with check counts
- [ ] Execution time < 30 seconds
- [ ] No Python tracebacks

#### 2.4 Full Audit (JSON)
```bash
python3 macos_security_audit.py --format json | python3 -m json.tool > /dev/null && echo "Valid JSON"
```
- [ ] Outputs valid JSON
- [ ] Contains `system_info` section
- [ ] Contains `results` array

#### 2.5 Full Audit (HTML)
```bash
python3 macos_security_audit.py --format html --output /tmp/audit_report.html
open /tmp/audit_report.html
```
- [ ] File created successfully
- [ ] Opens in browser
- [ ] Displays formatted report
- [ ] Styles render correctly

---

### 3. Category-Specific Tests

#### 3.1 Encryption Checks
```bash
python3 macos_security_audit.py --categories encryption --verbose
```
- [ ] FileVault check runs
- [ ] Result matches actual FileVault status (`fdesetup status`)

#### 3.2 Firewall Checks
```bash
python3 macos_security_audit.py --categories firewall --verbose
```
- [ ] Application Firewall check runs
- [ ] Stealth Mode check runs
- [ ] Results match System Settings

#### 3.3 System Integrity Checks
```bash
python3 macos_security_audit.py --categories system_integrity --verbose
```
- [ ] SIP check runs
- [ ] Result matches `csrutil status`
- [ ] Gatekeeper check runs
- [ ] XProtect check runs

#### 3.4 Privacy Checks
```bash
python3 macos_security_audit.py --categories privacy --verbose
```
- [ ] No crashes on TCC database access
- [ ] Handles permission errors gracefully

---

### 4. Edge Case Tests

#### 4.1 Elevated Mode
```bash
sudo python3 macos_security_audit.py --elevated --dry-run
```
- [ ] Lists additional sudo-required checks
- [ ] No permission errors

#### 4.2 Severity Filtering
```bash
python3 macos_security_audit.py --min-severity HIGH --format json
```
- [ ] Only shows HIGH and CRITICAL results
- [ ] Lower severity items filtered

#### 4.3 File Output
```bash
python3 macos_security_audit.py --output ~/Desktop/security_audit.txt
cat ~/Desktop/security_audit.txt
```
- [ ] File created at specified path
- [ ] Content matches stdout output

#### 4.4 Debug Mode
```bash
python3 macos_security_audit.py --debug --categories encryption 2>&1 | head -50
```
- [ ] Debug logging visible
- [ ] Log file created in `~/Library/Logs/macos-security-audit/`

---

### 5. Performance Validation

```bash
# Execution time
time python3 macos_security_audit.py --format json > /dev/null

# Memory usage (requires psutil or Activity Monitor)
# During audit execution, check "python" process in Activity Monitor
```

- [ ] Execution time < 30 seconds
- [ ] Peak memory < 100 MB
- [ ] No memory growth on repeated runs

---

### 6. Error Handling

#### 6.1 Invalid Arguments
```bash
python3 macos_security_audit.py --invalid-option 2>&1
```
- [ ] Shows usage error
- [ ] Non-zero exit code
- [ ] No traceback

#### 6.2 Invalid Category
```bash
python3 macos_security_audit.py --categories nonexistent --dry-run
```
- [ ] Handles gracefully
- [ ] Shows empty list or warning

#### 6.3 Permission Denied Scenarios
```bash
# Run as regular user (not root)
python3 macos_security_audit.py --format json
```
- [ ] Sudo-required checks show SKIP status
- [ ] No crashes on permission errors

---

### 7. Result Validation

Compare tool results with manual checks:

| Check | Tool Result | Manual Verification | Match? |
|-------|-------------|---------------------|--------|
| FileVault | | `fdesetup status` | |
| SIP | | `csrutil status` | |
| Firewall | | System Settings > Network > Firewall | |
| Gatekeeper | | `spctl --status` | |
| Auto Updates | | System Settings > Software Update | |

---

## Test Report Template

```markdown
## Manual Test Report

**Date:** YYYY-MM-DD
**Tester:** [Name]

### System Information
- **Model:** [e.g., MacBook Pro 14" 2023]
- **Chip:** [e.g., M3 Pro]
- **macOS:** [e.g., 14.2 Sonoma]
- **Python:** [e.g., 3.12.0]

### Test Results Summary
- Basic Functionality: [PASS/FAIL]
- Category Tests: [PASS/FAIL]
- Edge Cases: [PASS/FAIL]
- Performance: [X.Xs execution, XMB memory]
- Error Handling: [PASS/FAIL]
- Result Validation: [X/X checks matched]

### Issues Found
1. [Description of any issues]

### Notes
[Any additional observations]

### Approval
- [ ] All critical tests pass
- [ ] No blocking issues
- [ ] Ready for release
```

---

## Sign-Off

| Tester | System | Date | Signature |
|--------|--------|------|-----------|
| | | | |
| | | | |
| | | | |
| | | | |
| | | | |

**Release Approval:** _________________ Date: _________
