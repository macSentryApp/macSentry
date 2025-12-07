# Homebrew formula for macOS Security Audit
# Install: brew install --build-from-source ./Formula/macos-security-audit.rb
# Or add tap: brew tap your-org/macos-security-audit && brew install macos-security-audit

class MacosSecurityAudit < Formula
  desc "Automated security auditing tool for macOS"
  homepage "https://github.com/your-org/macos-security-audit"
  url "https://github.com/your-org/macos-security-audit/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "UPDATE_WITH_ACTUAL_SHA256"
  license "MIT"
  head "https://github.com/your-org/macos-security-audit.git", branch: "main"

  depends_on :macos
  depends_on "python@3.11"

  def install
    # Install Python files
    libexec.install "macos_security_audit.py"
    libexec.install "checks"
    libexec.install "utils"
    libexec.install "core"

    # Install launchd plist template
    (libexec/"launchd").install "launchd/com.macos-security-audit.plist"

    # Create wrapper script
    (bin/"macos-security-audit").write <<~EOS
      #!/bin/bash
      exec "#{Formula["python@3.11"].opt_bin}/python3" "#{libexec}/macos_security_audit.py" "$@"
    EOS

    # Install helper scripts
    (bin/"macos-security-audit-install").write <<~EOS
      #!/bin/bash
      set -euo pipefail

      PLIST_SOURCE="#{libexec}/launchd/com.macos-security-audit.plist"
      PLIST_TARGET="$HOME/Library/LaunchAgents/com.macos-security-audit.plist"
      LOG_DIR="$HOME/Library/Logs/macos-security-audit"
      AUDIT_SCRIPT="#{libexec}/macos_security_audit.py"
      DOMAIN_TARGET="gui/$(id -u)"

      mkdir -p "$LOG_DIR"
      cp "$PLIST_SOURCE" "$PLIST_TARGET"
      /usr/bin/sed -i '' "s#__SCRIPT_PATH__#${AUDIT_SCRIPT}#g" "$PLIST_TARGET"
      /usr/bin/sed -i '' "s#__LOG_DIR__#${LOG_DIR}#g" "$PLIST_TARGET"

      launchctl bootout "$DOMAIN_TARGET/com.macos-security-audit" 2>/dev/null || true
      launchctl bootstrap "$DOMAIN_TARGET" "$PLIST_TARGET" 2>/dev/null || \\
        launchctl load "$PLIST_TARGET" 2>/dev/null

      echo "✓ LaunchAgent installed: $PLIST_TARGET"
      echo "✓ Logs: $LOG_DIR"
      echo "Verify: launchctl list | grep macos-security-audit"
    EOS

    (bin/"macos-security-audit-uninstall").write <<~EOS
      #!/bin/bash
      set -euo pipefail

      PLIST_TARGET="$HOME/Library/LaunchAgents/com.macos-security-audit.plist"
      DOMAIN_TARGET="gui/$(id -u)"

      launchctl bootout "$DOMAIN_TARGET/com.macos-security-audit" 2>/dev/null || \\
        launchctl unload "$PLIST_TARGET" 2>/dev/null || true
      [[ -f "$PLIST_TARGET" ]] && rm "$PLIST_TARGET"

      echo "✓ LaunchAgent uninstalled"
    EOS
  end

  def caveats
    <<~EOS
      To schedule daily security audits at 9:00 AM:
        macos-security-audit-install

      To uninstall the scheduled job:
        macos-security-audit-uninstall

      Logs are written to:
        ~/Library/Logs/macos-security-audit/

      Run manually:
        macos-security-audit
        macos-security-audit --format json
        macos-security-audit --help
    EOS
  end

  test do
    system "#{bin}/macos-security-audit", "--dry-run"
  end
end
