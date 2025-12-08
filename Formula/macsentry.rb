# Homebrew formula for macSentry
# Install via tap: brew install macSentryApp/tap/macsentry
# Or local: brew install --build-from-source ./Formula/macsentry.rb

class Macsentry < Formula
  include Language::Python::Virtualenv

  desc "Automated security auditing and monitoring tool for macOS"
  homepage "https://github.com/macSentryApp/macos-security-audit"
  url "https://github.com/macSentryApp/macos-security-audit/archive/refs/tags/v2.0.0.tar.gz"
  sha256 "UPDATE_WITH_ACTUAL_SHA256"
  license "MIT"
  head "https://github.com/macSentryApp/macos-security-audit.git", branch: "main"

  depends_on :macos => :ventura
  depends_on "python@3.11"

  def install
    # Create virtualenv and install the package
    virtualenv_install_with_resources

    # Install launchd plist template
    (libexec/"launchd").install "launchd/com.macos-security-audit.plist"

    # Install helper script to set up scheduled scanning
    (bin/"macsentry-install").write <<~EOS
      #!/bin/bash
      set -euo pipefail

      PLIST_TARGET="$HOME/Library/LaunchAgents/com.macsentry.plist"
      LOG_DIR="$HOME/Library/Logs/macsentry"
      MACSENTRY_BIN="#{bin}/macsentry"
      DOMAIN_TARGET="gui/$(id -u)"

      echo "Installing macSentry scheduled audit..."
      mkdir -p "$LOG_DIR"
      
      # Create customized plist
      cat > "$PLIST_TARGET" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.macsentry</string>
    <key>ProgramArguments</key>
    <array>
        <string>$MACSENTRY_BIN</string>
        <string>--format</string>
        <string>json</string>
        <string>-o</string>
        <string>$LOG_DIR/audit-results.json</string>
    </array>
    <key>StartCalendarInterval</key>
    <dict>
        <key>Hour</key>
        <integer>9</integer>
        <key>Minute</key>
        <integer>0</integer>
    </dict>
    <key>StandardOutPath</key>
    <string>$LOG_DIR/macsentry.log</string>
    <key>StandardErrorPath</key>
    <string>$LOG_DIR/macsentry.error</string>
    <key>RunAtLoad</key>
    <false/>
</dict>
</plist>
PLIST

      # Load the agent
      launchctl bootout "$DOMAIN_TARGET/com.macsentry" 2>/dev/null || true
      launchctl bootstrap "$DOMAIN_TARGET" "$PLIST_TARGET" 2>/dev/null || \\
        launchctl load "$PLIST_TARGET" 2>/dev/null

      echo ""
      echo "✓ macSentry scheduled audit installed!"
      echo "  LaunchAgent: $PLIST_TARGET"
      echo "  Logs: $LOG_DIR"
      echo "  Schedule: Daily at 9:00 AM"
      echo ""
      echo "Verify with: launchctl list | grep macsentry"
    EOS

    # Install uninstall helper
    (bin/"macsentry-uninstall").write <<~EOS
      #!/bin/bash
      set -euo pipefail

      PLIST_TARGET="$HOME/Library/LaunchAgents/com.macsentry.plist"
      DOMAIN_TARGET="gui/$(id -u)"

      echo "Uninstalling macSentry scheduled audit..."
      
      launchctl bootout "$DOMAIN_TARGET/com.macsentry" 2>/dev/null || \\
        launchctl unload "$PLIST_TARGET" 2>/dev/null || true
      
      [[ -f "$PLIST_TARGET" ]] && rm "$PLIST_TARGET"

      echo "✓ macSentry scheduled audit uninstalled"
      echo "  Note: Logs remain at ~/Library/Logs/macsentry/"
    EOS
  end

  def caveats
    <<~EOS
      macSentry has been installed!

      Run a security audit:
        macsentry

      Schedule daily audits (9:00 AM):
        macsentry-install

      Remove scheduled audits:
        macsentry-uninstall

      More options:
        macsentry --help
        macsentry --format json -o report.json
        macsentry --format html -o report.html

      Logs: ~/Library/Logs/macsentry/
      Docs: https://github.com/macSentryApp/macos-security-audit#readme
    EOS
  end

  test do
    system "#{bin}/macsentry", "--dry-run"
  end
end
