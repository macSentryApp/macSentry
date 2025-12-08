# Homebrew formula for macOS Security Audit (legacy name)
# NOTE: This formula is deprecated. Use 'macsentry' instead:
#   brew install macSentryApp/tap/macsentry
#
# This formula is kept for backwards compatibility and redirects to macsentry.

class MacosSecurityAudit < Formula
  include Language::Python::Virtualenv

  desc "Automated security auditing tool for macOS (use 'macsentry' instead)"
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

    # Create alias for backwards compatibility
    (bin/"macos-security-audit").write <<~EOS
      #!/bin/bash
      exec "#{bin}/macsentry" "$@"
    EOS
  end

  def caveats
    <<~EOS
      NOTE: This formula name is deprecated!
      
      Please use 'macsentry' instead:
        brew uninstall macos-security-audit
        brew install macSentryApp/tap/macsentry

      For now, you can run:
        macsentry --help
        macsentry
    EOS
  end

  test do
    system "#{bin}/macsentry", "--dry-run"
  end
end
