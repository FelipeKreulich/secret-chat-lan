# Homebrew formula for CipherMesh.
#
# ACTIVATION (two one-time steps, after `npm publish`):
#   1. Publish the package:            npm publish
#   2. Fill in the tarball checksum:   the `sha256` below is a placeholder —
#      replace it with the real digest:
#        curl -sL https://registry.npmjs.org/ciphermesh/-/ciphermesh-2.7.0.tgz | shasum -a 256
#      (bump both the `url` version and `sha256` on every release).
#
# INSTALL (once the tap repo `FelipeKreulich/homebrew-ciphermesh` hosts this file):
#   brew tap felipekreulich/ciphermesh
#   brew install ciphermesh
# Or straight from this file:
#   brew install --build-from-source ./Formula/ciphermesh.rb
class Ciphermesh < Formula
  desc "End-to-end encrypted terminal chat for LAN and Tailscale"
  homepage "https://github.com/FelipeKreulich/secret-chat-lan"
  url "https://registry.npmjs.org/ciphermesh/-/ciphermesh-2.7.0.tgz"
  sha256 "e2dd4d20bc47afe0c82a4725e8757a47718ac62fe7a9b32c6e2110198e0a020a"
  license "MIT"

  depends_on "node"

  def install
    system "npm", "install", *std_npm_args
    bin.install_symlink Dir["#{libexec}/bin/*"]
  end

  test do
    assert_match "CipherMesh", shell_output("#{bin}/ciphermesh --help")
    assert_match version.to_s, shell_output("#{bin}/ciphermesh --version")
  end
end
