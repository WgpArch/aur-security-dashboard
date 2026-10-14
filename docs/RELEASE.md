# Release Ritual (v1.1.6+)

GitHub tarballs embed the commit SHA (pax header), so a tag's tarball can only be
hashed AFTER the tag exists. .gitattributes excludes PKGBUILD/.SRCINFO from the
tarball, which breaks the circular dependency.

1. Bump pkgver in PKGBUILD; set sha256sums to 64 zeros (placeholder).
2. Commit everything; push main to GitHub, GitLab, Codeberg.
3. Create the tag and push it to all mirrors. THE TAG NEVER MOVES AGAIN.
4. sleep 5; REAL=$(curl -sL https://github.com/WgpArch/aur-security-dashboard/archive/refs/tags/vX.Y.Z.tar.gz | sha256sum | awk '{print $1}')
5. Paste REAL into PKGBUILD; commit; push main. (Tag stays on the placeholder
   commit — this is intentional and correct.)
6. makepkg --printsrcinfo > .SRCINFO ; makepkg -si must print "Passed".
7. Copy PKGBUILD + .SRCINFO to ~/.aur-security-dashboard-aur; commit; push master.

If a build ever fails checksum validation: the tag points at the wrong commit.
Fix: git tag -f vX.Y.Z <placeholder-commit-sha> then force-push the tag.
