# Release Ritual

1. Update `pkgver` in PKGBUILD.
2. Run `makepkg --printsrcinfo > .SRCINFO`
3. `git add -A && git commit -m "vX.Y.Z: message"`
4. Push code: `git push origin main && git push gitlab main && git push codeberg main`
5. Create tag: `git tag vX.Y.Z`
6. Push tag: `git push origin vX.Y.Z && git push gitlab vX.Y.Z && git push codeberg vX.Y.Z`
7. Copy PKGBUILD and .SRCINFO to `~/.aur-security-dashboard-aur/`
8. Push AUR: `cd ~/.aur-security-dashboard-aur && git add -A && git commit -m "vX.Y.Z" && git push origin master`

*Note: The dashboard's "Smart SKIP" rule recognizes `#tag=vX.Y.Z` as pinned, so our own package passes our own security checks!*
