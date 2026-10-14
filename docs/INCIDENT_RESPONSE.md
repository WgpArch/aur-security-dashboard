# Incident Response Guide

## Node / NPM Supply Chain Findings (added in v1.1.4)
If Tab 10 reports **Node/NPM** under BUILD, or a **CRITICAL npx** match:
1. Do NOT run makepkg -si. npx executes registry code immediately during build.
2. Check the dependency name against the real upstream project for typosquatting
   (dirtyblanket-express-style impersonation) and the npm advisory database.
3. A missing --frozen-lockfile means dependencies can silently drift to compromised versions.
4. Report confirmed malicious AUR packages via the AUR flag/comment mechanism.

## Post-Install Hook (.install) Findings (added in v1.1.5)
.install scripts run AS ROOT after installation. A CRITICAL here outranks a CRITICAL in the PKGBUILD.
1. DO NOT INSTALL: abort. Never pacman -U the package.
2. Already installed? Check: ~/.ssh/authorized_keys, crontab -l, /etc/ld.so.preload,
   new entries in /etc/passwd, and re-run Tab 4 (SUID Scanner).
3. Legitimate hooks exist (font caches, daemon-reload). HIGH findings like useradd or
   systemctl enable require manual review against upstream documentation.

## v1.1.6 Alerts
### Update Diff: CHANGED
1. Read the highlighted diff lines before updating. Hijacked orphan packages typically
   add curl|bash lines, new sources, or .install hooks.
2. Check the AUR page: is the package orphaned? Did the maintainer change recently?
3. If the change is not explained by the upstream changelog, do NOT update; flag the package.
### Process Hunter: Binary deleted from disk
1. Note PID, user, command. Do not reboot yet (rebooting destroys evidence).
2. Cross-check Tab 2 (Network) for connections owned by that PID.
3. Inspect persistence: cron, systemd units, shell profiles, authorized_keys.
4. Record evidence, then kill the process and investigate the launch vector.
### Tab 10: Hex escapes / raw IP source / paste-site source
Treat as DO NOT INSTALL and report: hallmarks of deliberate obfuscation or
attacker-controlled infrastructure, never legitimate packaging.
