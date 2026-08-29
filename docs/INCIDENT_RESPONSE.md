##################################################
Incident Response Manual: Tab 1 - AUR Packages
##################################################

Purpose:
This tab lists all packages installed from the Arch User Repository (AUR). 
These packages are built from source by community members and are not officially supported by Arch Linux. 
They represent a higher security risk than official repository packages because they can contain unvetted code, 
outdated dependencies, or malicious build scripts.

What to Look For:

Outdated Versions: If an AUR package hasn't been updated in months or years, it may contain known vulnerabilities that are no longer
being patched.
Orphaned Packages: Packages that were once dependencies but are no longer required by anything. These receive zero security updates.
Suspicious Names: Packages with names that mimic popular software but have slight typos (typosquatting) or come from unknown
maintainers.

Incident Response Steps:

1.Verify Package Integrity:

If a package looks suspicious or is flagged as outdated, check its current status on the AUR Website
Look at the "Last Updated" date and the number of votes/popularity.

# Check local version vs AUR version
# Check local version vs AUR version (choose your helper):
trizen -Syua
# OR
paru -Syu --aur
# OR
yay -Syu --aur

2.Inspect the PKGBUILD:

Before updating or reinstalling a suspicious AUR package, always inspect its build script (PKGBUILD) 
for malicious commands like curl | bash, hidden network calls, or obfuscated code.

# Using paru
paru -S --view <package-name>

# Using yay 
yay -S --editmenu <package-name>

# Using trizen 
trizen -S --noconfirm --view <package-name>

⚠️ Arch-Specific Note: Always verify the maintainer's reputation on the AUR Website
before trusting any PKGBUILD. Official Arch repositories (core, extra, multilib) are signed and vetted; AUR packages are not.
If an official alternative exists, always prefer it over an AUR package.

######################################################
Incident Response Manual: Tab 2 - Network Connections
######################################################

Purpose:
This tab displays all active network connections on your system, including listening ports, established connections, 
and socket states. It provides real-time visibility into what your machine is communicating with, which is critical for detecting 
unauthorized access, data exfiltration, or rogue services.

What to Look For:

Unexpected Listening Ports: Services bound to 0.0.0.0 (all interfaces) that you did not intentionally configure. 
These are prime targets for remote exploitation.
Suspicious Outbound Connections: Established connections to unfamiliar IP addresses, especially on non-standard ports 
(not 80, 443, 53). This could indicate malware "phoning home" or a reverse shell.
Connections from Untrusted Networks: Inbound connections from IPs outside your local subnet (192.168.x.x, 10.x.x.x) when no 
external services should be exposed.

Incident Response Steps:

1.Identify the Owning Process:

For every suspicious connection, determine which process owns it. This tells you if it's a legitimate service or something malicious.
CLOSE_WAIT / TIME_WAIT Accumulation: A high number of these states may indicate a service under stress, a misconfigured application, 
or a denial-of-service attack.
IPv6 vs IPv4 Mismatches: Services listening only on IPv6 (::) but not IPv4 (or vice versa) when both should be configured, 
potentially creating blind spots in firewall rules.

Find the PID and program name for a specific port/connection
sudo ss -tlnp | grep <port-or-ip>
# OR use lsof for more detail
sudo lsof -i :<port>

2.Verify Service Legitimacy:
Cross-reference the process name and binary path against known system services. Check if the binary matches its expected package.

Verify which package owns a binary
pacman -Qo /path/to/binary

Check if the service is supposed to be running
systemctl status <service-name>

3.Block Suspicious Connections Immediately:
If a connection is confirmed malicious or unauthorized, block it at the firewall level while you investigate further.

Block outbound to suspicious IP (using nftables)
sudo nft add rule inet filter output ip daddr <suspicious-ip> drop

Or using iptables (legacy)
sudo iptables -A OUTPUT -d <suspicious-ip> -j DROP

4.Capture Traffic for Forensic Analysis:
Before killing the process or blocking the connection permanently, capture the traffic for later analysis. 
This preserves evidence.

Capture packets to/from suspicious IP (run as root)
sudo tcpdump -i any host <suspicious-ip> -w /tmp/suspicious_capture.pcap

Analyze later with Wireshark or tshark
tshark -r /tmp/suspicious_capture.pcap -Y "http.request"

5.Check for Persistence Mechanisms:
Malware often reinstalls itself. After stopping a suspicious connection, check for cron jobs, systemd timers, or modified init 
scripts that could restart it.

List user cron jobs
crontab -l

List system cron jobs
sudo ls /etc/cron.*

Check for suspicious systemd timers
systemctl list-timers --all

Severity Levels:

🔴 CRITICAL: Active connection to known C2 server, reverse shell detected, or sensitive port (SSH, database) exposed to internet 
without auth.
🟠 HIGH: Unexpected listening port on public interface, outbound connection to untrusted IP on non-standard port.
🟡 MEDIUM: Connection to unfamiliar but plausible service (e.g., update checker), high CLOSE_WAIT count.
🟢 LOW: Normal web browsing, DNS queries, expected service connections within local network.

###################################################
Incident Response Manual: Tab 3 - System Integrity
###################################################

Purpose:
This tab performs a cryptographic verification of all installed system binaries and configuration files against the official 
Arch Linux package database (pacman -Qk). It detects file modifications, missing files, permission changes, and timestamp anomalies 
that indicate rootkit installation, malware persistence, or unauthorized system tampering.

What to Look For:

Modified Binaries: Any executable in /usr/bin, /usr/sbin, or /lib that fails checksum verification. This is the primary indicator 
of a trojaned system binary (e.g., modified sshd, sudo, or login).
Missing Critical Files: Essential system files that should exist but are absent. Malware often deletes logging utilities (journalctl, lastlog) or security tools to cover its tracks.
Permission/Ownership Changes: Files with incorrect SUID bits, world-writable permissions, or wrong ownership. Attackers frequently 
modify permissions to maintain persistent access without modifying the binary itself.
Configuration File Tampering: Modified files in /etc/pam.d/, /etc/ssh/, /etc/sudoers, or /etc/passwd. These changes can create 
backdoor accounts, disable authentication, or weaken security policies.
TOCTOU Race Conditions: If a file's modification timestamp changed during the scan window, it may indicate an active attacker 
manipulating files in real-time to evade detection.

Incident Response Steps:

1.Isolate the Affected Package:
Identify which official package owns the compromised file. This determines the scope of the compromise and the correct remediation 
path.

Find the owning package for a suspicious file
pacman -Qo /path/to/suspicious/file

Reinstall the package to restore original files (DO NOT do this yet if forensics are needed)
sudo pacman -S --overwrite '*' <package-name>

2.Preserve Forensic Evidence BEFORE Remediation:
CRITICAL: Never overwrite or delete a suspicious file before capturing evidence. Create a forensic image first.

# Hash the suspicious file for chain-of-custody
sha256sum /path/to/suspicious/file > /tmp/evidence_hash.txt

# Copy the file to a secure evidence directory (preserve timestamps)
sudo cp -a /path/to/suspicious/file /tmp/forensic_evidence/

# Capture full file metadata
stat /path/to/suspicious/file > /tmp/evidence_metadata.txt
ls -laZ /path/to/suspicious/file >> /tmp/evidence_metadata.txt

3.Analyze the Modification:
Compare the suspicious file against the known-good version from the official package to understand what was changed.

Extract the original file from the package archive
mkdir -p /tmp/original_pkg && cd /tmp/original_pkg
tar xf /var/cache/pacman/pkg/<package-name>-*.pkg.tar.zst

Diff the original vs. the suspicious file
diff -u /tmp/original_pkg/usr/bin/<binary> /path/to/suspicious/file

Check for strings indicating malicious behavior
strings /path/to/suspicious/file | grep -iE 'curl|wget|bash|python|perl|socket|connect'

4.Check for Persistence Mechanisms:
A modified binary is rarely standalone. Search for related persistence artifacts across the entire system.

Search for recently modified files in critical directories (last 7 days)
sudo find /usr/bin /usr/sbin /etc /lib -mtime -7 -type f -exec ls -la {} \;

Check for LD_PRELOAD hijacking (common rootkit technique)
cat /etc/ld.so.preload 2>/dev/null
env | grep -i preload

Verify kernel module integrity
sudo lsmod | sort
sudo modinfo <suspicious-module> 2>/dev/null

5.Remediate Safely:
Only after evidence is preserved and analyzed, restore the system to a known-good state.

Reinstall the affected package with overwrite flag
sudo pacman -S --overwrite '*' <package-name>

Verify restoration succeeded
sudo pacman -Qk <package-name>

Rotate ALL credentials if any auth-related files were modified
sudo passwd root
Change passwords for all user accounts

Severity Levels:

CRITICAL: Modified authentication binary (sshd, sudo, login, passwd), modified PAM configuration, missing logging utilities, or 
detected LD_PRELOAD hijack. Assume full system compromise.
🟠 HIGH: Modified network service binary, altered firewall rules, changed SSH authorized_keys, or unexpected SUID bit on 
non-standard binary.
🟡 MEDIUM: Modified configuration file with no obvious security impact, missing non-critical file, or permission change on 
data-only file.
LOW: Timestamp-only change (no content modification), expected post-update file recreation, or user-owned config file modification.

⚠️ Forensic Best Practice Note:
Always assume that if one system binary is modified, the entire system must be considered untrustworthy. The only guaranteed clean 
recovery is a fresh install from verified media after preserving evidence. Package reinstallation fixes the symptom but cannot 
guarantee all persistence mechanisms have been removed.

###########################################################
Incident Response Manual: Tab 4 - SUID/SGID Binary Scanner
###########################################################

Purpose:
This tab identifies all files on the system with the Set User ID (SUID) or Set Group ID (SGID) bit set. These bits allow 
executables to run with the file owner's (usually root's) privileges regardless of who launches them. While many SUID binaries are 
legitimate system tools, unauthorized or modified SUID files are a primary persistence mechanism for attackers and a common 
privilege escalation vector.

What to Look For:

Non-Standard SUID Binaries: Any SUID file not in the official Arch Linux whitelist. Attackers frequently copy /bin/bash, 
/usr/bin/python3, or /usr/bin/find and set the SUID bit to create backdoor shells.
SUID Files in Writable Directories: Legitimate SUID binaries should only exist in /usr/bin, /usr/sbin, or /usr/lib. SUID files in 
/tmp, /var/tmp, /dev/shm, or user home directories are almost always malicious.
Modified Timestamps on Known SUID Binaries: If a whitelisted binary like /usr/bin/sudo has a modification time that doesn't match 
its package install date, it may have been trojaned while retaining its SUID bit.

Incident Response Steps:

1.Verify Against Official Whitelist:
Cross-reference every flagged binary against the known-good Arch Linux SUID list. Your dashboard already includes this whitelist; 
use it as your baseline.
Unexpected SGID Binaries: SGID files grant group-level privileges. While less critical than SUID, unexpected SGID binaries 
(especially those granting disk, shadow, or wheel group access) can leak sensitive data.
SUID Binaries Owned by Non-Root Users: A SUID binary owned by a regular user runs with that user's privileges, not root. 
This is unusual and may indicate a misconfiguration or a targeted attack against a specific account.

Manually verify if a binary belongs to an official package
pacman -Qo /path/to/suid/binary

Check the package's expected SUID files
pacman -Ql <package-name> | grep -E '^.* s$'  # 's' indicates SUID in pacman output

2.Analyze Suspicious Binaries:
For any non-whitelisted SUID file, determine its origin and intent before taking action.

Check file type and architecture
file /path/to/suspicious/suid/binary

Search for embedded strings indicating malicious behavior
strings /path/to/suspicious/suid/binary | grep -iE 'connect|socket|exec|shell|reverse|callback'

Check when the SUID bit was last set (may differ from file mod time)
stat /path/to/suspicious/suid/binary

3.Preserve Evidence Before Removal:
Never delete a suspicious SUID binary immediately. It is critical evidence.

Create forensic copy preserving all attributes
sudo cp -a /path/to/suspicious/suid/binary /tmp/forensic_evidence/suid_$(date +%Y%m%d_%H%M%S)

Record full metadata including SUID bit state
ls -la /path/to/suspicious/suid/binary > /tmp/forensic_evidence/suid_metadata.txt
getcap /path/to/suspicious/suid/binary >> /tmp/forensic_evidence/suid_metadata.txt 2>/dev/null

4.Remove the SUID Bit Safely:
If the binary is confirmed malicious or unnecessary, strip the SUID/SGID bit first (rather than deleting) to preserve the file for 
analysis while neutralizing the threat.

Remove SUID and SGID bits
sudo chmod u-s,g-s /path/to/suspicious/suid/binary

Verify the bit was removed
ls -la /path/to/suspicious/suid/binary

5.Search for Related Persistence Artifacts:
A rogue SUID binary rarely exists alone. Hunt for associated artifacts.

Find other files created/modified around the same time
sudo find / -newer /path/to/suspicious/suid/binary -not -path "/proc/*" -not -path "/sys/*" -type f 2>/dev/null

Check for cron jobs or systemd services referencing the binary
grep -r "suspicious_binary_name" /etc/cron* /etc/systemd/ /var/spool/cron/ 2>/dev/null

Search bash history for commands related to setting SUID bits
sudo grep -r "chmod.*[42].." /home/*/.*history /root/.*history 2>/dev/null

Severity Levels:

🔴 CRITICAL: SUID binary in /tmp, /dev/shm, or user directory; SUID copy of shell/interpreter (bash, python, perl); modified 
whitelisted auth binary (sudo, passwd, su). Immediate isolation required.
🟠 HIGH: Non-whitelisted SUID binary in system directory; SGID binary granting access to shadow, disk, or wheel groups; 
SUID binary with recent modification timestamp mismatch.
🟡 MEDIUM: Whitelisted SUID binary with unexpected ownership; SGID binary with unclear purpose; SUID file from installed package 
but not documented in package metadata.
🟢 LOW: Standard whitelisted SUID/SGID binary with correct ownership, permissions, and timestamps; expected browser sandbox 
binaries (chrome-sandbox, vivaldi-sandbox).

⚠️ Critical Forensic Note:
The presence of a single unauthorized SUID binary means the system's privilege boundary has been breached. Even after removing the 
SUID bit, assume the attacker may have already escalated privileges, created additional backdoors, or exfiltrated data. Full system 
rebuild from verified media is the only guaranteed remediation.

#######################################################################
Incident Response Manual: Tab 5 - Authentication & Brute-Force Monitor
#######################################################################

Purpose:
This tab analyzes system authentication logs (via journalctl) for the last 24 hours to detect failed login attempts, successful 
logins from unexpected sources, sudo usage anomalies, and session openings/closings. It provides real-time visibility into who is 
trying to access your system, how they are doing it, and whether those attempts succeeded or failed.

What to Look For:

Brute Force Patterns: Multiple failed password attempts from the same IP address within a short time window 
(e.g., >10 failures in 5 minutes). This indicates automated credential stuffing or dictionary attacks.
Invalid User Attempts: Login attempts using usernames that don’t exist on the system (Invalid user admin, Invalid user test). 
Attackers use common username lists; seeing these means someone is actively probing your SSH/service endpoints.
Successful Logins After Failures: A sequence of many failed attempts followed by a single success from the same source. 
This often means the attacker eventually guessed the correct password or used a leaked credential.
Sudo Usage Anomalies: Sudo commands executed by users who rarely use elevated privileges, or sudo commands run at unusual hours 
(e.g., 3 AM). Also watch for sudo commands that bypass audit logging (sudo -i, sudo su).
Session Openings Without Corresponding Closings: Sessions that open but never close may indicate abandoned reverse shells, hung 
processes, or attackers maintaining persistent interactive access.
Authentication from Unexpected Sources: Successful logins from IPs outside your known trusted networks, or via services you didn’t 
expect to be exposed (e.g., SSH login when you only use local console).

Incident Response Steps:

1.Correlate Failed + Successful Attempts:

Don’t treat failed and successful logins in isolation. Link them by source IP and timestamp to identify successful breaches after 
probing.

Find all auth events from a specific suspicious IP in last 24h
journalctl --since "24 hours ago" | grep "<suspicious-ip>" | grep -E "Failed|Accepted|session opened"

Count failures vs successes per IP
journalctl --since "24 hours ago" -g "Failed password|Accepted" | awk '{print $NF}' | sort | uniq -c | sort -rn

2.Identify Targeted Accounts:
Determine which user accounts are being targeted. Repeated attempts against root, admin, or service accounts indicate focused attacks.

List all targeted usernames from failed attempts
journalctl --since "24 hours ago" -g "Failed password" | grep -oP 'for \K\S+' | sort | uniq -c | sort -rn

Check if targeted accounts have weak passwords or are disabled
sudo passwd -S <targeted-username>

3.Preserve Log Evidence Before Rotation:
System logs rotate automatically. Preserve relevant entries immediately to prevent evidence loss.

Export all auth events from last 24h to forensic file
journalctl --since "24 hours ago" -g "Failed|Accepted|session|sudo" > /tmp/forensic_evidence/auth_log_$(date +%Y%m%d_%H%M%S).txt

Also preserve raw journal binary for full metadata
sudo cp /var/log/journal/*/system.journal /tmp/forensic_evidence/ 2>/dev/null || \
sudo journalctl --output=export > /tmp/forensic_evidence/journal_export.bin

4.Block Attacking IPs Immediately:
If brute force or unauthorized access is confirmed, block the source at the firewall level while preserving logs.

# Block IP with nftables (preferred on modern Arch)
sudo nft add rule inet filter input ip saddr <attacker-ip> drop

Or with iptables (legacy)
sudo iptables -A INPUT -s <attacker-ip> -j DROP

Verify block is active
sudo nft list ruleset | grep <attacker-ip>

5.Audit Affected Accounts & Services:
After blocking, verify no persistence was established through the compromised account or service.

# Check authorized_keys for targeted user
cat /home/<user>/.ssh/authorized_keys

Review sudoers configuration for unauthorized entries
sudo visudo -c
sudo grep -r "<user>" /etc/sudoers.d/

Check for new SSH keys or config changes
sudo find /etc/ssh /home/<user>/.ssh -mtime -1 -type f

Severity Levels:

🔴 CRITICAL: Successful login after multiple failures from external IP; sudo usage by unauthorized user; session opened for 
non-existent user; authentication bypass detected. Assume active compromise.
🟠 HIGH: >20 failed attempts from single IP in 1 hour; failed attempts against root/admin accounts; sudo usage at unusual hours; 
session opened without corresponding close.
🟡 MEDIUM: 5–20 failed attempts from single IP; invalid user attempts from internal network; normal sudo usage with minor anomaly; 
session timeout without explicit close.
🟢 LOW: 1–4 failed attempts (likely typo); expected sudo usage during business hours; routine session open/close cycles; 
authentication from known trusted IP.

⚠️ Critical Forensic Note:
Authentication logs are volatile and rotate frequently. Always export logs before any remediation action. A blocked IP tells you 
nothing about what happened before the block. The log entries contain the timeline, methodology, and scope of the attack—this is 
your primary evidence for incident reporting and potential legal proceedings. Never assume “no successful 
login” means “no breach”; attackers may use stolen tokens, SSH keys, or exploit vulnerabilities that don’t generate standard auth 
log entries.

#############################################################
 Incident Response Manual: Tab 6 - Anomalous Process Hunter
#############################################################

Purpose:
This tab enumerates all running processes and flags those exhibiting suspicious behavior patterns that deviate from normal system 
operation. It detects processes executing from writable directories, hidden processes, resource abuse (cryptomining), and 
unauthorized network listeners—providing real-time visibility into active threats before they establish persistence.

What to Look For:

Processes Running from Writable Directories: Any executable launched from /tmp, /var/tmp, /dev/shm, or user home directories 
(/home/*). Legitimate system binaries reside exclusively in /usr/bin, /usr/sbin, or /usr/lib. Processes from writable paths are 
almost always malicious payloads dropped by exploit kits or malware droppers.
Hidden or Renamed Processes: Processes with names designed to blend in (kworker/0:1-events, systemd-journal, dbus-daemon) but whose 
binary path doesn't match the legitimate service location. Attackers rename malware to mimic system processes.
High Resource Consumption: Processes consuming >80% CPU or memory unexpectedly. This is the primary indicator of cryptominers 
(xmrig, cpuminer) or ransomware encrypting files in the background.
Unusual Parent-Child Relationships: A web server process (nginx, apache) spawning a shell (bash, sh, python). Web servers should 
never spawn interactive shells; this indicates remote code execution (RCE) exploitation.
Processes Listening on Non-Standard Ports: Services binding to high-numbered ports (>1024) without corresponding systemd units. 
Reverse shells and C2 beacons commonly use ports like 4444, 8080, or random ephemeral ports.
Deleted Binary Execution: Processes whose executable file has been deleted from disk (shown as (deleted) in /proc/<pid>/exe). 
Malware often deletes its own binary after execution to evade file-based detection while continuing to run in memory.

Incident Response Steps:

1.Verify Process Legitimacy:
Before taking action, confirm whether the flagged process is genuinely anomalous or a false positive.

Get full process details including binary path and command line
ps aux | grep <suspicious-pid>

Check the actual binary being executed (may differ from process name)
ls -la /proc/<suspicious-pid>/exe

View the complete command line with arguments
cat /proc/<suspicious-pid>/cmdline | tr '\0' ' ' && echo

Verify if the binary belongs to an official package
pacman -Qo /proc/<suspicious-pid>/exe 2>/dev/null || echo "NOT FROM OFFICIAL PACKAGE"

2.Capture Live Process Evidence:
Do not kill the process immediately. Preserve its state for forensic analysis first.

Dump process memory map to identify loaded libraries and injected code
sudo cat /proc/<suspicious-pid>/maps > /tmp/forensic_evidence/process_<pid>_maps.txt

Capture open file descriptors (reveals C2 connections, log files, etc.)
sudo ls -la /proc/<suspicious-pid>/fd/ > /tmp/forensic_evidence/process_<pid>_fds.txt

Extract environment variables (may contain API keys, tokens, C2 URLs)
sudo cat /proc/<suspicious-pid>/environ | tr '\0' '\n' > /tmp/forensic_evidence/process_<pid>_env.txt

If binary was deleted, recover it from /proc before it's gone forever
sudo cp /proc/<suspicious-pid>/exe /tmp/forensic_evidence/recovered_binary_<pid>

3.Analyze Network Connections:
Determine what the process is communicating with to assess data exfiltration or C2 activity.

Show all network connections for the suspicious PID
sudo ss -tlnp | grep <suspicious-pid>
sudo ss -unp | grep <suspicious-pid>

Capture live traffic to/from the process for protocol analysis
sudo tcpdump -i any pid <suspicious-pid> -w /tmp/forensic_evidence/process_<pid>_capture.pcap &
Let it run for 30-60 seconds, then: kill %1

4.Terminate and Contain:
Only after evidence is preserved, stop the process and prevent immediate respawn.

Send SIGSTOP first to freeze the process (prevents cleanup/deletion)
sudo kill -STOP <suspicious-pid>

Then terminate gracefully
sudo kill -TERM <suspicious-pid>

If it refuses to die, force kill
sudo kill -9 <suspicious-pid>

Block associated IPs at firewall level
sudo nft add rule inet filter output ip daddr <c2-ip> drop

5.Hunt for Persistence Mechanisms:
A running process is usually just one component. Find how it survives reboots.

Search for cron jobs referencing the binary or its path
sudo grep -r "<binary-name-or-path>" /etc/cron* /var/spool/cron/ /home/*/crontab 2>/dev/null

Check systemd services and timers
systemctl list-units --type=service --all | grep -i "<binary-name>"
systemctl list-timers --all | grep -i "<binary-name>"

Look for init scripts or rc.local modifications
grep -r "<binary-name>" /etc/init.d/ /etc/rc.local /etc/profile.d/ 2>/dev/null

Check for LD_PRELOAD or library injection
cat /etc/ld.so.preload 2>/dev/null
sudo find /usr/lib /lib -name "*.so" -mtime -1 2>/dev/null

Severity Levels:

🔴 CRITICAL: Process from /tmp//dev/shm with outbound connection; deleted binary still running; web server spawning shell; 
cryptominer consuming >80% CPU; process listening on known C2 port (4444, 1337, etc.). Active compromise confirmed.
🟠 HIGH: Process mimicking system service name but wrong binary path; unexpected listener on non-standard port; process with 
deleted exe file; high resource usage without legitimate explanation.
🟡 MEDIUM: User-owned process consuming moderate resources; process from /opt or /usr/local without package ownership; unusual but 
plausible parent-child relationship.
LOW: Standard system process with expected resource usage; verified package-owned binary; normal user application processes.

⚠️ Critical Forensic Note:
Running processes are ephemeral evidence. They can vanish in milliseconds via self-deletion, crash, or attacker intervention. 
Always capture /proc/<pid>/exe, maps, fd, and environ before sending any signal. A killed process leaves only logs; a preserved 
process provides memory dumps, network state, and the actual malicious binary for reverse engineering. In legal proceedings, the 
difference between "we saw something suspicious" and "here is the recovered malware binary with timestamped chain-of-custody" 
determines case outcomes.

##########################################################
Incident Response Manual: Tab 7 - Systemd Service Auditor
##########################################################

Purpose:
This tab enumerates all active, failed, and enabled systemd service units to detect unauthorized services, misconfigured daemons, 
and persistence mechanisms. Unlike traditional init scripts, systemd services offer granular control over execution context, making 
them a preferred vector for attackers seeking reliable, stealthy persistence. This audit identifies services that deviate from 
expected system behavior or security baselines.

What to Look For:

Failed Services: Units in failed state may indicate tampered binaries, missing dependencies, or deliberate sabotage 
(e.g., an attacker disabling logging or security services).
Services Running from User Writable Paths: Any service executing binaries from /home/, /tmp/, /var/tmp/, or /dev/shm. 
Legitimate system services only execute from /usr/bin, /usr/sbin, /usr/lib, or /opt.
Unexpected Enabled Services: Services set to enabled that you did not intentionally configure. Attackers frequently enable custom 
services to ensure malware restarts after reboot.
Services with Elevated Privileges: Units running as root or with CapabilityBoundingSet granting dangerous capabilities 
(CAP_SYS_ADMIN, CAP_NET_RAW, CAP_DAC_OVERRIDE) without clear justification.
Services Masking Legitimate Functionality: Custom services with names mimicking system components (systemd-update-helper.service, 
network-manager-helper.service) but pointing to non-standard binaries.
Timer-Activated Services: .timer units triggering suspicious .service units at unusual intervals (e.g., every 5 minutes instead of 
daily/weekly), often used for periodic C2 beaconing or data exfiltration.

Incident Response Steps:

1.Investigate Failed Services First:
Failed services are high-priority indicators. Determine why they failed before assuming compromise.

Get detailed failure reason and recent logs
systemctl status <failed-service-name>
journalctl -u <failed-service-name> --since "24 hours ago" --no-pager

Check if the binary exists and is intact
systemctl show <failed-service-name> -p ExecStart
ls -la /path/to/binary/from/execstart
pacman -Qo /path/to/binary/from/execstart 2>/dev/null || echo "NOT FROM OFFICIAL PACKAGE"

2.Verify Suspicious Service Configuration:
For any service running from writable paths or with unexpected privileges, inspect its full unit file.

View the complete unit file (including drop-in overrides)
systemctl cat <suspicious-service-name>

Check for runtime modifications not in the unit file
systemctl show <suspicious-service-name> | grep -E "ExecStart|User|Group|Capability|ReadWritePaths"

Verify the binary's integrity against package database
sudo pacman -Qk <owning-package> 2>/dev/null || echo "PACKAGE NOT FOUND OR MODIFIED"

3.Preserve Service Evidence Before Disabling:
Never disable or stop a suspicious service before capturing its configuration and logs.

Export full unit file and drop-ins to evidence directory
mkdir -p /tmp/forensic_evidence/services
systemctl cat <suspicious-service-name> > /tmp/forensic_evidence/services/<service-name>.unit

Capture current runtime state and environment
systemctl show <suspicious-service-name> > /tmp/forensic_evidence/services/<service-name>.runtime

Preserve associated logs (critical for timeline reconstruction)
journalctl -u <suspicious-service-name> --no-pager > /tmp/forensic_evidence/services/<service-name>.log

If timer-activated, also preserve the timer unit
systemctl cat <service-name>.timer > /tmp/forensic_evidence/services/<service-name>.timer.unit 2>/dev/null

4.Disable and Contain Safely:
After evidence preservation, neutralize the service while maintaining forensic integrity.

Stop the service first (don't disable yet—stopping preserves runtime state in /proc)
sudo systemctl stop <suspicious-service-name>

Disable to prevent restart on boot
sudo systemctl disable <suspicious-service-name>

Mask to prevent accidental re-enablement during investigation
sudo systemctl mask <suspicious-service-name>

If timer-activated, also disable/mask the timer
sudo systemctl stop <service-name>.timer 2>/dev/null
sudo systemctl disable <service-name>.timer 2>/dev/null
sudo systemctl mask <service-name>.timer 2>/dev/null

5.Hunt for Related Persistence Artifacts:
A malicious service rarely exists alone. Search for companion artifacts across the system.

# Find other files created/modified near the service unit file timestamp
sudo find /etc/systemd /usr/lib/systemd -newer /etc/systemd/system/<suspicious-service>.service -type f 2>/dev/null

# Check for corresponding cron jobs (attackers often use both)
sudo grep -r "<binary-name-or-path>" /etc/cron* /var/spool/cron/ /home/*/crontab 2>/dev/null

Search for related binaries in writable directories
sudo find /tmp /var/tmp /dev/shm /home -name "*<service-keyword>*" -type f -mtime -7 2>/dev/null

Review systemd journal for service creation/modification events
journalctl _SYSTEMD_UNIT=<suspicious-service-name> --output=verbose | grep -E "Created|Modified|Enabled"

Severity Levels:

🔴 CRITICAL: Service running from /tmp//dev/shm//home; failed auth/security service (sshd, auditd, firewalld); service with 
CAP_SYS_ADMIN and no legitimate purpose; timer activating suspicious service every <10 minutes. Active persistence confirmed.
🟠 HIGH: Enabled service from /opt or /usr/local without package ownership; failed service with tampered binary; service masking 
legitimate component name; service with elevated capabilities and network access.
MEDIUM: Disabled but not masked suspicious service; timer with unusual schedule but plausible purpose; service with minor 
permission anomaly; failed service due to missing dependency (not tampering).
🟢 LOW: Standard system service in expected state; verified package-owned service with correct configuration; intentionally 
disabled third-party service with documented reason.

️Critical Forensic Note:
Systemd services are persistent by design. Unlike processes (Tab 6), they survive reboots and are automatically managed by the init 
system. This makes them both a primary attacker tool and a primary forensic artifact. Always preserve the entire unit file hierarchy 
(main unit + drop-in overrides in /etc/systemd/system/<service>.service.d/) because attackers frequently use drop-ins to modify 
legitimate services without altering the original package-owned unit file. A service that appears "normal" in systemctl cat may 
have been silently modified via drop-in—a technique your dashboard must account for in future updates.

########################################################################
Incident Response Manual: Tab 8 - Code Inspector (AUR PKGBUILD Scanner)
########################################################################

Purpose:
This tab performs static analysis on the PKGBUILD scripts of installed and pending AUR packages before they are compiled or executed. 
It searches for malicious patterns, obfuscated code, unauthorized network calls, and suspicious file modifications. This is your 
primary defense against supply chain attacks, where a compromised maintainer account or a typosquatted package injects malware 
directly into your system during the build process.

What to Look For:

Remote Code Execution (RCE) During Build: Commands that download and immediately execute code, such as curl <url> | bash, 
wget <url> | sh, or python -c "...". Legitimate packages should only download source tarballs, not executable payloads.
Obfuscation and Encoding: Use of base64 -d, xxd -r, or complex eval statements. Attackers use these to hide malicious payloads from 
casual inspection.
Writing to Sensitive System Paths: Scripts that write to /etc/cron.d/, /etc/systemd/system/, /usr/bin/, or /etc/profile.d/ during 
the package() or build() phase. 
User Environment Tampering: Modifications to ~/.bashrc, ~/.ssh/authorized_keys, or ~/.config/. This is a common technique for 
stealing SSH keys or establishing persistent reverse shells.
Pre-compiled Binaries from Unknown Sources: Instead of compiling from source, the PKGBUILD downloads a pre-compiled binary from a 
random GitHub release or file host. This bypasses compiler-level security mitigations and makes auditing impossible.
Excessive Permissions: Use of chmod 777 or chown root:root on files that do not require them.

Incident Response Steps:

1.Halt Installation and Isolate:
If the Code Inspector flags a package, do not install or update it. Isolate the package name and investigate further before 
proceeding.

If using an AUR helper, abort the current transaction
(Usually Ctrl+C or 'N' when prompted)

Manually download the PKGBUILD for offline inspection
git clone https://aur.archlinux.org/<package-name>.git /tmp/aur_audit/<package-name>
cd /tmp/aur_audit/<package-name>

2.Decode Obfuscated Payloads:
If the scanner flags base64 or hex strings, decode them in a safe, isolated environment to reveal the hidden payload.

Decode a base64 string safely (do not pipe to bash!)
echo "<suspicious-base64-string>" | base64 -d > /tmp/decoded_payload.txt

View the decoded payload in a safe text editor
nano /tmp/decoded_payload.txt

Check if the decoded payload contains network calls or shell commands
grep -iE 'curl|wget|bash|sh|python|socket|connect|/dev/tcp' /tmp/decoded_payload.txt

3.Audit the Maintainer and Package History:
Check the human element. A sudden change in a PKGBUILD from a previously trusted maintainer often indicates a compromised account.

Check the AUR page for comments, out-of-date flags, and recent changes
(Do this via your web browser at aur.archlinux.org)

Check the git history of the PKGBUILD for sudden, unexplained changes
cd /tmp/aur_audit/<package-name>
git log -p PKGBUILD

4.Build in a Sandbox (Advanced Forensics):
If the PKGBUILD is complex and you cannot determine its behavior through static analysis, build it in an isolated environment to 
observe its runtime behavior.

Use systemd-nspawn or a chroot to build safely
Example using a basic chroot (requires arch-chroot)

sudo arch-chroot /path/to/clean/chroot
Inside chroot:

cd /tmp/aur_audit/<package-name>
makepkg -si --noconfirm

Monitor network traffic and file changes during this process

5.Report and Contain:
If malicious code is confirmed, report it immediately to protect the community and block the associated infrastructure.

Flag the package as out-of-date or malicious on the AUR website
Send a detailed report to the AUR mailing list or security@archlinux.org

Block any malicious domains or IPs found in the PKGBUILD

sudo nft add rule inet filter output ip daddr <malicious-ip> drop
sudo nft add rule inet filter output dport <malicious-port> drop

Severity Levels:

🔴 CRITICAL: Direct execution of remote code (curl | bash), writing to SSH keys/cron/systemd, known malicious maintainer, or decoded payload contains a reverse shell/C2 beacon. Do not install.
🟠 HIGH: Heavy obfuscation (base64, eval), downloading pre-compiled binaries from untrusted GitHub repos, writing to /etc/ or /usr/ without justification.
🟡 MEDIUM: Unnecessary network calls during the build() phase, minor permission anomalies, fetching sources from non-upstream mirrors.
🟢 LOW: Standard build process, fetching sources from official upstream repositories, clean PKGBUILD with active and trusted maintainer.

️Critical Forensic Note:
Supply chain attacks are uniquely dangerous because the malicious code often runs with the privileges of the user building the 
package. If a user builds a malicious AUR package using sudo makepkg (a bad practice, but common), the malware gains root 
immediately. Furthermore, sophisticated PKGBUILD malware will delete its own traces after execution. The PKGBUILD itself is your 
primary forensic artifact. Always preserve the git history and the exact version of the PKGBUILD that was flagged, as the attacker 
will likely delete or modify it once discovered.

###########################################################
Incident Response Manual: Tab 9 - System Hardening Posture
###########################################################

Purpose:
This tab evaluates the live security configuration of the Linux kernel by reading critical parameters from /proc/sys and 
/sys/kernel/security. It verifies whether Mandatory Access Control (MAC) is active and checks for essential exploit mitigations 
like kernel pointer restriction, ptrace scoping, and BPF JIT hardening. This tab answers the fundamental question: Is the kernel 
configured to resist advanced exploitation, or is it running with default, permissive settings?

What to Look For:

Inactive Mandatory Access Control (MAC): If AppArmor, SELinux, or TOMOYO is not loaded, the kernel relies solely on standard 
Discretionary Access Control (DAC). This means if an attacker compromises a process, they have the exact same permissions as that 
user, with no secondary containment layer.
Exposed Kernel Pointers (kptr_restrict = 0): When kernel memory addresses are visible to unprivileged users, it makes it trivially 
easy for attackers to bypass Kernel Address Space Layout Randomization (KASLR) and exploit kernel vulnerabilities.
Unrestricted ptrace (yama/ptrace_scope = 0): Allows any process to debug or inspect the memory of any other process running under 
the same user. Malware frequently uses this to inject code into legitimate processes (like browsers or SSH clients) to steal 
credentials.

Incident Response Steps:

1.Verify Current Kernel State:
Before making changes, confirm the exact current values of the flagged parameters to ensure the dashboard is reading them correctly 
and to establish a baseline.

Check MAC status

cat /sys/kernel/security/lsm

Check kernel hardening parameters

sysctl kernel.kptr_restrict
sysctl kernel.yama.ptrace_scope
sysctl net.core.bpf_jit_harden

Disabled BPF JIT Hardening: The Berkeley Packet Filter (BPF) is heavily used in modern networking and tracing. If JIT hardening is 
off, it increases the risk of speculative execution attacks (like Spectre) via malicious BPF programs.

2.Apply Immediate Temporary Mitigations:
If a critical parameter is vulnerable, you can change it immediately in the running kernel without rebooting. This is useful during 
an active incident to stop an ongoing exploit attempt.

Restrict kernel pointers (1 = hidden from non-root, 2 = hidden from everyone)

sudo sysctl -w kernel.kptr_restrict=2

Restrict ptrace (1 = restricted to children, 2 = admin-only, 3 = disabled)

sudo sysctl -w kernel.yama.ptrace_scope=1

Harden BPF JIT (1 = unprivileged only, 2 = all code)

sudo sysctl -w net.core.bpf_jit_harden=2

3.Make Hardening Permanent:
Temporary sysctl changes revert on reboot. To make them permanent, create a dedicated configuration file.

Create a custom hardening config file

sudo nano /etc/sysctl.d/99-arch-hardening.conf

Add the following lines:
kernel.kptr_restrict = 2
kernel.yama.ptrace_scope = 1
net.core.bpf_jit_harden = 2

Apply the new configuration immediately

sudo sysctl --system

4.Enable Mandatory Access Control (MAC):
If the dashboard reports MAC as "Inactive", you should enable a MAC framework. Arch Linux supports AppArmor and TOMOYO out of the 
box via kernel parameters.

For AppArmor (requires installing apparmor package and adding to bootloader)
Edit your bootloader config (GRUB/systemd-boot) and add to kernel parameters:
apparmor=1 security=apparmor

For TOMOYO (requires installing tomoyo-toolsAUR)
Edit bootloader config and add:
lsm=landlock,lockdown,yama,integrity,tomoyo,bpf
security=tomoyo

Severity Levels:

🔴 CRITICAL: MAC is inactive on a server or multi-user system; kptr_restrict is 0 on a system exposed to untrusted users; 
ptrace_scope is 0 on a development machine running untrusted code.
🟠 HIGH: BPF JIT hardening is disabled; kptr_restrict is 1 (default) on a high-security workstation; MAC is inactive on a personal 
desktop handling sensitive data.
MEDIUM: ptrace_scope is 1 (default Arch setting) but the user runs sandboxed applications that require broader ptrace access; minor 
sysctl deviations from maximum hardening.
🟢 LOW: All parameters are set to maximum hardening levels; MAC is active and enforcing; system is fully locked down 
(may require relaxing settings for specific gaming or development tools).

⚠️ Critical Forensic Note:
Kernel hardening is a defense-in-depth measure, not a silver bullet. It significantly raises the cost and complexity of Local 
Privilege Escalation (LPE) and information disclosure attacks, but it cannot stop an attacker who already has root access. 
Furthermore, maximum hardening (e.g., ptrace_scope=3 or kptr_restrict=2) can break certain legitimate applications, debuggers, and 
anti-cheat software. Always test sysctl changes in a non-production environment first, and document why a specific parameter was 
relaxed if it deviates from the baseline.
