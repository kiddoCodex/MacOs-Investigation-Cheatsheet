# macOS Investigation Cheatsheet for Red Teamers

This cheatsheet is designed for conducting thorough investigations and security assessments on macOS systems. It covers critical techniques for enumeration, user analysis, persistence mechanisms, network traffic analysis, file system auditing, and more.

---

## 1. **System Information**

### General System Info:
- **System Profiler (CLI)**: 
  - `system_profiler SPSoftwareDataType` - View detailed software information (OS version, kernel version, build)
  - `system_profiler SPHardwareDataType` - Detailed hardware information (CPU, memory, disk)
  - `sw_vers` - Displays macOS version and build.
- **hostname**: Get the machine’s hostname.
- **uname -a**: Get detailed information about the kernel and system architecture.
- **top -l 1**: View system performance and resource usage in real-time.

### Disk and Storage:
- **diskutil list**: Display all storage devices and partitions.
- **df -h**: Show disk space usage.
- **du -sh <path>**: Show disk usage of a specific directory.
- **mount**: List all mounted filesystems.
- **lsblk**: List block devices (useful for storage analysis).
- **ls /Volumes**: List all mounted drives and external volumes.

### Network Information:
- **ifconfig**: Display network interface details.
- **netstat -an**: Show all network connections and listening ports.
- **lsof -i**: List processes using network connections.
- **netstat -r**: Display the routing table.
- **ipconfig getifaddr en0**: Get the IP address of a specific interface (e.g., `en0` for Ethernet).
- **traceroute <host>**: Trace the route to a remote host.

---

## 2. **User and Group Enumeration**

### User Accounts:
- **dscl . -list /Users**: List all local user accounts.
- **id <username>**: Show information about a user’s UID, GID, and group memberships.
- **finger <username>**: View detailed user information (if available).
- **w**: Shows who is logged in and their activities.
- **whoami**: Display the current logged-in user.
- **ls -l /Users**: List directories and check for user accounts in the `/Users` directory.

### Groups:
- **dscl . -list /Groups**: List all local groups.
- **dscl . -read /Groups/admin**: Display members of the `admin` group.
- **groups <username>**: Display group memberships for a specific user.
- **id**: Displays current user’s UID and GID.

### User Activity:
- **last**: Show the last logins for all users.
- **last -f /var/log/wtmp**: View user login history.
- **last -t <time_interval>**: Filter logs based on time.
- **grep <username> /var/log/authd.log**: Search authentication logs for specific user activity.

---

## 3. **File System & Persistence**

### Hidden Files:
- **ls -a**: List all files, including hidden files (those starting with a dot).
- **find / -name ".*"**: Find all hidden files across the system.
- **find / -name "*.*" -exec file {} \;**: Identify file types and hidden files across the system.

### System Logs:
- **/var/log/system.log**: View general system logs.
- **/var/log/authd.log**: Contains authentication logs (useful for login attempts, sudo commands, etc.).
- **/private/var/log/install.log**: Installation logs for software packages.
- **grep -i <pattern> /var/log/*log**: Search for specific patterns or events in system logs (e.g., suspicious commands, login attempts).
- **log show --predicate 'eventMessage contains "<pattern>"'**: Search for specific events in the unified logs.
- **log show --last 1d**: View logs from the past day.
  
### Persistence Mechanisms:
- **launchctl list**: List all running services and background tasks.
- **launchctl bootout system /path/to/plist**: Remove a system service (useful for persistence removal).
- **launchctl load /Library/LaunchDaemons/<plist>**: Load a new service for persistence.
- **launchctl unload /Library/LaunchDaemons/<plist>**: Unload a service.
- **ls /Library/LaunchDaemons/**: List all system-level launch daemons (services that start on boot).
- **ls /Library/LaunchAgents/**: List all user-level launch agents.
- **ls /System/Library/LaunchDaemons/**: System-level daemons.
- **ls /private/etc/rc.common**: Check for custom startup scripts or configurations.

### Autostart Items:
- **open -a "System Preferences" /System/Library/PreferencePanes**: Open System Preferences to check for auto-start apps.
- **defaults read com.apple.loginwindow**: Check login window preferences.
- **ls -l ~/Library/Preferences/**: Search for potential user-specific configuration files that could affect startup.

---

## 4. **Malware Analysis & Detection**

### Analyzing Running Processes:
- **ps aux**: List all running processes.
- **top -u <user>**: Display processes for a specific user.
- **lsof -i**: Show network-related processes.
- **Activity Monitor**: GUI-based tool for investigating running processes and resource usage.
- **netstat -an | grep ESTABLISHED**: Identify established network connections.
- **strings <file_path>**: Extract readable strings from files (useful for detecting malicious code).
- **file <file_path>**: Identify the file type (helpful for detecting disguised malicious files).
- **sudo dtrace -n 'syscall::open:entry /execname == "malicious_program"/ { printf("%d %s %d", pid, execname, arg0); }'**: Trace system calls for a specific process.

### Kernel Extensions & Modules:
- **kextstat**: Display loaded kernel extensions (modules).
- **kextunload /path/to/kext**: Unload a kernel extension.
- **kextload /path/to/kext**: Load a kernel extension.
- **ls /System/Library/Extensions/**: Check the system extensions directory for unauthorized modules.

### File and Binary Analysis:
- **codesign -dvvv <file_path>**: Display the code signature of an application (check for modifications).
- **spctl --assess --verbose <file_path>**: Assess the Gatekeeper status of a binary.
- **otool -L <file_path>**: Display libraries linked to a binary.
- **otool -V <file_path>**: Display detailed version information for a binary.
- **nm <file_path>**: Display symbols from a binary file (useful for identifying suspicious code).
- **strings <file_path>**: Extract readable strings from executables (useful for detecting suspicious content).

---

## 5. **Forensics and Evidence Collection**

### Collecting Logs:
- **log show --predicate 'eventMessage contains "authentication"'**: Investigate authentication events.
- **syslog**: Check for older system logs in `/var/log/syslog`.
- **find / -name "*.log"**: Find log files across the system.
- **grep "failed" /var/log/*log**: Identify failed login attempts in the system logs.

### Memory Dump Analysis:
- **sudo pmset -g log**: Investigate power-related logs.
- **vm_stat**: Display statistics related to virtual memory usage.
- **fs_usage**: Monitor file system activity, including file access.

### File Integrity and Hashing:
- **shasum <file_path>**: Generate a SHA1 checksum of a file for integrity checking.
- **md5 <file_path>**: Generate an MD5 hash for file integrity verification.
- **/usr/bin/openssl dgst -sha256 <file_path>**: Generate a SHA-256 hash of a file.
  
---

## 6. **Network Monitoring & Analysis**

### Network Connections and Traffic:
- **netstat -an | grep <port_number>**: Check for listening services on a specific port.
- **tcpdump -i en0**: Capture packets on a specific network interface (replace `en0` with the actual interface name).
- **iftop**: Real-time network usage monitoring.
- **nmap <target-ip>**: Perform a network scan to find open ports and services.
- **sudo pfctl -sr**: Display active firewall rules.
- **sudo tcpdump -n -i en0**: Capture network traffic on `en0` (interface).

---

## 7. **Privilege Escalation**

### Check for Elevated Privileges:
- **sudo -l**: List available sudo privileges for the current user.
- **dscl . -read /Groups/admin**: View members of the `admin` group.
- **sudo find / -name "*.plist"**: Search for potential launch agents that may require elevated privileges.
- **sudo launchctl list**: List loaded launch daemons/services that require elevated privileges.

### Escalate Privileges:
- **sudo /bin/bash**: Spawn a new shell with elevated privileges.
- **sudo su**: Switch to the root user.
- **sudo -u root <command>**: Run commands as the root user without switching shell.

---

## 8. **Apple-Specific Investigation Tools**

- **FSEvents**: Use this to track file system events. You can analyze `/System/Library/Logs` and `/private/var/db/fsevents` for activity related to file system changes.
- **Apple System Logs**: Located at `/var/log`, these logs are important for gathering traces of user logins, application activity, and kernel events.

---

## Conclusion

This **macOS Investigation Cheatsheet** provides a comprehensive set of techniques to investigate and analyze macOS systems. It covers areas such as system enumeration, user and group analysis, persistence mechanisms, file integrity checks, network monitoring, and more. By using these techniques, you can gain a thorough understanding of the system’s security posture, detect malicious activities, and gather valuable evidence during a penetration test or incident response.

---

