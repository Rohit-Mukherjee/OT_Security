# Linux Forensics

### Introduction to Linux

### Shells and command history

### sh

- Created by Stephen Bourne in the late 1970s at AT&T Bell Labs
- Set the standard for text-based user interfaces and shell scripting
- It's still around and used today
- It influenced Bash and Zsh, which extend sh's capabilities while maintaining compatibility with its scripts

### Bash

- Extends sh with interactive features, like command completion and history
- Developed by Brian Fox in the late 1980s for the GNU Project
- Includes all features of sh, but adds scripting enhancements, usability features, and more
- Most widely used default shell for Linux

### Bash History

- Maintains command history within a file called `. bash _ history` located within `$HOME`
- Timestamps for commands are not recorded by default, but can be enabled
- The `$HISTTIMEFORMAT` environment variable can be set to enable this

### Bash Configuration Files

- . bashrc sourced by interactive non-login shells
- . bash _ profile (or . bash _ login, then . profile if (absent) sourced for user login shells

Other Important Configuration Files:
- `/etc/profile` sourced for all users' login shells
- `/etc/bash . bashrc` typically sourced from . bashrc for system-wide Bash configurations (this can vary by distro)
- . bash _ logout will also be parsed on logout for user
login shells
- To add the timestamps in the Bash History
    - it is located in the profile of the user
    
    ![vmware_ZPYDLjQixY.png](Linux%20Forensics%2024ad487fd08d80deba30e1e3b1533515/c5d3eca1-de31-41ba-9d14-5e33c8836f44.png)
    
- As from the history command it can be seen that the timestamps are not visible in the command

![vmware_J2MaYk8UFf.png](Linux%20Forensics%2024ad487fd08d80deba30e1e3b1533515/vmware_J2MaYk8UFf.png)

- to make any changes to bashrc

```bash
nano ~/.bashrc          # edit only for your account
sudo nano /etc/bash.bashrc   # edit for all users
HISTTIMEFORMAT="%d/%m/%y %T " 
source .bashrc #this is for loading the bash profile again
```

- After doing this now we can see the timestamps being recorded in the history command which is very powerful when we try to do some IR.

![vmware_ysEg1lFK6f.png](Linux%20Forensics%2024ad487fd08d80deba30e1e3b1533515/vmware_ysEg1lFK6f.png)

### Anti Forensics on the Bash History

- Delete `. bash _ history`
- Edit `. bash _ history` to remove specific lines
- Unset the `$HISTFILE` environment variable
- Prepend commands with a <space>
    - this is a very powerfull method of the attacker bypassing the bash history defenses
- Modify Bash configuration files to disable history

### Zsh

- Maintains command history within a file called `. zsh_history` located within `$HOME`
- Timestamps for commands are not recorded by default, but can be enabled
- Maintains configuration within a file called `. zshrc` located within `$HOME`
- To enable timestamps, modify `. zshrc`:
    - `setopt EXTENDED_HISTORY`
    - `export HISTTIMEFORMAT=”[%F %T]”`

### History

Linux is basically combination of Linux Kernel and the GNU Operating System

### WSL Forensics

### **🔍 1. Inside the WSL Filesystem (Linux-side)**

These are stored **inside** the `ext4.vhdx` virtual disk for the distro:

| Artifact | Linux Path inside WSL | Notes |
| --- | --- | --- |
| Bash history | `~/.bash_history` | One per Linux user account; may be incomplete if shell didn’t exit cleanly |
| System logs | `/var/log/syslog`, `/var/log/auth.log` | WSL2 keeps these if the service is installed and logging is enabled |
| Cron logs | `/var/log/cron*` | Only if cron is installed |
| SSH logs | `/var/log/auth.log` | Shows SSH attempts if SSH server is running |
| Custom shell history | `~/.zsh_history`, etc. | Depends on the shell |

### **💾 2. Windows Host Side Storage**

These are **outside** of WSL but directly tied to it:

| Artifact | Windows Path | Notes |
| --- | --- | --- |
| WSL virtual disk | `%USERPROFILE%\AppData\Local\Packages\<DistroPackage>\LocalState\ext4.vhdx` | Contains full Linux FS; can be mounted without starting WSL |
| WSL1 rootfs | `%USERPROFILE%\AppData\Local\lxss\rootfs\` *(older WSL1)* | Direct folder structure |
| Temp interop files | `%LOCALAPPDATA%\Temp` | Files copied between Windows & WSL may appear here temporarily |
| Interop mount path | `/mnt/c` inside WSL ↔ `C:\` in Windows | Changes in one side instantly reflect in the other |

### **📝 3. Windows Event Logs**

These can show **when** and sometimes **what** was run in WSL:

- **Event Viewer → Applications and Services Logs → Microsoft → Windows → Subsystem-Linux**
    - Shows WSL start/stop, errors, etc.
- **Security Log** (Event ID 4688) — Process creation
    - If enabled, logs `wsl.exe` launches with parameters.
- **Sysmon Event ID 1** — Process creation
    - Shows exact command line (e.g., `wsl.exe -d Ubuntu bash -c "ls -la"`).

### **🕵️ 4. How to Forensically Extract History**

### **From Linux-side without starting WSL:**

1. Use **`wsl --mount`** or a Linux VM to read:
    - `Users/<username>/.bash_history`
    - `/var/log/*`
2. **Shutdown WSL completely**:
    
    ```powershell
    wsl --shutdown
    **Mount the virtual disk**:
    ```
    
    ```powershell
    Mount-VHD -Path "$env:USERPROFILE\AppData\Local\Packages\<DistroPackage>\LocalState\ext4.vhdx" -ReadOnly
    ```
    

### **⚠ Anti-Forensic Notes**

- `~/.bash_history` is only written when Bash exits normally — so killing WSL abruptly can avoid logging the last commands.
- Prepending a space before a command *may* avoid logging if `HISTCONTROL=ignorespace` is set.
- However, **Windows Event Logs and Sysmon will still record WSL.exe launches**, even if Bash history is clean.

### WSL Evidence Access Methods

| Feature / Criteria | **`\\wsl$` Live Access** | **Offline Mount of `ext4.vhdx` (Read-Only)** |
| --- | --- | --- |
| **WSL State** | Requires WSL to be **running** | WSL stays **off** |
| **Risk of altering evidence** | **High** — timestamps, logs, caches may update just by starting WSL | **Low** — read-only mount prevents changes |
| **Access method** | File Explorer → `\\wsl$\DistroName` | PowerShell: `Mount-VHD -ReadOnly` |
| **Deleted file recovery** | ❌ Not possible | ✅ Possible with forensic tools |
| **Unallocated space analysis** | ❌ Not accessible | ✅ Accessible |
| **Ease of use** | ✅ Very easy (no admin rights needed) | ⚠ Requires admin rights & mounting steps |
| **Speed** | ✅ Immediate once WSL starts | ⚠ Slight delay to mount & assign letter |
| **Integrity for court evidence** | ❌ Not suitable | ✅ Forensic sound if mounted read-only |
| **Location inside Windows** | Virtual share provided by WSL | `%USERPROFILE%\AppData\Local\Packages\<DistroPackage>\LocalState\ext4.vhdx` |
| **Access to logs & history** | ✅ Yes (current, live version) | ✅ Yes (at time of shutdown) |

### 🗺 WSL Forensic Config Map

| **Config Scope** | **File Name** | **Location in Linux (inside WSL)** | **Location on Windows Host** | **Forensic / Attack Notes** |
| --- | --- | --- | --- | --- |
| **Global (all distros)** | `.wslconfig` | *N/A* | `C:\Users\<Username>\.wslconfig` | Controls WSL VM settings (RAM, CPU, swap, networking). Can disable logging or alter networking for stealth. |
| **Per-distro** | `wsl.conf` | `/etc/wsl.conf` | Inside `ext4.vhdx` → `/etc/wsl.conf` | Enables autorun commands, starts services, changes hostname/DNS. Great persistence spot. |
| **User shell startup** | `.bashrc` | `/home/<user>/.bashrc` | Inside `ext4.vhdx` → `/home/<user>/.bashrc` | Can run malware on shell start. Common persistence vector. |
| **User login script** | `.profile` / `.bash_profile` | `/home/<user>/` | Inside `ext4.vhdx` | Runs at login; stealthier than `.bashrc` in some setups. |
| **All-user shell init** | `/etc/profile` | `/etc/profile` | Inside `ext4.vhdx` → `/etc/profile` | Affects all users. Can inject malicious exports or scripts. |
| **Profile.d scripts** | `/etc/profile.d/<script>.sh` | `/etc/profile.d/` | Inside `ext4.vhdx` | Auto-executed for all shells; persistent malware can hide here. |
| **System boot commands** | `[boot]` section in `/etc/wsl.conf` | `/etc/wsl.conf` | Inside `ext4.vhdx` | Can auto-start services (e.g., SSH, reverse shells) when WSL starts. |
| **Cron jobs (per-user)** | `crontab -e` | `/var/spool/cron/crontabs/<user>` | Inside `ext4.vhdx` | Time-based execution, stealthy persistence. |
| **Cron jobs (system)** | `/etc/crontab` | `/etc/crontab` | Inside `ext4.vhdx` | Runs as root, could launch malware periodically. |
| **Networking configs** | `/etc/hosts`, `/etc/resolv.conf` | `/etc/` | Inside `ext4.vhdx` | Can redirect DNS or block security update servers. |
| **SSH keys/config** | `.ssh/config` & private keys | `/home/<user>/.ssh/` | Inside `ext4.vhdx` | Allows backdoor access without passwords. |

### Root Directory Structure

### 📂 Linux Root Directory Structure (Forensics Reference)

| **Directory** | **Purpose** | **Forensic Notes** |
| --- | --- | --- |
| `/bin` | Essential user binaries (`ls`, `cp`, `bash`). | Check for replaced/trojanized binaries; verify file hashes. |
| `/boot` | Bootloader files, kernel images. | Look for modified init scripts or extra kernels (bootkits). |
| `/dev` | Device files (disks, terminals, etc.). | Can hide malicious named pipes or fake devices for persistence. |
| `/etc` | System-wide configuration files. | **High-value**: Inspect `/etc/passwd`, `/etc/shadow`, `/etc/hosts`, cron jobs, `/etc/sudoers`. |
| `/home` | User home directories. | Check `.bashrc`, `.profile`, `.ssh/`, hidden files for persistence. |
| `/lib`, `/lib64` | Shared libraries for binaries. | Look for malicious libraries, LD_PRELOAD tricks. |
| `/media` | Removable media mount points. | Rare, but could store staged tools or exfil files. |
| `/mnt` | Temporary mount points. | Check for unexpected mounts (e.g., attacker’s remote shares). |
| `/opt` | Optional software. | Often used for custom installs — inspect for rogue software. |
| `/proc` | Virtual filesystem with process info. | Live forensics: list processes, network connections, open files. |
| `/root` | Root user’s home directory. | **Critical**: Check for hidden tools, SSH keys, persistence scripts. |
| `/run` | Runtime data (PID files, sockets). | Check for unknown running services or malware sockets. |
| `/sbin` | System admin binaries. | Verify against known-good hashes for tampering. |
| `/srv` | Service data (web, FTP, etc.). | Check for unexpected hosted files or webshells. |
| `/sys` | Kernel and hardware info. | Rarely altered, but can be abused for privilege escalation in some exploits. |
| `/tmp` | Temporary files. | Common malware drop point; look for hidden/dated files. |
| `/usr` | User programs, docs, libraries. | `/usr/local/bin` is a common persistence location. |
| `/var` | Logs, mail, caches, spools. | **High-value**: `/var/log` for attacker traces, `/var/spool/cron` for scheduled jobs. |

### File and Directory Permissions

### 📂 Linux File Types & Permissions Table

| **Symbol** | **Type** | **Description** | **Example** |
| --- | --- | --- | --- |
| `-` | Regular file | Normal file containing data, text, or binary. | `-rw-r--r--` |
| `d` | Directory | Contains other files or directories. | `drwxr-xr-x` |
| `l` | Symbolic link | Points to another file or directory. | `lrwxrwxrwx` |
| `c` | Character device | Device file that handles data character-by-character. | `crw-------` |
| `b` | Block device | Device file that handles data in blocks. | `brw-r-----` |
| `p` | Named pipe (FIFO) | Enables inter-process communication. | `prw-r--r--` |
| `s` | Socket | Network or local socket for IPC. | `srwxr-xr-x` |

### 🔑 Permission Fields (rwx)

| **Symbol** | **Meaning** | **Value** |
| --- | --- | --- |
| `r` | Read permission | 4 |
| `w` | Write permission | 2 |
| `x` | Execute permission (or access for dirs) | 1 |
| `-` | No permission | 0 |

### 👥 Permission Groups

| **Position** | **Who** | **Example** |
| --- | --- | --- |
| 1st group | **Owner (user)** | `rwx` in `rwxr-xr--` means owner can read, write, execute. |
| 2nd group | **Group** | `r-x` means group can read & execute, but not write. |
| 3rd group | **Others (world)** | `r--` means everyone else can only read. |

### ⚙ Special Permission Bits

| **Bit** | **Symbol** | **Description** | **Example** |
| --- | --- | --- | --- |
| Setuid | `s` in user exec position | Executes file with owner’s privileges. | `-rwsr-xr-x` |
| Setgid | `s` in group exec position | Executes file with group’s privileges; for dirs, new files inherit group. | `drwxrws---` |
| Sticky bit | `t` in others exec position | For dirs, only owner can delete own files. | `drwxrwxrwt` |

### 🪢 **Permission Structure**

Permissions are in **three groups of three**:

```markdown
[User]  [Group]  [Others]
rw-     r--      r--
```

### Meaning of each character:

- `r` → Read
- `w` → Write
- `x` → Execute
- → No permission

## 🗒️SetUID, SetGID & StickyBit

### **1️⃣ Setuid (Set User ID)**

- **Symbol:** `s` in the **user (owner)** execute position.
- **Numeric value:** `4` in the thousands place (e.g., `4755`).
- **Meaning:** When a file with Setuid is executed, it runs with the **permissions of the file owner**, not the user who runs it.

Example:

```bash
-rwsr-xr-x 1 root root 12345 Aug 10 /usr/bin/passwd
```

- Owner: `root`
- Execute bit for owner is replaced with `s` → Setuid is active.
- When any user runs `/usr/bin/passwd`, it runs as **root**, allowing them to update `/etc/shadow`.

**Forensics risk:**

If a Setuid binary is vulnerable, attackers can exploit it to get **root privileges**.

### **2️⃣ Setgid (Set Group ID)**

- **Symbol:** `s` in the **group** execute position.
- **Numeric value:** `2` in the thousands place (e.g., `2755`).
- **Meaning:**
    - On **files**: Runs with the **group permissions** of the file.
    - On **directories**: New files inside inherit the **group ownership** of the directory.

Example (binary):

```bash
-rwxr-sr-x 1 root mail 12345 Aug 10 /usr/bin/procmail
```

- Group: `mail`
- Execute bit for group is replaced with `s` → Setgid active.

Example (directory):

```bash
drwxr-sr-x 2 root staff 4096 Aug 10 /shared
```

- Any new file in `/shared` will belong to the `staff` group.

**Forensics risk:**

On binaries — can escalate group privileges.

On directories — can keep sensitive files grouped together but could be abused for persistence.

### **3️⃣ Sticky Bit**

- **Symbol:** `t` in the **others** execute position.
- **Numeric value:** `1` in the thousands place (e.g., `1777`).
- **Meaning:**
    - On **directories**: Only the file’s owner (or root) can delete/rename files, even if the directory is world-writable.
    - On **files** (legacy): Was used to keep the program in memory for speed — now mostly obsolete.

Example:

```bash
drwxrwxrwt 10 root root 4096 Aug 10 /tmpWorld-writable (`777`) but **sticky bit** (`t`) prevents users from deleting each other’s files.
```

**Forensics risk:**

If a world-writable directory **does not** have the sticky bit, any user can delete or replace files belonging to others — an easy persistence trick.

### Users and Groups

### **What is a User in Linux?**

A **user** is an account that can log in or run processes.

Each user has:

- **Username** (`bob`, `root`)
- **UID** (User ID — number)
- **Home directory** (`/home/bob`)
- **Default shell** (`/bin/bash`)

Example from `/etc/passwd`:

```
bob:x:1000:1000:Bob Smith,,,:/home/bob:/bin/bash
```

- `bob` → Username
- `x` → Password stored in `/etc/shadow`
- `1000` → UID (User ID)
- `1000` → GID (Group ID)
- `Bob Smith,,,` → Info field
- `/home/bob` → Home directory
- `/bin/bash` → Login shell

### **What is a Group in Linux?**

A **group** is a collection of users, mainly for permissions.

- **Primary group** → linked in `/etc/passwd`
- **Secondary groups** → stored in `/etc/group`

Example from `/etc/group`:

```
admins:x:1001:alice,bob
```

- `admins` → Group name
- `x` → Password placeholder
- `1001` → GID (Group ID)
- `alice,bob` → Members

### **Permissions Relationship**

When you run:

```bash
ls -l file.txt
```

You might see:

```
-rw-r----- 1 alice admins 1234 Aug 10 file.txt
```

This means:

- **Owner**: `alice` (can read + write)
- **Group**: `admins` (can read)
- **Others**: no access

### **Special User & Group IDs**

| UID/GID | Name | Purpose |
| --- | --- | --- |
| 0 | root | Full system control |
| 1–999 | System accounts | Services like `daemon`, `www-data` |
| 1000+ | Regular users | Human accounts |

### **Purpose of `/etc/passwd`**

- **Location:** `/etc/passwd`
- **Purpose:** Stores **user account information**.
- **Permissions:** World-readable (`rw-r--r--`), but **not** writable by normal users.
- **Reason it’s world-readable:** Programs need to map UIDs to usernames (e.g., when showing file owners with `ls -l`).

### 🛖 **Structure**

Each line represents **one user account**.

Fields are separated by colons (`:`):

```
username:password:UID:GID:GECOS:home_directory:shell
```

### 🎀 **Field-by-Field Explanation**

| **Field** | **Example** | **Meaning** | **Security / Forensic Notes** |
| --- | --- | --- | --- |
| **1. Username** | `bob` | Login name (unique) | Short, lowercase, no spaces. Look for suspicious names like `.` or `root1`. |
| **2. Password** | `x` | Traditionally stores password hash here, but now replaced with `x` meaning “hash is in `/etc/shadow`”. | If this field contains a **real hash** instead of `x`, the system is using **insecure legacy mode**. |
| **3. UID (User ID)** | `1000` | Numeric ID for the user. UID 0 = root. System users usually have UIDs < 1000. | Malicious UID change to `0` gives attacker root privileges. |
| **4. GID (Group ID)** | `1000` | Primary group’s numeric ID. Maps to `/etc/group`. | If attacker changes this to an admin group (like `sudo`), they escalate privileges. |
| **5. GECOS (User Info)** | `Bob Smith,,555-1234` | Free text for full name, phone, etc. | Rarely abused, but can hide encoded data here. |
| **6. Home Directory** | `/home/bob` | Default location after login. | Suspicious if set to `/` or another user’s home. |
| **7. Shell** | `/bin/bash` | Default shell when logging in. `/sbin/nologin` or `/bin/false` means no login allowed. | Attackers may change to `/bin/bash` to enable login for service accounts. |

### 🧂 **Example of etc/passwd**

```
root:x:0:0:root:/root:/bin/bash
bob:x:1000:1000:Bob Smith,,555-1234:/home/bob:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
```

- **root** → UID 0, full control
- **bob** → Regular human user
- **daemon** → System account for background processes, no login

### **📜 `/etc/shadow` — Complete Guide**

The `/etc/shadow` file stores **secure account information** for local users, including their **password hashes** and **password policy settings**.

Only `root` can read this file because it contains sensitive authentication data.

### **1. Structure**

Each line in `/etc/shadow` represents one account, with **colon-separated fields**:

```
username:password:lastchg:min:max:warn:inactive:expire:reserved
```

| Field # | Name | Purpose | Example |
| --- | --- | --- | --- |
| 1 | **username** | Login name of the account. | `bob` |
| 2 | **password** | Hashed password + algorithm ID, or a special value. | `$6$rounds=5000$salt$hash` |
| 3 | **lastchg** | Days since 1 Jan 1970 when password was last changed. | `19500` |
| 4 | **min** | Minimum number of days before the password can be changed. | `0` |
| 5 | **max** | Maximum number of days the password is valid. | `90` |
| 6 | **warn** | Days before expiration to warn the user. | `7` |
| 7 | **inactive** | Days after expiration before account is disabled. | `0` |
| 8 | **expire** | Days since 1 Jan 1970 when account will be disabled. | `-1` (no expiry) |
| 9 | **reserved** | Reserved for future use (often blank). | *(empty)* |

### **2. Password Field (Field #2)**

The password field can have **three types** of values:

### a) **Hashed password**

Format:

```
$id[$params]$salt$hash
```

| Component | Meaning |
| --- | --- |
| `$id` | Algorithm ID (see table below). |
| `$params` | Optional extra settings (e.g., rounds count). |
| `salt` | Random string used to make each hash unique. |
| `hash` | The actual password hash. |

### b) **Special values**

- `!` — Account locked (password authentication disabled).
- — Similar to `!`, but also means no password was ever set.
- Empty string (`""`) — No password required (login without password — **very dangerous**).

### **3. Algorithm IDs**

| ID / Prefix | Algorithm | Example in `/etc/shadow` | Strength / Notes |
| --- | --- | --- | --- |
| *(no `$`)* | Traditional DES | `abCDefghijk` | Very weak, legacy only. |
| `$1$` | MD5-crypt | `$1$salt$hash` | Weak — should be avoided. |
| `$2a$`, `$2b$`, `$2y$` | bcrypt | `$2y$12$salt...` | Strong, adaptive. |
| `$5$` | SHA-256-crypt | `$5$rounds=10000$salt$hash` | Good, supports rounds. |
| `$6$` | SHA-512-crypt | `$6$rounds=10000$salt$hash` | Strong, default on many distros. |
| `$argon2i$`, `$argon2id$` | Argon2 | `$argon2id$v=19$m=65536,t=2,p=1$...` | Very strong, memory-hard. |

### **4. Example Line with Explanation**

```
bob:$6$rounds=10000$XyZ123abc$abcdef1234567890...:19500:0:90:7:0:-1:
```

- **bob** → username
- **$6$** → SHA-512 hashing
- **rounds=10000** → more iterations to slow brute force
- **XyZ123abc** → salt
- **abcdef1234567890...** → hashed password
- **19500** → password last changed 19500 days since 1970 (~2023)
- **0** → can change password anytime
- **90** → password expires after 90 days
- **7** → user gets 7 days warning before expiry
- **0** → account disabled immediately after expiry
- **1** → account never expires

### **5. Security & Forensics Notes**

| Forensic Indicator | Meaning / Action |
| --- | --- |
| `!` or `*` at start | Account locked — can't log in via password. |
| Empty password field | No password required — check immediately. |
| `$1$` (MD5) present | Weak — upgrade hash algorithm. |
| `$5$` or `$6$` | Acceptable but not as strong as bcrypt/Argon2. |
| `$argon2id$` | Very strong — modern best practice. |
| Low `rounds` (<5000) | Easier to brute force — increase rounds. |
| Very old `lastchg` | Might indicate long-unused account — review/remove. |

### **Linux Logs**

### Authentication and Security Logs

### **PAM**

**PAM** stands for **Pluggable Authentication Modules**.

It’s basically the **authentication framework** that most modern Linux systems use to decide:

> Who are you? How should I verify you? And should I let you in?
> 

Instead of each program (like `login`, `sudo`, `ssh`) writing its own authentication code, PAM provides a **shared, modular system** where you can “plug in” different authentication methods.

### **1. How PAM Works**

When a program needs authentication:

1. The program calls PAM.
2. PAM looks up its config files in `/etc/pam.d/` (or `/etc/pam.conf`).
3. The config file lists modules (plugins) to run — for example:
    - Check the password hash in `/etc/shadow`
    - Require a 2FA code
    - Check fingerprint
    - Authenticate against LDAP/Active Directory
4. If all required modules say “OK” → access granted.

### **2. PAM Configuration**

Each service (e.g., `sudo`, `sshd`, `passwd`) has its own config file inside `/etc/pam.d/`.

Example: `/etc/pam.d/sudo`

```
auth    required    pam_env.so
auth    required    pam_unix.so
account required    pam_unix.so
session required    pam_unix.so
```

- **auth** → Verifies identity (passwords, tokens, biometrics)
- **account** → Checks account status (locked, expired, etc.)
- **password** → Changes or updates passwords
- **session** → Manages things after login (mounting drives, logging, etc.)

### **3. Example PAM Modules**

| Module | Purpose | Example Use |
| --- | --- | --- |
| `pam_unix.so` | Standard Linux `/etc/passwd` + `/etc/shadow` authentication | Local logins |
| `pam_tally2.so` | Lock account after too many failed logins | Brute-force protection |
| `pam_google_authenticator.so` | 2FA via Google Authenticator | SSH MFA |
| `pam_faillock.so` | Track failed logins | Security monitoring |
| `pam_ldap.so` | Authenticate against LDAP server | Enterprise logins |
| `pam_pkcs11.so` | Smartcard authentication | Gov/enterprise systems |

### **Deep-dive into how PAM does those four authentication methods**

### **1. Check the password hash in `/etc/shadow`**

**Module used:** `pam_unix.so`

**Type:** Local authentication

**Process:**

1. User types a password.
2. PAM calls `pam_unix.so`.
3. `pam_unix.so` reads `/etc/shadow` (root-only readable).
4. Finds the matching username → extracts hash string (`$id$salt$hash`).
5. Uses the `$id` to select the correct hashing algorithm (SHA-512, bcrypt, Argon2, etc.).
6. Hashes the entered password with the same **salt** and algorithm.
7. If the result matches the stored hash → authentication success.

**Security notes:**

- If `/etc/shadow` is stolen → offline cracking possible.
- If `pam_unix.so` is replaced with a malicious version → passwords can be logged in plaintext.
- Default algorithm is configured in `/etc/login.defs` (`ENCRYPT_METHOD`).

**Forensics:**

- Watch `/etc/shadow` with integrity monitoring (`tripwire`, `auditd`).
- Review `/etc/login.defs` to see chosen algorithm and parameters.

### **2. Require a 2FA code**

**Module used:** Examples:

- `pam_google_authenticator.so`
- `pam_oath.so`
- `pam_yubico.so`

**Type:** Time-based One-Time Password (TOTP) or hardware token authentication.

**Process (TOTP example like Google Authenticator):**

1. User enters username & password.
2. PAM verifies password via `pam_unix.so`.
3. Then `pam_google_authenticator.so` prompts for a **6-digit code**.
4. The code is verified using:
    - The secret key stored in the user’s home (`~/.google_authenticator`)
    - The current timestamp (TOTP changes every 30 seconds).
5. If correct → access granted.

**Security notes:**

- Even if the password is stolen, attacker needs the TOTP secret.
- Secret file `~/.google_authenticator` should be `chmod 400`.
- Can be bypassed if PAM configs are edited to remove the 2FA step.

**Forensics:**

- Look for modifications in `/etc/pam.d/` service files (e.g., `sshd` config) that remove `pam_google_authenticator.so`.
- Review `/var/log/auth.log` for 2FA failures.

### **3. Check fingerprint**

**Module used:** `pam_fprintd.so`

**Type:** Biometric authentication

**Process:**

1. User attempts login (GUI or terminal).
2. PAM calls `pam_fprintd.so` which interacts with `fprintd` daemon.
3. Fingerprint scanner captures fingerprint data.
4. Template is compared to stored biometric data in `/var/lib/fprint/`.
5. If match → PAM says "OK".

**Security notes:**

- Biometrics are not stored as raw images, but as feature templates.
- Templates can’t be easily “changed” if leaked (unlike passwords).
- Requires compatible hardware & drivers.

**Forensics:**

- Check `/var/log/fprintd.log` for usage.
- Monitor `/var/lib/fprint/` for changes (could indicate template replacement attack).

### **4. Authenticate against LDAP/Active Directory**

**Modules used:**

- `pam_ldap.so` (LDAP)
- `pam_winbind.so` or `pam_sss.so` (Active Directory via Samba/SSSD)

**Type:** Centralized network authentication

**Process:**

1. User enters username & password.
2. PAM module sends credentials to an LDAP or AD server.
3. Server verifies:
    - Username exists
    - Password hash matches
    - Account is active (not expired/locked)
4. Server responds with success/failure.
5. PAM applies local authorization rules.

**Security notes:**

- If LDAP/AD server is compromised, all connected systems are at risk.
- PAM configs can be forced to "fall back" to local accounts if server unreachable (could be abused).
- Communication should be encrypted (LDAPS, Kerberos).

**Forensics:**

- Monitor `/var/log/secure` or `/var/log/auth.log` for remote auth failures.
- Check `/etc/pam_ldap.conf` or `/etc/sssd/sssd.conf` for server details (and encryption).

### **Summary Table**

| Method | PAM Module | Storage Location | Risk if Compromised | Forensic Focus |
| --- | --- | --- | --- | --- |
| Local `/etc/shadow` | `pam_unix.so` | `/etc/shadow` | Offline password cracking | Monitor file integrity & algorithm |
| TOTP 2FA | `pam_google_authenticator.so` | `~/.google_authenticator` | Bypass if PAM config edited | Log & config monitoring |
| Fingerprint | `pam_fprintd.so` | `/var/lib/fprint/` | Template replacement attack | Watch biometric storage |
| LDAP/AD | `pam_ldap.so` / `pam_sss.so` | LDAP/AD server | Mass credential theft | Network traffic + config audit |

### **PAM authentication flow diagram**

![vlc_yFkbZYKJCa.png](Linux%20Forensics%2024ad487fd08d80deba30e1e3b1533515/vlc_yFkbZYKJCa.png)

```
    ┌─────────────────────────────────────────┐
    │ User tries to log in (ssh, sudo, etc.)   │
    └─────────────────────────────────────────┘
                      │
                      ▼
         ┌────────────────────────┐
         │ PAM starts auth process │
         └────────────────────────┘
                      │
                      ▼
 ┌────────────────────────────────────┐
 │ Step 1: Password check              │
 │ Module: pam_unix.so                 │
 │ Reads /etc/shadow, hashes password  │
 │ → If fail → reject login            │
 └────────────────────────────────────┘
                      │
                      ▼
 ┌────────────────────────────────────┐
 │ Step 2: Two-Factor Auth (TOTP)      │
 │ Module: pam_google_authenticator.so │
 │ Verifies code in ~/.google_authenticator │
 │ → If fail → reject login            │
 └────────────────────────────────────┘
                      │
                      ▼
 ┌────────────────────────────────────┐
 │ Step 3: Biometric Check (Fingerprint) │
 │ Module: pam_fprintd.so              │
 │ Compares scan with /var/lib/fprint/ │
 │ → If fail → reject login            │
 └────────────────────────────────────┘
                      │
                      ▼
 ┌────────────────────────────────────┐
 │ Step 4: LDAP/AD Network Auth        │
 │ Module: pam_ldap.so / pam_sss.so    │
 │ Sends credentials to remote server │
 │ → If fail → reject login            │
 └────────────────────────────────────┘
                      │
                      ▼
    ┌─────────────────────────────────────────┐
    │ PAM grants access, starts user session  │
    └─────────────────────────────────────────┘

```

### `/etc/security` directory details

`/etc/security` is where many **PAM-related and login security policy files** live in Linux (including Mint, Debian, RHEL).

`/etc/security` Directory Reference

| File / Directory | Purpose | Key Config Parameters | Security & Forensic Notes |
| --- | --- | --- | --- |
| **access.conf** | Restrict access to services based on user/group and host | `+ : user : host` / `- : group : ALL` | Can block/allow specific accounts from logging in remotely; check for whitelist/blacklist tampering |
| **faillock.conf** | Configures login failure tracking & lockouts | `deny=`, `unlock_time=`, `fail_interval=` | Protects against brute-force; forensic logs stored in `/var/run/faillock/` |
| **group.conf** | Controls group-based password aging & policies | `GROUP_MIN`, `GROUP_MAX` | Rarely used, but changes may impact multi-user security |
| **limits.conf** | Sets resource limits per user/group | `nofile`, `nproc`, `cpu`, `memlock` | Attackers may increase limits to aid DoS or malware persistence |
| **limits.d/** | Directory for per-package or per-service limits | Same as `limits.conf` | Can override global limits; useful to spot service-specific abuse |
| **namespace.conf** | Defines namespace isolation settings | `uid`, `pid`, `net` namespace mappings | Security-hardening feature; tampering may weaken container/VM isolation |
| **namespace.d/** | Drop-in config for namespace rules | — | Check for unexpected additions by attacker scripts |
| **pam_env.conf** | Environment variables for PAM sessions | `VARIABLE DEFAULT OVERRIDE` | Attackers may set malicious `PATH` or preload libraries here |
| **pam_env.d/** | Drop-in environment config files | Same as above | Useful for targeted service-level environment injection |
| **sepermit.conf** | Allows login only when certain SELinux conditions are met | SELinux booleans | Rare; tampering here may allow bypass of SELinux restrictions |
| **time.conf** | Time-based access control for logins | `login ; tty ; time range` | Used to restrict login hours; attackers could widen allowed window |
| **pwquality.conf** | Password complexity rules | `minlen=`, `ucredit=`, `lcredit=`, `dcredit=`, `ocredit=` | Weakening these rules aids password guessing |
| **dictionaries/** | Wordlists used for password quality checks | Text files of words | If replaced with empty file → password policy may become useless |

### **PAM Module Locations by Distro Family**

| Distro Family | Common Path for PAM Modules | Example |
| --- | --- | --- |
| **Debian / Ubuntu / Mint** | `/usr/lib/x86_64-linux-gnu/security/` | `pam_unix.so`, `pam_google_authenticator.so` |
| **Debian (32-bit)** | `/usr/lib/i386-linux-gnu/security/` | Same module names, 32-bit build |
| **RHEL / CentOS / Fedora** | `/lib64/security/` (64-bit) or `/lib/security/` (32-bit) | `pam_unix.so`, `pam_tally2.so` |
| **Arch Linux** | `/usr/lib/security/` | Minimalistic, no arch subdir |

### Auth.log

### **What `/var/log/auth.log` Contains**

- **Purpose:**
    
    This is the main authentication log file for Debian-based systems (Mint, Ubuntu, Kali).
    
    It records **security-related events**, including:
    
    - Successful & failed logins (local & remote)
    - `sudo` usage
    - SSH login attempts
    - PAM authentication results
    - Key generation and login via keys
    - User account changes

### **Example Log Entries**

```
Feb 12 10:32:21 mint sudo:    rohit : TTY=pts/0 ; PWD=/home/rohit ; USER=root ; COMMAND=/bin/cat /etc/shadow
Feb 12 10:33:45 mint sshd[1432]: Failed password for invalid user admin from 192.168.0.5 port 45712 ssh2
Feb 12 10:34:12 mint sshd[1432]: Accepted password for rohit from 192.168.0.10 port 45713 ssh2
Feb 12 10:34:12 mint sshd[1432]: pam_unix(sshd:session): session opened for user rohit

```

### **Viewing Live Logs**

```bash
sudo tail -f /var/log/auth.log
```

- `f` = follow the log in real time (like watching a security feed)
- Good for **live SSH brute-force monitoring** or checking if PAM configs work.

### **Searching Historical Logs**

### **Using `grep`**

```bash
sudo grep "Failed password" /var/log/auth.log
```

Finds all failed login attempts.

```bash
sudo grep "rohit" /var/log/auth.log
```

Search for entries related to a specific username.

### **Working with Compressed Logs**

Older auth logs are rotated & compressed (`auth.log.1`, `auth.log.2.gz`, etc.).

### **View compressed logs without extracting**

```bash
sudo zcat /var/log/auth.log.2.gz
```

Shows the whole file.

### **Search inside compressed logs**

```bash
sudo zgrep "Failed password" /var/log/auth.log.2.gz
```

Performs a grep search directly inside `.gz` logs.

### **Useful Forensic Commands**

| Task | Command |
| --- | --- |
| Show all failed SSH logins | `sudo grep "Failed password" /var/log/auth.log` |
| Show all successful SSH logins | `sudo grep "Accepted password" /var/log/auth.log` |
| Count failed attempts per IP | `sudo grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -nr` |
| Show all `sudo` attempts | `sudo grep "sudo" /var/log/auth.log` |
| Follow log in real-time | `sudo tail -f /var/log/auth.log` |
| Search old compressed logs for "root" | `sudo zgrep "root" /var/log/auth.log.*.gz` |

### **Forensic Notes**

- **Tampering Signs:**
    
    Missing entries, out-of-order timestamps, or recent file modification (`stat /var/log/auth.log`) can indicate log manipulation.
    
- **Persistence Check:**
    
    Look for repeated failed login attempts followed by success — could indicate brute-force.
    
- **Lateral Movement:**
    
    Multiple logins from unusual IP ranges may suggest compromise.
    

### **`faillog`**

- **Purpose:** Tracks **failed login attempts** for each user.
- **Location:** `/var/log/faillog` (binary format — must be viewed with `faillog` command).
- **Source:** Information comes from **PAM** modules like `pam_tally` or `pam_faillock`.

### **Commands**

```bash
sudo faillog
```

Shows a table:

```
Login     Failures Maximum Latest
rohit     3        0       02/12/25 10:32:21
root      0        0       01/12/25 09:01:45
```

```bash
sudo faillog -u rohit
```

View failed attempts for a single user.

```bash
sudo faillog -r -u rohit
```

Reset failed login counter for a user (useful if they got locked out).

```bash
sudo faillog -m 3 -u rohit
```

Set **maximum allowed failed logins** before account lockout.

**Forensics Use:**

- Quickly check brute-force attempts against specific accounts.
- See if an attacker triggered account lockouts.

---

### **`lastlog`**

- **Purpose:** Shows the **most recent successful login** for every user.
- **Location:** `/var/log/lastlog` (binary format — must be viewed with `lastlog` command).
- **Source:** Updated by login programs (e.g., `login`, `sshd`) after successful authentication.

### **Commands**

```bash
sudo lastlog
```

Shows:

```
Username         Port     From             Latest
root             pts/0    192.168.0.10     Tue Feb 12 10:34:12 +0530 2025
rohit            pts/1    192.168.0.15     Mon Feb 10 14:11:33 +0530 2025
nobody           **Never logged in**
```

```bash
sudo lastlog -u rohit
```

Show last login for a specific user.

```bash
sudo lastlog -t 7
```

Show users who logged in **within the last 7 days**.

```bash
sudo lastlog -b 7
```

Show users whose last login was **more than 7 days ago**.

**Forensics Use:**

- Detect unusual login times.
- Spot dormant accounts suddenly being used.
- Identify remote IPs for user sessions.

### u/w/b/tmp

### **Overview Table**

| File | Location | Purpose | Command to Read |
| --- | --- | --- | --- |
| **`utmp`** | `/var/run/utmp` | Current **active** logins & sessions | `who`, `w` |
| **`wtmp`** | `/var/log/wtmp` | History of all logins & logouts | `last` |
| **`btmp`** | `/var/log/btmp` | History of **failed** login attempts | `lastb` |

### Syslogs and Kernel Logs

### Syslog

### **What is syslog?**

- **Syslog** is a standard logging protocol used by Unix/Linux systems to record system messages and events.
- It is **not a single file**, but a system-wide logging **service** that can collect messages from:
    - Kernel
    - System services (systemd, cron, sshd, etc.)
    - Applications
    - Remote systems (if configured)
- In Debian-based systems (like Linux Mint), the main file is:
    
    ```
    /var/log/syslog
    ```
    
    On RHEL/CentOS, it’s usually:
    
    ```
    /var/log/messages
    ```
    

### **How syslog works**

- Messages are sent to **syslog daemon** (`rsyslogd` in most modern distros).
- Each message has:
    1. **Facility** (which part of the system created it, e.g., `auth`, `cron`, `kern`)
    2. **Severity level** (importance: `emerg`, `alert`, `crit`, `err`, `warning`, `notice`, `info`, `debug`)
    3. **Message body** (human-readable event)

Example format:

```
Aug 12 10:05:01 mint CRON[2342]: (root) CMD (apt update)
```

- **Timestamp**: `Aug 12 10:05:01`
- **Host**: `mint`
- **Process**: `CRON[2342]`
- **Message**: `(root) CMD (apt update)`

### **Syslog facilities**

| Facility | Description |
| --- | --- |
| `auth` / `authpriv` | Authentication (login, su, sudo) |
| `cron` | Cron jobs |
| `daemon` | System daemons |
| `kern` | Kernel messages |
| `mail` | Mail server logs |
| `syslog` | Syslog internal messages |
| `user` | User processes |
| `local0` – `local7` | Custom applications |

### **Syslog severity levels**

| Code | Keyword | Meaning |
| --- | --- | --- |
| 0 | emerg | System unusable |
| 1 | alert | Action must be taken immediately |
| 2 | crit | Critical condition |
| 3 | err | Error condition |
| 4 | warning | Warning condition |
| 5 | notice | Normal but significant |
| 6 | info | Informational |
| 7 | debug | Debug-level message |

### **Syslog forensic importance**

- Useful to **trace system activity** before, during, and after incidents.
- Can show:
    - Unauthorized login attempts (ties with `/var/log/auth.log`)
    - Service start/stop events
    - Kernel panics
    - Cron job executions
- Attackers may **tamper** with `/var/log/syslog` to hide their tracks — forensic snapshots should be taken early.

### **Commands for syslog analysis**

| Command | Purpose |
| --- | --- |
| `tail -f /var/log/syslog` | View live syslog events |
| `grep sshd /var/log/syslog` | Filter SSH events |
| `zgrep -i "error" /var/log/syslog.*.gz` | Search compressed archived logs |
| `journalctl -u ssh` | View SSH logs (systemd journal) |
| `logger "Test message"` | Send test message to syslog |

### dmesg

### **1. What is `dmesg`?**

- **`dmesg`** = **Display Message** (short for “diagnostic messages”).
- It prints the **kernel ring buffer**, which contains messages from the Linux kernel.
- Mainly shows **boot messages** and **hardware-related events**:
    - Device initialization
    - Driver loading
    - Kernel warnings/errors
    - Plug-and-play device detection (USB insert/remove)
    - Filesystem mounting errors

### **2. How it works**

- The kernel stores its messages in a **ring buffer** (a circular memory area).
- `dmesg` simply reads that buffer and displays its contents.
- Messages are generated **very early in the boot process**, before syslog is even running.
- After boot, it also logs **real-time kernel events** (e.g., USB insertion).

### **3. Typical uses**

### View boot sequence

```bash
dmesg | less
```

Shows everything from kernel load to device driver initialization.

### Show only recent messages

```bash
dmesg | tail
```

### Show timestamps

```bash
dmesg -T
```

This converts raw kernel time (seconds since boot) into human-readable time.

### Filter for USB events

```bash
dmesg | grep -i usb
```

### **4. Forensic importance**

- **Hardware evidence**: Lists all detected devices at boot (HDDs, USB drives, network cards).
- **USB device tracing**: Shows when removable drives were plugged in or removed — key in data theft investigations.
- **Kernel exploit detection**: May reveal kernel panic traces, unusual driver loading, or module insertions (`insmod`/`modprobe`).
- **Rootkit detection**: Suspicious kernel modules can be spotted here.

### **5. Example output**

```
[    0.000000] Linux version 5.15.0-78-generic (buildd@lcy02-amd64-031)
[    0.123456] USB 2-1: new high-speed USB device number 4 using xhci_hcd
[    0.223456] EXT4-fs (sda1): mounted filesystem with ordered data mode
```

- **`[ 0.123456]`** → Seconds since boot.
- **`USB 2-1: ...`** → Device event (USB inserted).
- **`EXT4-fs (sda1)`** → Filesystem mount event.

### **6. Key differences from `/var/log/kern.log`**

| Feature | `dmesg` | `/var/log/kern.log` |
| --- | --- | --- |
| Source | Kernel ring buffer (RAM) | Syslog from kernel facility |
| Persistence | Lost after reboot (unless saved) | Saved to disk |
| Use case | Quick real-time hardware/kernel debug | Historical analysis |

### kern.log

### **What it is**

- **`/var/log/kern.log`** stores **kernel messages** that are sent via the syslog service.
- It’s essentially the **persistent version of `dmesg`**, saved to disk.
- Found in Debian/Ubuntu/Linux Mint systems (on RHEL/CentOS, kernel logs are in `/var/log/messages`).

### **What it contains**

- Boot messages (kernel version, hardware detection)
- Driver loading/unloading
- Hardware events (USB insertion/removal, disk I/O errors)
- Kernel warnings/errors (e.g., `EXT4-fs error`, `Out of memory`)
- Security-relevant kernel events (e.g., module insertion)

### **Forensic use**

- **Persistent record** of what `dmesg` showed — survives reboots.
- Lets you **correlate timestamps** with events in `/var/log/syslog` or `/var/log/auth.log`.
- Useful for:
    - Tracking removable device usage
    - Investigating hardware failures
    - Detecting suspicious kernel module activity

### **Example**

```
text
CopyEdit
Aug 12 09:25:31 mint kernel: [    1.234567] EXT4-fs (sda1): mounted filesystem with ordered data mode
Aug 12 09:25:31 mint kernel: [    1.456789] usb 2-1: new high-speed USB device number 4 using xhci_hcd

```

- Matches `dmesg` but with:
    - **Real timestamps**
    - Saved permanently (until rotated)

### journalctl

### **1. What are journal logs?**

- **journal logs** are stored by **systemd-journald**, the logging component of **systemd** (used in most modern Linux distros like Mint, Ubuntu, Fedora).
- Unlike `/var/log/syslog` (plain text), journal logs are **binary** — faster, more structured, and can store richer metadata.
- Can record:
    - Kernel messages
    - Syslog messages
    - Standard output/error from services
    - Metadata (PID, UID, SELinux context, etc.)

### **2. Location**

By default, stored in:

- `/run/log/journal/` → **Volatile logs** (lost after reboot)
- `/var/log/journal/` → **Persistent logs** (kept after reboot)
    
    *(Persistent directory might need to be created manually: `sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal`)*
    

### **3. Viewing logs with `journalctl`**

### **Basic usage**

```bash
journalctl
```

Shows the entire log from oldest to newest.

---

### **Show only current boot**

```bash
journalctl -b
```

### **Follow live logs (like `tail -f`)**

```bash
journalctl -f
```

### **Filter by service**

```bash
journalctl -u ssh
```

or

```bash
journalctl -u ssh --since today
```

### **Filter by time**

```bash
journalctl --since "2025-08-12 09:00" --until "2025-08-12 10:00"
```

### **Show kernel logs only**

`journalctl` is the main tool for reading systemd journal logs.

```bash
journalctl -k
```

### **4. Forensic value**

- **Centralized**: Everything is in one place — no need to check separate `/var/log/*` files.
- **Tamper detection**: Binary format is harder (but not impossible) to edit without leaving traces.
- **Detailed metadata**: Can identify *which* process, user, or system component generated a log.
- **Historical searches**: Easier to query with time ranges, service names, or severity levels.

### **5. Comparison with `/var/log/syslog`**

| Feature | syslog (/var/log) | journalctl |
| --- | --- | --- |
| Storage format | Plain text | Binary |
| Persistence | Yes | Depends on config |
| Querying | `grep`/`awk` | Built-in filters |
| Metadata | Limited | Rich (PID, UID, SELinux, etc.) |
| Ease of tampering | Easier to edit | Harder, but still possible |

### Web Services Logs

### **Apache Logs (Linux)**

| Log File | Location (Debian/Ubuntu) | Location (RHEL/CentOS) | Purpose |
| --- | --- | --- | --- |
| **access.log** | `/var/log/apache2/access.log` | `/var/log/httpd/access_log` | Records every request (IP, URL, method, status, referrer, user-agent). |
| **error.log** | `/var/log/apache2/error.log` | `/var/log/httpd/error_log` | Records server errors (404s, PHP errors, misconfigs). |
| **other_vhosts_access.log** | `/var/log/apache2/other_vhosts_access.log` | May vary | Logs requests to virtual hosts not explicitly defined in configs. |
| **ssl_access.log / ssl_error.log** | `/var/log/apache2/` | `/var/log/httpd/` | Logs SSL/TLS-specific access and errors. |
| **rotated logs** | `/var/log/apache2/*.gz` | `/var/log/httpd/*.gz` | Archived logs managed by `logrotate`. |

### **Nginx Logs (Linux)**

| Log File | Location (Debian/Ubuntu) | Location (RHEL/CentOS) | Purpose |
| --- | --- | --- | --- |
| **access.log** | `/var/log/nginx/access.log` | `/var/log/nginx/access.log` | Records all client requests (IP, method, status, referrer, UA). |
| **error.log** | `/var/log/nginx/error.log` | `/var/log/nginx/error.log` | Logs errors, crashes, permission issues, failed requests. |
| **site-specific logs** | `/var/log/nginx/<site>_access.log`, `/var/log/nginx/<site>_error.log` | Same | Per-domain logging (set in `/etc/nginx/sites-available/` configs). |
| **rotated logs** | `/var/log/nginx/*.gz` | `/var/log/nginx/*.gz` | Archived logs managed by `logrotate`. |

### Linux Firewall Logs

### **📊 Linux Firewall Tools Comparison**

| Firewall Tool | Backend | Default Distros | Syntax & Ease | Key Features | Logging | Config Location |
| --- | --- | --- | --- | --- | --- | --- |
| **iptables** (legacy) | Netfilter | Older Debian, Ubuntu (<20), CentOS 6/7 | Medium – rule chains with `-A`, `-j DROP/ACCEPT` | Classic tool, supports tables (filter, nat, mangle), chain-based rules | Kernel logs (`/var/log/kern.log`, `/var/log/messages`, `journalctl -k`) | `/etc/iptables/rules.v4` (Debian), `/etc/sysconfig/iptables` (RHEL) |
| **nftables** (modern) | Netfilter | Default in Debian ≥10, Ubuntu ≥20.04, Fedora, RHEL 8+ | Medium – simpler, unified syntax | Replaces iptables, IPv4/IPv6 in one ruleset, faster, efficient | Same as iptables (`dmesg`, journalctl) | `/etc/nftables.conf` |
| **ufw** (Uncomplicated Firewall) | iptables/nftables | Ubuntu, Linux Mint, Debian | Easy – human readable (`ufw allow 22`) | Simplified firewall, beginner-friendly, IPv4 & IPv6 support, profiles | `/var/log/ufw.log` (separate log file) | `/etc/ufw/` |
| **firewalld** | nftables | Fedora, RHEL, CentOS, openSUSE | Medium/Easy – uses zones & services | Dynamic firewall, zone-based (public, internal, trusted), runtime & permanent configs | `journalctl -u firewalld`, syslog | `/etc/firewalld/` |

### Cilium

### 🔹 1. Introduction

- **Cilium** is an **open-source networking, security, and observability tool** for **containerized applications** (Kubernetes, Docker, microservices).
- It uses **eBPF (Extended Berkeley Packet Filter)** in the Linux kernel to provide **high-performance** packet filtering, monitoring, and enforcement.
- Unlike **iptables/nftables**, which rely on **IP + Port rules**, Cilium enforces **identity-based, service-aware policies**.

### 🔹 2. Why Cilium?

| Traditional Firewalls (iptables, nftables) | Cilium |
| --- | --- |
| Rule-based: IP, Port, Protocol only. | Identity-based: Pods, services, labels. |
| Not Kubernetes-aware. | Deep Kubernetes integration. |
| Slower (packet traverses rule chains). | Faster (eBPF kernel programs). |
| Hard to trace microservice flows. | Full observability with **Hubble**. |
| Coarse-grained security. | Fine-grained, per-service security. |

### 🔹 3. Cilium Architecture

- **Kernel Layer (eBPF):** Cilium injects eBPF programs into the Linux kernel to filter, forward, and monitor packets.
- **Cilium Agent:** Runs as a daemonset on each Kubernetes node, managing policies & BPF maps.
- **Cilium Operator:** Provides cluster-wide functionality.
- **Hubble:** Observability layer for network monitoring & service communication.

### 🔹 4. Key Features

| Feature | Description |
| --- | --- |
| **Networking (CNI)** | Works as a Kubernetes CNI (Container Network Interface). |
| **Security Policies** | Enforces **L3/L4 (IP, Port)** and **L7 (HTTP, gRPC, Kafka)** policies. |
| **Identity-based Security** | Uses **Kubernetes labels** to allow/deny traffic, not IPs. |
| **Load Balancing** | L4 & L7-aware load balancing (better than kube-proxy). |
| **Observability** | `cilium monitor` and **Hubble** provide live traffic & policy decision tracing. |
| **Performance** | High efficiency with eBPF (no iptables chains). |

### 🔹 5. Logging & Monitoring

| Tool | Usage |
| --- | --- |
| **cilium status** | Check if Cilium is running properly. |
| **cilium monitor** | Live view of packets + policy decisions. |
| **hubble observe** | Observability of pod-to-pod communications. |
| **journalctl -u cilium** | Logs from the Cilium agent. |

### 🔹 6. Comparison with Other Linux Firewalls

| Feature | iptables | nftables | ufw | firewalld | **Cilium** |
| --- | --- | --- | --- | --- | --- |
| Layer | L3/L4 | L3/L4 | L3/L4 | L3/L4 (zones) | L3–L7 |
| Backend | Netfilter | Netfilter | iptables/nftables | nftables | eBPF |
| Cloud-native | ❌ | ❌ | ❌ | ❌ | ✅ |
| Best For | Host firewalls | Host firewalls | Beginners | Dynamic zones | Kubernetes, containers |
| Observability | Limited | Limited | Minimal | Minimal | Extensive (Hubble) |

### AuditD Logs

### 🔹 1. What is auditd?

- **auditd** = *Linux Auditing Daemon*.
- It is part of the **Linux Audit Framework**.
- Used to **track security-relevant events** on the system.
- Logs **who did what, when, and how** at the kernel level.

👉 For forensics, it’s like a **black box flight recorder** for Linux systems.

### 🔹 2. Components of Auditd

| Component | Description |
| --- | --- |
| **auditd** | Main daemon that writes events to disk (`/var/log/audit/audit.log`). |
| **auditctl** | Command-line tool to configure audit rules (add, delete, list). |
| **ausearch** | Searches through audit logs. |
| **aureport** | Generates summary reports from audit logs. |
| **audispd** | Audit dispatcher – forwards audit events to other programs. |
| **plugins** | Extend auditd (e.g., forward logs to SIEM, syslog). |

### 🔹 3. Audit Log Location

- Logs are stored in:
    
    ```
    /var/log/audit/audit.log
    ```
    
- Example entry:
    
    ```
    type=EXECVE msg=audit(1672326160.123:412): argc=3 a0="rm" a1="-rf" a2="/tmp/test"
    ```
    
    - **type=EXECVE** → execution event.
    - **uid=1000** → which user.
    - **comm="rm"** → command executed.
    - **a0, a1, a2** → command arguments.

👉 This shows **which command was run, by whom, and when**.

### 🔹 4. Audit Rules

Rules define **what events to monitor**.

| Rule Type | Example | Meaning |
| --- | --- | --- |
| **File watch** | `auditctl -w /etc/passwd -p wa -k passwd_change` | Watch `/etc/passwd` for **write (w)** or **attribute (a)** changes. |
| **Syscall rule** | `auditctl -a always,exit -F arch=b64 -S execve -k exec_log` | Log every `execve` (program execution). |
| **User login events** | `auditctl -a always,exit -F arch=b64 -S setuid,setgid -k uid_change` | Track user/group ID changes. |

### 🔹 5. auditctl – Key Commands

| Command | Purpose |
| --- | --- |
| `auditctl -s` | Show auditd status. |
| `auditctl -l` | List current rules. |
| `auditctl -w /etc/passwd -p wa -k passwd_change` | Watch passwd file. |
| `auditctl -a always,exit -F arch=b64 -S execve -k exec_log` | Log all executed commands. |
| `auditctl -D` | Delete all rules. |

### 🔹 6. ausearch – Searching Logs

| Command | Usage |
| --- | --- |
| `ausearch -m avc` | Search for SELinux denials. |
| `ausearch -k passwd_change` | Search logs tagged with key `passwd_change`. |
| `ausearch -x /usr/bin/passwd` | Search all executions of `/usr/bin/passwd`. |
| `ausearch -ua 1000` | Show all activity by UID 1000. |

### 🔹 7. aureport – Reporting

| Command | Report Type |
| --- | --- |
| `aureport -au` | Authentication attempts. |
| `aureport -l` | Login/logout report. |
| `aureport -f` | File access report. |
| `aureport -x` | Executed commands report. |
| `aureport -k` | Reports by audit rule key. |

### 🔹 8. Example Use Cases in Forensics

| Scenario | Auditd Rule | Why Useful |
| --- | --- | --- |
| Detect passwd file changes | `auditctl -w /etc/passwd -p wa -k passwd_change` | Logs any attempt to edit system users. |
| Detect privilege escalation | `auditctl -a always,exit -F arch=b64 -S setuid,setgid -k priv_esc` | Logs if someone tries to change UID/GID. |
| Detect executed binaries | `auditctl -a always,exit -F arch=b64 -S execve -k exec_log` | Records all commands executed. |
| Detect root shell | `ausearch -ua 0` | Shows all activity from root user. |
| Detect suspicious login attempts | `aureport -au` | Helps spot brute force. |

### 🔹 9. Integration

- **Syslog forwarding** → Send audit logs to `/var/log/syslog`.
- **SIEM tools (Splunk, ELK, Wazuh)** → Collect and analyze centrally.
- **SELinux/AppArmor** → Auditd works together with mandatory access control.

### 🔹 10. Pros & Cons

| Pros | Cons |
| --- | --- |
| Kernel-level logging (tamper-resistant). | Can generate a lot of logs. |
| Great for forensics & compliance. | Needs careful rule tuning. |
| Works with SIEM & monitoring. | Misconfigured rules = performance issues. |
| Supports detailed reports & searches. | Logs may be complex to read without tools. |

### ✅ Summary

- **auditd** = Linux auditing system daemon.
- Logs all **security-relevant events** (file changes, command executions, logins).
- Key tools: **auditctl** (rules), **ausearch** (search logs), **aureport** (summary).
- Essential for **forensics, compliance (PCI, HIPAA, SOX), and intrusion detection**.

### Sysmon For Linux

### 🔹 1. What is Sysmon?

- **Sysinternals Sysmon** = "System Monitor".
- Originally a Windows tool (by Microsoft Sysinternals).
- Provides **detailed telemetry of system activity**: process creation, network connections, file changes, etc.
- Now available on **Linux (open-source, MIT-licensed)**.

👉 In **forensics & security monitoring**, Sysmon gives deeper visibility than standard logs.

### 🔹 2. Features of Sysmon on Linux

| Feature | Explanation |
| --- | --- |
| **Process Monitoring** | Logs when processes start/stop, parent-child relationships. |
| **File Monitoring** | Logs file creation, deletion, changes. |
| **Network Monitoring** | Logs inbound/outbound connections, IPs, ports. |
| **Hashes** | Records file hashes (SHA256, etc.) for executed binaries. |
| **Event IDs** | Similar to Windows Sysmon (e.g., Event ID 1 = process create). |
| **JSON output** | Logs are structured JSON, easier for SIEM integration. |

### 🔹 3. Sysmon for Linux Installation

1. Clone repo:
    
    ```bash
    git clone https://github.com/Sysinternals/SysmonForLinux.git
    ```
    
2. Build & install:
    
    ```bash
    cd SysmonForLinux
    mkdir build && cd build
    cmake ..
    make
    sudo make install
    ```
    
3. Start Sysmon with a config:
    
    ```bash
    sudo sysmon -accepteula -i sysmonconfig.xml
    
    ```
    

### 🔹 4. Sysmon Configuration

- Uses **XML configuration files** (same style as Windows Sysmon).
- Defines **what events to log & filter**.
- Example (`sysmonconfig.xml`):
    
    ```xml
    <Sysmon schemaversion="4.50">
      <EventFiltering>
        <ProcessCreate onmatch="include">
          <CommandLine condition="contains">/bin/bash</CommandLine>
        </ProcessCreate>
      </EventFiltering>
    </Sysmon>
    
    ```
    

👉 This example logs whenever **bash** is executed.

### 🔹 5. Sysmon Events in Linux

| Event ID | Description |
| --- | --- |
| **1** | Process creation (shows parent process, command line, hash). |
| **3** | Network connection (source/destination IP/port, process ID). |
| **11** | File creation time changes. |
| **23** | File deletion detected. |
| **255** | Error / Sysmon internal event. |

*(Windows Sysmon has 20+ event IDs, but Linux Sysmon currently supports fewer — evolving over time.)*

### 🔹 6. Log Location

- Logs are written to:
    
    ```
    /var/log/sysmon.log
    ```
    
- Example JSON log:
    
    ```json
    {
      "EventID": 1,
      "ProcessGuid": "{...}",
      "Image": "/usr/bin/bash",
      "CommandLine": "bash -i",
      "ParentImage": "/usr/bin/ssh",
      "User": "rohit"
    }
    ```
    

👉 Very useful for tracking **reverse shells** or **malicious scripts**.

### 🔹 7. Analysis Tools

| Tool | Usage |
| --- | --- |
| `jq` | Parse JSON logs. Example: `jq '.EventID' /var/log/sysmon.log` |
| `grep` / `zgrep` | Search logs quickly. Example: `grep "bash" /var/log/sysmon.log` |
| **SIEM integration** | Forward logs to Splunk, ELK, Wazuh, etc. |

### 🔹 8. Sysmon vs auditd vs journalctl

| Feature | **Sysmon** | **auditd** | **journalctl** |
| --- | --- | --- | --- |
| **Purpose** | Security telemetry (process, network, file). | Compliance/auditing (system calls, file access). | General system logs (services, kernel, apps). |
| **Format** | JSON (structured). | Custom format. | Journal binary → text. |
| **Ease of Analysis** | Easy (SIEM-ready). | Complex parsing. | Easy but less forensic detail. |
| **Scope** | Security/forensic focus. | Compliance focus. | General monitoring. |

### 🔹 9. Forensic Use Cases

| Scenario | Sysmon Event | Why Useful |
| --- | --- | --- |
| Detect reverse shell | Event ID 1 (ProcessCreate) + Event ID 3 (NetworkConnect) | Shows `bash` spawned by `ssh` + outbound IP. |
| Detect malware execution | Event ID 1 with SHA256 hash | Hashes can be matched against VirusTotal. |
| Detect persistence | Event ID 11 (File Create) | Tracks suspicious script or cron job creation. |
| Detect data exfiltration | Event ID 3 (network connection) | Unusual outbound connections. |

### 🔹 10. Pros & Cons

| Pros | Cons |
| --- | --- |
| Detailed security telemetry. | Not installed by default. |
| JSON logs (SIEM friendly). | Still evolving (fewer events than Windows Sysmon). |
| Same config style as Windows Sysmon. | Needs tuning → too noisy by default. |
| Great for detecting attacks. | Can impact performance if over-logging. |

### ✅ Summary

- **Sysmon for Linux** = security monitoring tool for **process, network, file, and hash events**.
- Logs in **JSON**, making it great for forensics & SIEMs.
- Complements **auditd** (compliance) and **journalctl/syslog** (system logging).
- Ideal for **incident response, malware analysis, and threat hunting**.

### Linux File Systems

### EXT2, 3 and 4

### 📊 **Table 1: General Features of Ext2, Ext3, Ext4**

| Feature | Ext2 | Ext3 | Ext4 |
| --- | --- | --- | --- |
| Year Introduced | 1993 | 2001 | 2008 |
| Journaling | ❌ No | ✅ Yes | ✅ Yes (with improvements) |
| Max File Size | 2 TB | 2 TB | 16 TB |
| Max Volume Size | 32 TB | 32 TB | 1 EB |
| Performance | Fast (no journal overhead) | Slower (journal overhead) | Optimized (journaling + extents) |
| Data Structures | Inodes, block groups | Inodes, block groups + journal | Inodes, block groups + extents, delayed allocation |
| Use Cases | USB, SD cards, recovery | Legacy Linux distros | Modern Linux distros |

### 📊 **Table 2: Forensic Perspective (Data Recovery & Logging)**

| Forensic Aspect | Ext2 | Ext3 | Ext4 |
| --- | --- | --- | --- |
| **Deleted Files** | Data often recoverable (no journal overwrite). | Harder: journal may overwrite deleted file metadata. | Hardest: extents + delayed allocation overwrite quickly. |
| **Journaling Impact** | N/A (no journaling). | Journal overwrites inode/data → reduces recovery chance. | Journaling + extents = less recoverable. |
| **Timestamps** | atime, mtime, ctime preserved. | Same as Ext2. | Adds `crtime` (file creation time) → useful for forensics. |
| **Superblock Backups** | Multiple backup superblocks exist. | Same. | Same. |
| **Recovery Tools** | High success with **carving** & inode scanning. | Limited recovery (metadata may be lost). | Limited, but `crtime` helps timeline analysis. |
| **Preferred in Forensics?** | ✅ Yes | ❌ Less | ❌ Less |

### 📊 **Table 3: Forensic Tools & TSK (The Sleuth Kit) Support**

| Tool / Command | Ext2 | Ext3 | Ext4 |
| --- | --- | --- | --- |
| **TSK `fls`** (list files) | Works fully. | Works but journal may hide deleted. | Works, supports extents but some recovery limited. |
| **TSK `icat`** (extract file) | Works fully. | Works, may fail if journal overwrote. | Works, limited if delayed allocation overwrote. |
| **TSK `istat`** (inode info) | Full metadata. | Metadata + journalized changes. | Metadata + `crtime`. |
| **TSK `ils`** (list inodes) | Can find deleted files easily. | Deleted inode entries may be lost. | Deleted inodes harder due to extents. |
| **debugfs** | Excellent for manual inode browsing. | Works, but journal complicates deleted recovery. | Works, supports extents. |
| **Photorec/Foremost** | High recovery success. | Medium success. | Low success (fragmentation + extents). |

### ✅ Summary

- **Ext2** → Best for forensics (no journal, data often recoverable).
- **Ext3** → Journaling overwrites metadata, lowers recovery.
- **Ext4** → Modern, but extents & delayed allocation make recovery harder.
- **TSK** works across all, but recovery **best in Ext2**, **worst in Ext4**.

### File Time Stamp in Linux

### 📘 **File Timestamps in Linux**

Linux filesystems (especially **Ext2/3/4**) maintain **four main timestamps**:

| Timestamp | Field | Meaning |
| --- | --- | --- |
| **atime** | Access Time | Last time the file was **read/accessed**. |
| **mtime** | Modification Time | Last time the file’s **content** was changed. |
| **ctime** | Change Time | Last time the file’s **metadata/inode** (permissions, ownership, links) was changed. |
| **crtime** | Creation Time | Only available in **Ext4**, shows when file was originally created. |

### 🔹 1. Using `stat` command

```bash
stat filename

```

Example output:

```
  File: example.txt
  Size: 1234       Blocks: 8    IO Block: 4096 regular file
Device: 802h/2050d Inode: 456789  Links: 1
Access: 2025-08-17 21:15:01.000000000 +0530   <-- atime
Modify: 2025-08-16 20:00:30.000000000 +0530   <-- mtime
Change: 2025-08-16 20:01:10.000000000 +0530   <-- ctime
 Birth: 2025-08-14 10:12:45.000000000 +0530   <-- crtime (Ext4 only)

```

### 🔹 2. Getting **only specific times**

```bash
stat -c %x filename   # Access time
stat -c %y filename   # Modification time
stat -c %z filename   # Change time
stat -c %w filename   # Creation (birth) time (if supported)

```

### 🔹 3. Using `ls` (limited)

```bash
ls -l filename     # Shows mtime
ls -lu filename    # Shows atime
ls -lc filename    # Shows ctime

```

### 🔹 4. Using `debugfs` (Forensics on Ext filesystems)

If you want deeper forensic timestamps (e.g., **deleted files**):

```bash
sudo debugfs /dev/sda1
debugfs: stat /path/to/file

```

Output may include:

- atime
- mtime
- ctime
- crtime (file creation time, useful in Ext4 for timeline analysis).

### 🔹 5. Timeline Analysis for Forensics

You can export timestamps to build a **timeline** of events:

```bash
fls -r -m / disk.img > bodyfile.txt   # Create file listing from disk image
mactime -b bodyfile.txt > timeline.txt  # Create human-readable timeline

```

### ✅ Summary

- Use `stat` for quick timestamp lookup.
- Use `ls -l`, `ls -lu`, `ls -lc` for selective timestamp display.
- Use **debugfs** or **The Sleuth Kit (TSK)** for forensic timestamp recovery.
- **Ext4’s `crtime`** is especially useful in forensics to know when a file was created.

### fstab

### 📘 **fstab (File System Table)**

The file `/etc/fstab` defines how and where filesystems are mounted at boot.

### Structure of `/etc/fstab`

Each line has **6 fields**:

| Field | Description | Example |
| --- | --- | --- |
| **1. Device** | The disk/partition or UUID to mount. | `/dev/sda1`, `UUID=3e6be9de-8139-11d1-9106-a43f08d823a6` |
| **2. Mount Point** | Where it will be attached in the directory tree. | `/`, `/home`, `/boot` |
| **3. Filesystem Type** | Type of FS. | `ext4`, `xfs`, `swap`, `ntfs` |
| **4. Options** | Mount options. | `defaults`, `noatime`, `ro`, `rw` |
| **5. Dump** | Used by `dump` backup utility (0 = ignore). | `0` |
| **6. Pass** | Order for `fsck` checks (0 = don’t check). | `1` for root, `2` for others |

✅ **Forensics Note**: `/etc/fstab` tells you what partitions were mounted → helps reconstruct how disks looked at boot.

### debusfs

### 📘 **debugfs (File System Debugger)**

- Tool for **ext2/ext3/ext4** filesystems.
- Allows direct, **low-level access** to the filesystem.
- Can view inodes, blocks, and even recover deleted files.

### Open a filesystem with debugfs:

```bash
sudo debugfs /dev/sda1

```

(or if analyzing a disk image)

```bash
sudo debugfs disk.img

```

### Common debugfs commands:

| Command | Description |
| --- | --- |
| `ls` | List directory contents |
| `stat <filename>` | Show file metadata (inode info + timestamps) |
| `logdump` | Show journal contents |
| `rdump <file> <dest_dir>` | Recover (dump) a file |
| `lsdel` | List deleted inodes (potentially recoverable files) |
| `dump <inode> <dest_file>` | Dump file by inode (useful when no filename) |
| `quit` | Exit debugfs |

### 📘 **File Recovery with debugfs**

When a file is deleted:

- The **directory entry is removed**,
- But the **inode and data blocks** may still exist until overwritten.

### Steps to Recover Deleted File:

1. Open filesystem:
    
    ```bash
    sudo debugfs /dev/sda1
    ```
    
2. List deleted inodes:
    
    ```bash
    debugfs: lsdel
    ```
    
    Output example:
    
    ```
    Inode  12345  Deleted at: 2025-08-17 14:00
    Inode  12346  Deleted at: 2025-08-17 14:10
    ```
    
3. Inspect the inode:
    
    ```bash
    debugfs: stat <inode_number>
    ```
    
    → Shows size, timestamps, and block locations.
    
4. Recover file:
    
    ```bash
    debugfs: dump <inode_number> /tmp/recovered_file
    ```
    

✅ **Forensics Note**:

- Ext2 → high recovery chance.
- Ext3/Ext4 → recovery is harder because **journaling & extents** overwrite metadata faster.
- Still, `lsdel` + `dump` gives you the inode data if blocks are intact.

### 📑 **Summary Notes**

`/etc/fstab`: Defines automatic mounting of filesystems. Important in **system reconstruction**.

`debugfs`: Low-level forensic tool for **ext2/3/4**, can view inodes, metadata, and recover files.

**File recovery with debugfs**: Use `lsdel`, `stat`, `dump` → works best on Ext2, limited on Ext3/Ext4 due to journaling.

### Ext4magic

### 📘 **ext4magic – File Recovery Tool for Ext3/Ext4**

- Works on **ext3/ext4 filesystems**.
- Uses the **journal** to reconstruct deleted files.
- Supports **timeline-based recovery** (files deleted after a certain date/time).
- More user-friendly than `debugfs`.

### 🔹 **Installation**

On Debian/Ubuntu/Mint:

```bash
sudo apt update
sudo apt install ext4magic

```

### 🔹 **Basic Syntax**

```bash
ext4magic <device_or_image> [options]

```

Example:

```bash
sudo ext4magic /dev/sda1 -f /home/user -d /recovery/

```

### 🔹 **Common Options**

| Option | Description |
| --- | --- |
| `-f <path>` | Recover a specific file or directory (relative to FS root). |
| `-r` | Recover all deleted files. |
| `-d <dir>` | Destination directory for recovered files. |
| `-m` | List deleted inodes (like `lsdel` in debugfs). |
| `-a "YYYY-MM-DD HH:MM:SS"` | Recover files deleted **after** a specific timestamp. |
| `-b` | Recover files deleted **before** a specific timestamp. |
| `-j` | Use journal to recover recently deleted files (most effective). |

### 🔹 **Examples**

### 1. List deleted files

```bash
sudo ext4magic /dev/sda1 -m
```

👉 Shows deleted inodes and metadata.

---

### 2. Recover a specific file

```bash
sudo ext4magic /dev/sda1 -f /home/user/secret.txt -d /tmp/recovery/
```

👉 Restores `secret.txt` to `/tmp/recovery/`.

---

### 3. Recover all deleted files from partition

```bash
sudo ext4magic /dev/sda1 -r -d /tmp/recovery/
```

---

### 4. Recover files deleted after a certain time

```bash
sudo ext4magic /dev/sda1 -r -a "2025-08-16 12:00:00" -d /tmp/recovery/
```

### 🔹 **Forensics Notes**

- **Ext2**: `debugfs` is better (no journal).
- **Ext3/Ext4**: `ext4magic` is preferred (journal helps).
- Journal data makes it possible to restore **recently deleted** files with good integrity.
- Older files (overwritten blocks) may be partially corrupted.

### 🔹 **Comparison: debugfs vs ext4magic**

| Feature | debugfs | ext4magic |
| --- | --- | --- |
| Works on | ext2/3/4 | ext3/4 only |
| Deleted file listing | `lsdel` | `-m` |
| Recovery method | Dump by inode | Journal-based recovery |
| Strength | Good for raw inode recovery | Strong recovery for recent deletions |
| Weakness | Harder on Ext3/4 with journaling | Limited if journal is wiped |

### ✅ **Summary**:

- Use `debugfs` for **manual inode-based recovery**.
- Use `ext4magic` for **journal-based recovery on ext3/ext4**, especially when the deletion was recent.

### Linux Persistence

### 📘 **init.d (SysV Init System)**

### 🔹 Overview

- Older init system used in **Debian, Ubuntu (pre-15.04)**, CentOS 6, etc.
- Scripts are stored in:
    - `/etc/init.d/` → main service scripts.
    - `/etc/rc*.d/` → symbolic links that control runlevel startup/shutdown.

### 🔹 Workflow

- Each script in `/etc/init.d/` controls starting/stopping a service.
- Example commands:
    
    ```bash
    sudo service apache2 start
    sudo service ssh stop
    ```
    

### 🔹 Malware Persistence via init.d

Attackers may:

1. **Drop a malicious script** into `/etc/init.d/`.
    - Example: `/etc/init.d/update.sh` containing malware binary execution.
2. **Create symlinks in rc directories** (`/etc/rc2.d/S99update`) to auto-run at boot.
3. The script will execute **every system boot**.

✅ **Forensic Detection**:

- Check for unusual scripts in `/etc/init.d/`.
- Look at symlinks in `/etc/rc*.d/` for unknown `Sxx` or `Kxx` entries.
- Hash compare against baseline.

### 📘**systemd (Modern Init System)**

### 🔹 Overview

- Default in **Debian 8+, Ubuntu 15.04+, RHEL7+, Fedora**.
- Uses **unit files** to manage services.
- Faster and more flexible than init.d.

### 🔹 Locations

- System services:
    - `/etc/systemd/system/` (custom user-created services)
    - `/lib/systemd/system/` (default system services)
- User services:
    - `~/.config/systemd/user/`

### 🔹 Workflow

- Example service unit file (`evil.service`):
    
    ```
    [Unit]
    Description=Malicious Service
    
    [Service]
    ExecStart=/usr/bin/evilscript.sh
    Restart=always
    
    [Install]
    WantedBy=multi-user.target
    ```
    
- Installation:
    
    ```bash
    sudo cp evil.service /etc/systemd/system/
    sudo systemctl enable evil.service
    sudo systemctl start evil.service
    ```
    

---

### 🔹 Malware Persistence via systemd

Attackers may:

1. Create a **malicious service unit file** (`evil.service`).
2. Enable it with `systemctl enable evil.service`.
3. The service auto-starts at every boot.
4. Can hide persistence inside `~/.config/systemd/user/` (per-user persistence).

✅ **Forensic Detection**:

- List enabled services:
    
    ```bash
    systemctl list-unit-files --state=enabled
    ```
    
- Inspect suspicious services:
    
    ```bash
    systemctl cat <service_name>
    ```
    
- Check user-level systemd directories.
- Look for **ExecStart** paths pointing to unusual scripts/binaries.

### 📑 **Comparison: init.d vs systemd in Malware Persistence**

| Feature | init.d (SysV) | systemd |
| --- | --- | --- |
| Location | `/etc/init.d/` | `/etc/systemd/system/`, `~/.config/systemd/user/` |
| Startup Control | rc scripts (symlinks in `/etc/rc*.d/`) | `systemctl enable <service>` |
| Persistence Method | Drop malicious init script + symlink | Create/modify `.service` unit file |
| Detection | Check unknown scripts & symlinks | List services, inspect ExecStart paths |
| Usage Today | Legacy (still in old distros) | Default in modern distros |

### 🔹 **Forensic & Security Notes**

- Both init.d and systemd allow **boot persistence**, which is stealthier than crontab or user profiles.
- Malware often mimics **legitimate service names** (e.g., `networkd.service`, `kworker.service`).
- Good practice:
    - Maintain baseline of services.
    - Audit `/etc/init.d/`, `/etc/systemd/system/` regularly.
    - Use tools like `chkrootkit`, `rkhunter`, `osquery` for persistence hunting.

### 📘 **Cron Jobs (Traditional Scheduling)**

### 🔹 Overview

- Cron is the **oldest and most common scheduling mechanism** in Linux.
- It executes commands at scheduled times.
- Uses **cron tables (`crontabs`)** to define schedules.

### 🔹 Locations

| Location | Purpose |
| --- | --- |
| `/etc/crontab` | System-wide cron file. |
| `/etc/cron.d/` | Additional system cron jobs (often package-installed). |
| `/etc/cron.hourly/`, `/etc/cron.daily/`, `/etc/cron.weekly/` | Drop scripts to run automatically. |
| `/var/spool/cron/crontabs/` | Per-user cron jobs. |

### 🔹 Syntax in crontab

```bash
* * * * * /path/to/command
```

- Fields: **minute, hour, day of month, month, day of week**
- Example (run every day at midnight):
    
    ```bash
    0 0 * * * /usr/bin/backup.sh
    ```
    

### 🔹 Malware Persistence via Cron

- Attacker adds a **malicious cron job** to run malware repeatedly.
- Example persistence entry:
    
    ```bash
    @reboot /usr/bin/malware.sh
    */10 * * * * /usr/bin/malware.sh
    ```
    
- **@reboot** = execute once at system boot.

✅ **Forensic Detection**

- List cron jobs for all users:
    
    ```bash
    crontab -l
    sudo ls -la /var/spool/cron/crontabs/
    sudo cat /etc/crontab
    ```
    
- Check `/etc/cron.*` directories for suspicious scripts.
- Look for **hidden binaries/scripts** in unusual paths.

### 📘**systemd Timers (Modern Scheduling)**

### 🔹 Overview

- Replaces cron in **systemd-based distros** (Debian 8+, Ubuntu 15.04+, RHEL7+, Fedora).
- More flexible, integrated into systemd.
- Uses **unit files with `[Timer]` sections**.

### 🔹 Timer Structure

Two files are needed:

1. **Service unit** (`evil.service`): defines what to run.
    
    ```
    [Unit]
    Description=Malicious Service
    
    [Service]
    ExecStart=/usr/bin/evilscript.sh
    ```
    
2. **Timer unit** (`evil.timer`): defines when to run.
    
    ```
    [Unit]
    Description=Run malicious script every 10 minutes
    
    [Timer]
    OnBootSec=1min
    OnUnitActiveSec=10min
    
    [Install]
    WantedBy=timers.target
    ```
    

### 🔹 Commands

- Enable and start timer:
    
    ```bash
    sudo systemctl enable evil.timer
    sudo systemctl start evil.timer
    ```
    
- List all timers:
    
    ```bash
    systemctl list-timers --all
    ```
    

### 🔹 Malware Persistence via Timers

- Attacker creates a hidden **systemd service + timer pair**.
- Example persistence:
    - `~/.config/systemd/user/updates.timer` → runs malware hourly.
    - Auto-restarts even if detected in `ps` process list.

✅ **Forensic Detection**

- Check active timers:
    
    ```bash
    systemctl list-timers --all
    ```
    
- Inspect suspicious timers:
    
    ```bash
    systemctl cat <timername>
    ```
    
- Look in:
    - `/etc/systemd/system/`
    - `/lib/systemd/system/`
    - `~/.config/systemd/user/`

### 📑 **Comparison: Cron vs systemd Timers**

| Feature | Cron | systemd Timers |
| --- | --- | --- |
| Location | `/etc/crontab`, `/var/spool/cron/` | `/etc/systemd/system/*.timer`, `~/.config/systemd/user/` |
| Scheduling | Fixed syntax (`* * * * *`) | Flexible (OnBootSec, OnUnitActiveSec, calendar events) |
| Logging | Minimal (`/var/log/syslog`) | Integrated with `journalctl` |
| Persistence Usage | Old-school, still common | Modern, stealthier |
| Detection | Check crontabs, cron dirs | `systemctl list-timers`, check custom unit files |

### 🔹 **Forensic Notes**

- Malware prefers **cron** for simplicity (works everywhere).
- Advanced malware prefers **systemd timers** (harder to notice, integrates with system logs).
- Both can survive reboots and provide **stealth persistence**.
- 🔍 **Hunting tip**: baseline legitimate cron jobs and timers → alert on new/unknown entries.

### **Bash Files (.bashrc, .bash_profile, .profile)**

- **Purpose**: Bash reads these files during shell startup (interactive login or non-login shells).
- **Locations**:
    - `~/.bashrc` → executed for interactive non-login shells.
    - `~/.bash_profile`, `~/.profile` → executed for login shells.
- **Malware Abuse**: Attacker adds malicious commands/scripts so they execute every time the user logs in.
    - Example:
        
        ```bash
        echo "/usr/bin/evil.sh" >> ~/.bashrc
        ```
        
- **Forensic Detection**:
    - Check user’s `~/.bashrc`, `~/.bash_profile` for suspicious entries.
    - Look for hidden binaries/scripts (`/tmp/.evil`).

### 🛠️ **rc.local**

- **Purpose**: Script executed at the end of each multi-user runlevel (boot time).
- **Location**: `/etc/rc.local` (some distros disable by default in systemd).
- **Malware Abuse**: Attacker places malicious commands here → runs automatically at boot.
    - Example entry:
        
        ```bash
        /usr/bin/python3 /usr/local/bin/revshell.py &
        ```
        
- **Forensic Detection**:
    - Inspect `/etc/rc.local` for unauthorized changes.
    - Check file permissions & modification timestamps.

### 🔌**udev Rules**

- **Purpose**: `udev` manages device events (USBs, disks, network interfaces).
- **Location**: `/etc/udev/rules.d/` or `/lib/udev/rules.d/`.
- **Malware Abuse**: Create malicious rule to execute code when device is attached.
    - Example rule:
        
        ```
        ACTION=="add", KERNEL=="sda", RUN+="/usr/bin/evil.sh"
        ```
        
- **Forensic Detection**:
    - List rules: `cat /etc/udev/rules.d/*`
    - Look for suspicious `RUN+=` directives.

### 🖥️ **XDG Autostart**

- **Purpose**: Desktop environments (GNOME, KDE, XFCE) use XDG `.desktop` files to start apps at login.
- **Locations**:
    - `~/.config/autostart/` (per user)
    - `/etc/xdg/autostart/` (system-wide)
- **Malware Abuse**: Drop a `.desktop` file pointing to malware.
    - Example malicious `.desktop` file:
        
        ```
        [Desktop Entry]
        Type=Application
        Exec=/usr/bin/evil.sh
        Hidden=false
        ```
        
- **Forensic Detection**:
    - Inspect `.desktop` files in those directories.
    - Check for hidden scripts in `/tmp` or `~/.local/bin`.

### 🌐  **NetworkManager Scripts**

- **Purpose**: NetworkManager can execute scripts on network events.
- **Location**: `/etc/NetworkManager/dispatcher.d/`
- **Malware Abuse**: Place script here → executed when interface goes up/down.
    - Example persistence:
        
        ```bash
        #!/bin/bash
        if [ "$2" = "up" ]; then
            /usr/bin/evil.sh &
        fi
        ```
        
- **Forensic Detection**:
    - Inspect dispatcher scripts: `ls -la /etc/NetworkManager/dispatcher.d/`
    - Look for unauthorized executables.

### 👤 **New User Account**

- **Purpose**: Attacker creates a backdoor account for persistence.
- **Command**:
    
    ```bash
    sudo useradd attacker -m -s /bin/bash
    sudo passwd attacker
    sudo usermod -aG sudo attacker
    ```
    
- **Malware Abuse**: Hidden account allows re-entry via SSH or sudo.
- **Forensic Detection**:
    - Inspect `/etc/passwd` for unusual users.
    - Compare account creation timestamps with logs.
    - Check `/etc/shadow` for unexpected password hashes.

### 🔑 **sudoers File**

- **Purpose**: Defines users allowed to run commands as root.
- **Location**: `/etc/sudoers` or `/etc/sudoers.d/`
- **Malware Abuse**: Attacker adds backdoor privilege escalation.
    - Example entry:
        
        ```
        attacker ALL=(ALL) NOPASSWD:ALL
        ```
        
- **Forensic Detection**:
    - Inspect `/etc/sudoers` and `/etc/sudoers.d/` for unauthorized entries.
    - Look for **NOPASSWD** rules.

### 📑 **Summary Table**

| Persistence Method | Location | Trigger | Malware Abuse | Forensic Check |
| --- | --- | --- | --- | --- |
| **Bash Files** | `~/.bashrc`, `~/.bash_profile`, `~/.profile` | User login | Auto-exec malware on shell start | Inspect hidden commands |
| **rc.local** | `/etc/rc.local` | Boot | Run malware at boot | Check for modified rc.local |
| **udev Rules** | `/etc/udev/rules.d/` | Device event | Auto-exec on USB attach/network | Search `RUN+=` in rules |
| **XDG Autostart** | `~/.config/autostart/`, `/etc/xdg/autostart/` | GUI login | Add `.desktop` file for malware | Inspect `.desktop` files |
| **NetworkManager** | `/etc/NetworkManager/dispatcher.d/` | Network up/down | Launch malware when network connects | Review dispatcher scripts |
| **New User Account** | `/etc/passwd`, `/etc/shadow` | Always available | Hidden user with sudo rights | Audit user list |
| **sudoers File** | `/etc/sudoers`, `/etc/sudoers.d/` | Privileged exec | Grant root to attacker | Inspect for `NOPASSWD` |

### Evidence Collection

### 🖥️ **1. dd**

- **Purpose**: Low-level utility to copy and convert data.
- **Command**:
    
    ```bash
    dd if=/dev/sda of=/mnt/evidence/disk.img bs=4M conv=noerror,sync
    ```
    
    - `if=` → input file (device or file).
    - `of=` → output file.
    - `bs=` → block size.
    - `conv=noerror,sync` → skip errors but pad with zeros.
- **Forensics Notes**:
    - Simple but **not forensic-friendly** (no hashing, no metadata logging).
    - Must calculate hash manually after imaging (`md5sum`, `sha256sum`).

### 🖥️ **2. dcfldd**

- **Purpose**: Forensic-enhanced version of `dd`, created by DoD’s Computer Forensics Lab (DCFL).
- **Features**:
    - Built-in hashing (MD5, SHA1, SHA256).
    - Hash verification during copy.
    - Split image output.
    - Logging of imaging process.
- **Command**:
    
    ```bash
    dcfldd if=/dev/sda of=/mnt/evidence/disk.img hash=sha256 log=/mnt/evidence/dcfldd.log
    ```
    
- **Forensics Notes**:
    - Better than `dd` → avoids manual hashing.
    - Still widely used in **forensic acquisition labs**.

### 🖥️ **3. dc3dd**

- **Purpose**: Successor to `dcfldd`, developed by the DoD Cyber Crime Center (DC3).
- **Features**:
    - Supports all features of `dcfldd`.
    - Enhanced error handling.
    - Better hashing options (multiple simultaneous hashes).
    - Progress indicators.
    - Wiping functions with patterns (for secure erasure).
- **Command**:
    
    ```bash
    dc3dd if=/dev/sda of=/mnt/evidence/disk.img hash=md5 sha256 log=/mnt/evidence/dc3dd.log
    ```
    
- **Forensics Notes**:
    - Most **forensic labs prefer dc3dd**.
    - Standard for **court-admissible acquisitions**.

### 📊 **Comparison Table**

| Feature | dd | dcfldd | dc3dd |
| --- | --- | --- | --- |
| Developer | Unix (coreutils) | DoD Computer Forensics Lab | DoD Cyber Crime Center (DC3) |
| Hashing Support | ❌ No | ✅ Yes (MD5, SHA1, SHA256) | ✅ Yes (multiple, parallel) |
| Logging | ❌ No | ✅ Yes | ✅ Yes (improved) |
| Split Images | ❌ No | ✅ Yes | ✅ Yes |
| Error Handling | Basic (`noerror`) | Improved | Advanced |
| Progress Indicator | ❌ No | Limited | ✅ Yes |
| Forensic Suitability | ⚠️ Limited | ✅ Good | ✅ Best |

### 🔍 **Forensic Best Practices**

1. Always image in **read-only mode** using a **write blocker**.
    
    ```bash
    hdparm -r1 /dev/sda   # set device to read-only
    ```
    
2. Use `dc3dd` or `dcfldd` for **hash-integrated imaging**.
3. Store **log files** with chain-of-custody.
4. Verify integrity after imaging:
    
    ```bash
    sha256sum disk.img
    ```
    

### AVML - For Memory Collection

### AVML — Acquire Volatile Memory for Linux

**AVML** is a **userland memory acquisition tool** developed by Microsoft, written in Rust, and distributed as a static binary. It’s designed to be portable, reliable, and easy to use across diverse Linux environments—ideal for forensic investigators.

[GitHub](https://github.com/microsoft/avml?utm_source=chatgpt.com)

### Key Features

- **Kernel-Independent**: Works without relying on the specific Linux distribution or kernel version—no on-target compilation needed.
- **Multiple Memory Sources**: Automatically attempts to acquire memory using:
    - `/dev/crash` (crash dump device)
    - `/proc/kcore` (virtual ELF memory)
    - `/dev/mem` (physical memory), opened in read-only mode
        
        [GitHub](https://github.com/microsoft/avml?utm_source=chatgpt.com)
        
- **Standard Formats**: Outputs memory in **LiME** format (a widely supported forensic image format).
- **Compression Support**: Optional Snappy-based compression to minimize image sizes.
- **Remote Upload**: Can stream results to **Azure Blob Store**, **HTTP PUT endpoints**, or use pre-signed URLs for AWS/GCP. Built-in retry logic and optional deletion of file upon successful upload.
    
    [GitHub](https://github.com/microsoft/avml?utm_source=chatgpt.com)[Microsoft Learn](https://learn.microsoft.com/en-us/security/research/project-freta/how-to-capture-an-image?utm_source=chatgpt.com)
    
- **Portability & Scalability**: Suitable for large-scale deployments across diverse and custom kernel environments where tools like LiME become impractical.
    
    [Reddit](https://www.reddit.com/r/computerforensics/comments/xs2a77/lime_vs_avml_for_linux_memory_acquisition/?utm_source=chatgpt.com)
    

### Limitations & Edge Cases

- **Kernel Lockdown**: If Linux is in lockdown mode, AVML will fail to access memory through its usual interfaces.
    
    [Reddit](https://www.reddit.com/r/computerforensics/comments/xs2a77/lime_vs_avml_for_linux_memory_acquisition/?utm_source=chatgpt.com)
    
- **Anti-Forensics Risks**: Malware with kernel-level access might evade memory capture even from AVML, but similar vulnerabilities exist for any on-host acquisition tool, including LiME.
    
    [Reddit](https://www.reddit.com/r/computerforensics/comments/xs2a77/lime_vs_avml_for_linux_memory_acquisition/?utm_source=chatgpt.com)
    
- **Source Reliability**: Depends on availability of `/proc/kcore`, `/dev/mem`, or `/dev/crash`—some distributions may disable these for security.
    
    [GitHub](https://github.com/microsoft/avml?utm_source=chatgpt.com)
    

### Typical Usage Quick-Start

1. **Download and make executable:**
    
    ```bash
    wget https://github.com/microsoft/avml/releases/latest/download/avml
    chmod +x avml
    ```
    
2. **Capture Memory (uncompressed):**
    
    ```bash
    sudo ./avml output.lime
    ```
    
3. **Capture Memory (compressed):**
    
    ```bash
    sudo ./avml --compress output.lime.compressed
    ```
    
4. **Upload to Azure Blob with deletion after upload**:
    
    ```bash
    avml --sas-url "<SAS_URL>" --compress --delete output.lime.compressed
    ```
    
5. **Convert compressed image back to raw LiME format**:
    
    ```bash
    avml-convert compressed.lime compressed.raw
    ```
    
- **For cloud responses**, Velociraptor includes a ready-made artifact script for AVML usage.
    
    [docs.velociraptor.app](https://docs.velociraptor.app/exchange/artifacts/pages/linux.memory.avml/?utm_source=chatgpt.com)
    
- **Real-world testing** shows AVML can capture memory extremely quickly (e.g., 1 GB in ~2 seconds).
    
    [iblue.team](https://www.iblue.team/memory-forensics-1/acquisition/linux-avml-acquisition?utm_source=chatgpt.com)
    

### **Unix-like Artifacts Collector - UAC**

Documentation : [https://tclahr.github.io/uac-docs/#](https://tclahr.github.io/uac-docs/#)

### 🛠️ **Unix-like Artifacts Collector (UAC)**

- **Purpose**:
    
    UAC is a **live response triage tool** for Unix-like systems (Linux, macOS, BSD).
    
    It’s widely used in **forensics and incident response (DFIR)** to quickly collect important system artifacts.
    
- **Origin**:
    
    Developed as part of **forensic triage frameworks** (community-driven, often found on GitHub).
    
    It simplifies **evidence acquisition** without requiring full disk/memory imaging.
    

### 🔑 **What UAC Collects**

| Category | Artifacts Collected | Forensic Value |
| --- | --- | --- |
| **System Info** | Hostname, OS version, uptime, kernel, architecture | Identifies target environment |
| **Users & Groups** | `/etc/passwd`, `/etc/shadow`, `/etc/group`, logged-in users | Account enumeration |
| **Processes** | Running processes, parent/child relationships | Detect persistence, malware |
| **Network** | Open ports, listening sockets, active connections | Detect backdoors, exfiltration |
| **Services & Startup** | Init/systemd configs, crontabs, rc.local, autostart files | Persistence detection |
| **Filesystems** | Mounted drives, fstab, disk usage | Identify hidden/mounted volumes |
| **Logs** | `/var/log/*`, journal logs | Event correlation |
| **Security** | iptables, nftables, SELinux/AppArmor status | Security posture |
| **Binaries** | Hashes of critical binaries (`/bin`, `/sbin`) | Detect tampering/rootkits |

### 📂 **Typical UAC Output**

- Collected into a structured directory:
    
    ```
    UAC_Collection_2025-08-17/
    ├── system_info.txt
    ├── users_groups/
    │   ├── passwd
    │   ├── shadow
    ├── processes/
    ├── network/
    ├── logs/
    │   ├── syslog
    │   ├── auth.log
    └── hashes/
    ```
    
- Sometimes compressed into a `.tar.gz` archive for transport.

### ⚖️ **Forensic Notes**

- **Use cases**: Quick **triage** when full disk imaging is impractical (e.g., cloud VMs, containers, live systems).
- **Integrity**: Hashes (SHA256/MD5) can be calculated during collection.
- **Limitations**:
    - Does not capture raw disk data (no deleted file recovery).
    - Does not capture memory by itself (can be paired with tools like `avml` for memory acquisition).

### 📊 **Comparison with Other Tools**

| Tool | Purpose | Platform | Strength |
| --- | --- | --- | --- |
| **UAC** | Collect Unix artifacts (logs, configs, processes) | Linux/Unix/macOS | Lightweight, structured triage |
| **KAPE** | Windows artifact collector | Windows | Very popular in DFIR |
| **Avml** | Memory acquisition | Linux | Captures volatile memory |
| **dd/dcfldd/dc3dd** | Full disk imaging | Linux/Unix | Forensic-grade raw copies |
| **The Sleuth Kit (TSK)** | Post-mortem disk analysis | Cross-platform | Deleted file recovery |

✅ In short:

**UAC = Unix-like Artifacts Collector**, a **triage tool for DFIR**, gathering live response evidence (logs, configs, processes, persistence mechanisms, network activity) from Linux and other Unix-like systems.

### 🔎 **UAC Forensic Workflow Example**

### 📌 Step 1: Prepare the Environment

- Boot into a **forensic live CD/USB** if possible (to avoid contaminating evidence).
- Or, if doing **live triage** (cloud, container, production server), run directly with minimal footprint.

```bash
# Create a safe directory for storing artifacts
mkdir -p /mnt/usb/UAC_Collection
cd /mnt/usb/UAC_Collection
```

---

### 📌 Step 2: Download or Copy UAC Tool

If UAC is already packaged from GitHub:

```bash
git clone https://github.com/tclahr/uac.git
cd uac
```

Or if deployed by incident response team, copy the precompiled/scripted UAC to the system.

---

### 📌 Step 3: Run UAC Collection

Run with **root privileges** (needed to access logs, shadow, processes, etc.):

```bash
sudo ./uac --output /mnt/usb/UAC_Collection
```

👉 This will generate structured subdirectories containing artifacts.

---

### 📌 Step 4: Verify Output

The output folder will look like:

```
/mnt/usb/UAC_Collection/
├── system_info.txt
├── users_groups/
│   ├── passwd
│   ├── shadow
├── processes/
│   ├── ps_list.txt
│   ├── open_files.txt
├── network/
│   ├── netstat.txt
│   ├── ifconfig.txt
│   ├── routes.txt
├── persistence/
│   ├── crontabs.txt
│   ├── systemd_services.txt
│   ├── autostart.txt
├── logs/
│   ├── auth.log
│   ├── syslog
│   ├── dmesg.txt
└── hashes/
    ├── bin_hashes.txt
    ├── sbin_hashes.txt

```

---

### 📌 Step 5: Integrity Checks

Generate **hashes** of the collected data for forensic soundness:

```bash
cd /mnt/usb/UAC_Collection
sha256sum * > collection_hashes.sha256
```

---

### 📌 Step 6: Analyze Collected Artifacts

Now, the analyst can investigate on a separate workstation:

### Users & Groups

```bash
cat users_groups/passwd
cat users_groups/shadow
```

👉 Detect suspicious accounts (UID 0 backdoors, weak hashes).

### Running Processes

```bash
cat processes/ps_list.txt | grep suspicious_binary
```

👉 Identify malware persistence.

### Network

```bash
cat network/netstat.txt | grep ESTABLISHED
```

👉 Detect unusual external connections.

### Persistence

```bash
cat persistence/systemd_services.txt | grep -i evil
```

👉 Spot malicious `systemd` services.

---

### 📌 Step 7: Extend with Memory Acquisition

Since UAC does **not capture memory**, pair with **AVML**:

```bash
sudo ./avml memory_dump.lime
sha256sum memory_dump.lime > memory_dump.lime.sha256
```

This adds volatile evidence (keys, injected malware, sockets).

### 📊 **Forensic Value of UAC Workflow**

| Phase | Evidence | Why It Matters |
| --- | --- | --- |
| System Info | Kernel, OS, uptime | Detect reboots, patch level |
| Users/Groups | passwd, shadow | Detect rogue accounts |
| Processes | Running tasks | Detect malware execution |
| Network | Netstat, ifconfig | Detect C2/backdoors |
| Persistence | systemd, cron, rc.local | Identify persistence mechanisms |
| Logs | auth.log, syslog | Detect privilege escalation |
| Hashes | /bin, /sbin binaries | Detect rootkits/tampered executables |

### TimeLining

### 🛠️ **The Sleuth Kit (TSK) for Linux Forensics**

### 📌 What is TSK?

- **The Sleuth Kit (TSK)** is an **open-source digital forensic toolkit**.
- Primarily used for **post-mortem analysis** of **disk images** (not live response).
- Works on **Linux, Unix, Windows, and macOS**, but is most commonly used on Linux forensic workstations.
- Provides CLI tools for analyzing:
    - **File systems** (ext2/3/4, NTFS, FAT, HFS, XFS, etc.)
    - **Deleted files**
    - **Metadata and timelines**

### 🔑 **Core Features of TSK**

| Feature | Description | Linux Forensic Value |
| --- | --- | --- |
| **Image Support** | Reads raw (`dd`), EWF (`.E01`), AFF | Handles forensic disk images |
| **Partition Analysis** | View partitions and layouts (`mmls`) | Detect hidden partitions |
| **File System Analysis** | Ext2, Ext3, Ext4, FAT, NTFS, HFS+ | Useful for Linux ext file systems |
| **Deleted File Recovery** | Recover unallocated/deleted files (`fls`, `icat`) | File recovery |
| **Metadata & Timelines** | Analyze MAC times (`istat`, `mactime`) | Timeline reconstruction |
| **Keyword Search** | Search disk images (`tsk_recover`, `tsk_loaddb`) | Finding indicators of compromise |

### 📂 **Important TSK Commands (Linux Focus)**

| Command | Purpose | Example |
| --- | --- | --- |
| `mmls` | Show partitions on a disk image | `mmls disk.dd` |
| `fsstat` | Show details about a file system | `fsstat -f ext4 disk.dd` |
| `fls` | List files/directories (including deleted) | `fls -r -f ext4 disk.dd` |
| `istat` | Show metadata for a file (inode info) | `istat -f ext4 disk.dd 12345` |
| `icat` | Extract file contents by inode | `icat -f ext4 disk.dd 12345 > file.txt` |
| `blkstat` | Show details about a disk block | `blkstat -f ext4 disk.dd 23456` |
| `tsk_recover` | Recover all files from image | `tsk_recover -a disk.dd output/` |
| `mactime` | Create timeline from MAC times | `fls -m / disk.dd > bodyfile ; mactime -b bodyfile > timeline.txt` |

### 📊 **Linux Ext File System Forensics with TSK**

| Ext Version | Supported By TSK | Forensic Notes |
| --- | --- | --- |
| **Ext2** | ✅ Full support | Easy recovery, no journaling |
| **Ext3** | ✅ Limited (journaling complicates) | Journal analysis is harder, but metadata available |
| **Ext4** | ✅ Partial (some features unsupported) | Timestamps & extents supported, recovery sometimes incomplete |

👉 For **deleted file recovery**, ext2 is easiest. Ext3/4 journaling makes recovery harder, but TSK still extracts metadata and content.

### 🔍 **Example Workflow: Ext4 Image Analysis**

1. **Identify partitions**:
    
    ```bash
    mmls disk.dd
    
    ```
    
    → Shows partition layout.
    
2. **File system info**:
    
    ```bash
    fsstat -f ext4 disk.dd
    
    ```
    
    → Shows ext4 metadata (block size, mount times, etc.).
    
3. **List files (including deleted)**:
    
    ```bash
    fls -r -f ext4 disk.dd > bodyfile.txt
    
    ```
    
    → Recursive listing.
    
4. **Build timeline**:
    
    ```bash
    mactime -b bodyfile.txt > timeline.txt
    less timeline.txt
    
    ```
    
    → Helps reconstruct attacker activity.
    
5. **Recover a deleted file**:
    
    ```bash
    icat -f ext4 disk.dd 12345 > recovered.txt
    
    ```
    
    → Extracts file by inode number.
    

### ⚖️ **Forensic Value of TSK on Linux**

| Artifact | How TSK Helps | Investigator Benefit |
| --- | --- | --- |
| Deleted Files | `fls`, `icat`, `tsk_recover` | Recover attacker scripts, malware |
| Metadata | `istat`, `fsstat` | Detect creation/access patterns |
| Timelines | `mactime` | Correlate intrusion steps |
| Partition Info | `mmls` | Find hidden partitions or volumes |
| Journaling Limits | Ext3/Ext4 journaling may overwrite deleted data | Must supplement with tools like **extundelete** or **ext4magic** |

### 🕒 **Linux Forensic Timeline Analysis with fls & mactime**

### 🔹 Step 1: Collect File System Metadata with `fls`

**`fls` (File List)** → Lists files, directories, and deleted entries from a disk image or partition.

It creates a **bodyfile** (intermediate file) that stores **metadata timestamps**.

### Common Syntax:

```bash
fls -r -f ext4 disk.dd > bodyfile.txt

```

| Option | Meaning |
| --- | --- |
| `-r` | Recursive (list all subdirectories) |
| `-f ext4` | Specify file system type (ext2/3/4, ntfs, etc.) |
| `disk.dd` | Forensic image or partition |
| `> bodyfile.txt` | Output to bodyfile (intermediate timeline file) |

✅ **Output**: The `bodyfile.txt` contains **MAC times** (Modified, Accessed, Changed) of files.

### 🔹 Step 2: Create a Timeline with `mactime`

**`mactime`** reads the **bodyfile** and converts it into a **human-readable timeline**.

### Common Syntax:

```bash
mactime -b bodyfile.txt > timeline.txt

```

| Option | Meaning |
| --- | --- |
| `-b bodyfile.txt` | Input bodyfile created by `fls` |
| `> timeline.txt` | Save human-readable timeline |
| `-d` | Output in CSV format (good for Excel/ELK analysis) |
| `-y` | Show full year in timestamps |

✅ **Output**: `timeline.txt` contains **chronological events** from the file system.

### 🔹 Example Workflow

1. **List files and build bodyfile**:
    
    ```bash
    fls -r -f ext4 disk.dd > bodyfile.txt
    
    ```
    
2. **Generate timeline**:
    
    ```bash
    mactime -b bodyfile.txt > timeline.txt
    
    ```
    
3. **Review timeline**:
    
    ```bash
    less timeline.txt
    
    ```
    

### 🔹 Timeline Output Example

```
Mon Jan 13 2025 12:14:35, M.., /home/user/.bash_history
Mon Jan 13 2025 12:14:40, .A.., /home/user/malware.sh
Mon Jan 13 2025 12:14:45, ..C., /var/log/auth.log

```

- **M** → Modified
- **A** → Accessed
- **C** → Changed (metadata/inode change)

### 📊 **Forensic Value of fls + mactime**

| Artifact | Tool Used | Value in Investigation |
| --- | --- | --- |
| File creation/deletion timeline | `fls`, `mactime` | Reconstruct attacker steps |
| Malware execution | Timeline shows when malicious script accessed | Pinpoint initial intrusion |
| Log tampering | Compare log modification times | Detect anti-forensic behavior |
| Correlate events | Cross-reference with `/var/log/auth.log` | Identify user sessions & commands |

### ⚖️ **Limitations**

- Ext3/Ext4 journaling may overwrite old deleted entries.
- Only shows MAC times → attacker may **manipulate timestamps (Timestomping)**.
- Should be **correlated with system logs** (`auth.log`, `syslog`, `journalctl`).

### ✅ **Summary**:

- **`fls`** → Extracts file system metadata into a **bodyfile**.
- **`mactime`** → Converts that into a **human-readable forensic timeline**.
- Together, they help **reconstruct attacker activity** and validate intrusion timelines.

### Linux Memory Analysis

### 🧠 **Linux Memory Analysis with Volatility**

### 🔹 Step 1: Memory Acquisition (Dumping)

Memory is **volatile**, so capturing it correctly is crucial.

Some common tools:

| Tool | Usage | Notes |
| --- | --- | --- |
| **avml** | `avml dump.mem` | Lightweight, Microsoft tool, cloud-friendly |
| **LiME** (Linux Memory Extractor) | `insmod lime.ko "path=/mnt/memdump.lime format=lime"` | Kernel module, versatile |
| **dd** | `dd if=/dev/mem of=dump.mem` | Legacy, `/dev/mem` often restricted |
| **fmem** | `/dev/fmem` module | Safer alternative to `/dev/mem` |

✅ Example with **avml** (easiest):

```bash
sudo ./avml dump.mem

```

This creates `dump.mem` which can be analyzed with **Volatility**.

### 🔹 Step 2: Install Volatility

Volatility has two main versions:

- **Volatility 2 (legacy)** → Python 2.7 based, older plugins.
- **Volatility 3 (modern)** → Python 3, cross-platform, better for Linux.

### Install Volatility 3 (recommended)

```bash
# Install dependencies
sudo apt update
sudo apt install -y python3 python3-pip git pcregrep

# Clone Volatility 3
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3

# Install requirements
pip3 install -r requirements.txt

```

Run with:

```bash
python3 vol.py -h

```

### 🔹 Step 3: Identify Memory Profile (Volatility 2 only)

In Volatility 2, you need the correct **profile** (Linux kernel version).

```bash
volatility -f dump.mem linux_banner

```

This reveals kernel info (e.g., `Linux version 5.10.0-23-amd64`).

In Volatility 3 → **no profile needed** (auto-detects structures).

### 🔹 Step 4: Perform Memory Analysis

### 📝 Common Volatility Commands for Linux

| Category | Command | Description |
| --- | --- | --- |
| **System Info** | `linux_banner` | Kernel version |
|  | `linux_pslist` | List processes |
|  | `linux_pstree` | Process tree |
|  | `linux_lsmod` | Loaded kernel modules |
| **Memory & Files** | `linux_mount` | Mounted filesystems |
|  | `linux_lsof` | Open files |
| **Networking** | `linux_netstat` | Active connections |
|  | `linux_ifconfig` | Network interfaces |
| **Malware Detection** | `linux_bash` | Dump bash history |
|  | `linux_check_creds` | Detect credential reuse |
|  | `linux_hidden_modules` | Rootkit detection |
| **Forensics** | `linux_dmesg` | Kernel logs from memory |
|  | `linux_enumerate_files` | List all inodes/files |

### 🔹 Step 5: Example Workflow

1. **Dump memory** with avml:
    
    ```bash
    sudo ./avml dump.mem
    
    ```
    
2. **Check system banner**:
    
    ```bash
    python3 vol.py -f dump.mem linux_banner
    
    ```
    
3. **List processes**:
    
    ```bash
    python3 vol.py -f dump.mem linux_pslist
    
    ```
    
4. **Get process tree**:
    
    ```bash
    python3 vol.py -f dump.mem linux_pstree
    
    ```
    
5. **Extract bash history**:
    
    ```bash
    python3 vol.py -f dump.mem linux_bash
    
    ```
    
6. **Check network connections**:
    
    ```bash
    python3 vol.py -f dump.mem linux_netstat
    
    ```
    

### 🔹 Forensic Value

| Artifact | Recovered via Volatility | Why It’s Useful |
| --- | --- | --- |
| Running processes | `linux_pslist`, `linux_pstree` | Detect malware, persistence |
| Bash history | `linux_bash` | Attacker commands |
| Network connections | `linux_netstat` | Detect C2 (Command & Control) |
| Kernel modules | `linux_lsmod`, `linux_hidden_modules` | Rootkit detection |
| Open files | `linux_lsof` | Identify exfiltration |
| Logs in memory | `linux_dmesg` | Kernel/boot logs |

### ⚖️ Limitations

- Memory dumps can be **large** (GBs).
- Volatility requires **symbol tables** for some Linux kernels (sometimes needs custom module compilation).
- Attackers may clear bash history or use in-memory malware.

### ✅ **Summary**

- **Acquire memory** with `avml` or `LiME`.
- **Analyze** with Volatility (`pslist`, `bash`, `netstat`, `lsmod`).
- **Correlate findings** with disk forensics (TSK timelines, logs).