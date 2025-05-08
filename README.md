# elev

**elev** is a minimal, secure privilege elevation tool written in Rust—designed as a drop‑in replacement for `sudo` or `doas`. It follows modern security practices with a focus on simplicity and transparency.

---

## Features

* 🔒 **Secure**: Implemented in Rust for memory safety and resilience against common vulnerabilities.
* ⚡ **Fast & Lightweight**: Minimal dependencies and a small footprint for responsive performance.
* 📝 **Simple Configuration**: Human‑readable rule syntax for fine‑grained allow/deny policies.
* 🧩 **Role-Based Access**: Assign users or groups to named roles and write policies around them.
* 🚫 **Advanced Deny Logic**: Deny rules override any allow rules, including root or wildcard entries.
* ✨ **Wildcard & Regex Support**: Flexible command matching for complex workflows.
* 🛠️ **Extensible**: Configurable and easy to integrate into custom environments.
* 🌱 **Solarpunk & Cybersecurity Principles**: Built with user autonomy and safe tech philosophies in mind.

---

## Installation

**Prerequisites:**

* Rust toolchain (version 1.70 or newer)
* Access to the `root` account (no `sudo` or `doas` required)

1. **Switch to the root user**:

   ```bash
   su -
   ```

2. Run the installer from the project root:
   ```
   ./install.sh
   ```


This script will:

Compile elev in release mode

Install the binary to /usr/local/bin/elev

Create a default config at /etc/elev.conf



---

## Configuration

The default configuration file is located at `/etc/elev.conf`. Define rules using human-readable syntax. Available keywords:

* `allow` / `deny`
* `user` or `:group`
* `as <target_user>`
* `cmd <pattern>` (wildcards `*`, `?`, or full regex)
* `priority <0-255>`
* `time HH:MM-HH:MM`
* `days <mon,tue,...,sun>` or `*` for all days

Example rule format:

```text
allow <user_or_:group> [as <target_user>] cmd <pattern> [priority <n>] [time <start>-<end>] [days <list>]
```

---

## Examples

```conf
# Allow user "alice" to run "journalctl" as root at any time
allow alice as root cmd journalctl

# Deny user "bob" from running "userdel" between 22:00 and 06:00 on weekdays
deny bob as root cmd userdel time 22:00-06:00 days mon,tue,wed,thu,fri

# Allow any member of group "admins" to run any command as any user, high priority
allow :admins cmd * priority 100

# Deny all users from rebooting or shutting down the system
deny all cmd reboot
deny all cmd shutdown
```

---

## Usage

Invoke `elev` just like you would `sudo` or `doas`:

```bash
$ elev journalctl -xe
```

For detailed help:

```bash
$ elev --help
```
