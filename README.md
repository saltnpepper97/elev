# elev

**elev** is a minimal, secure privilege elevation tool written in Rust — inspired by `doas` and `sudo`, but designed with modern practices and simplicity in mind.

---

## 🚀 Features

- 🔐 **Secure**: Written in safe, memory-checked Rust to prevent common vulnerabilities.
- ⚡ **Fast & Lightweight**: Focuses on minimalism, providing a swift and responsive experience.
- ✅ **Simple Configuration**: Easy-to-understand rule syntax for allowing and denying commands with fine-grained control.
- 🧩 **Customizable & Extensible**: Designed to be flexible and modifiable for various workflows and use cases.
- 🕒 **Time-Based Access**: Rules can be set to be active during specific time windows.
- 🚫 **Advanced Deny Logic**: Deny rules can override even `root` or other allow rules, ensuring precise control over command execution.
- 🔧 **Wildcard & Regex Support**: Supports both wildcards and regular expressions for flexible command matching.
- 🛡️ **Cybersecurity Focus**: Built with modern cybersecurity practices and solarpunk principles in mind, prioritizing safe technology and user autonomy.

---

## 🛠️ Building

To build `elev`, you'll need Rust > 1.70 installed. Then run this command:

```bash
cargo build --release

