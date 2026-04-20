# 🔐 K-Lock  
## 🛡️ Your Application May Fall to a Zero-Day. Your Server Won't.
Stop reverse shells, unauthorized binaries, and data exfiltration at the kernel level—even after an attacker achieves full Remote Code Execution.

K-Lock is a high-performance, kernel-level runtime security tool designed to protect Linux applications from **Remote Code Execution (RCE)**.

Unlike traditional security tools that operate in user space, K-Lock runs directly inside the **Linux Kernel** using:

- **eBPF (Extended Berkeley Packet Filter)**
- **LSM (Linux Security Module) hooks**

It intercepts system calls in real-time to block:

- Unauthorized command execution  
- Restricted file access  
- Suspicious outbound network connections  

---

## ✨ Key Features

- 🚫 **RCE Prevention**  
  Blocks execution of any binary not explicitly listed in your whitelist.

- 📂 **Data Exfiltration Shield**  
  Prevents reading sensitive files such as `/etc/passwd` or `.env`.

- 🌍 **Network Egress Control**  
  Restricts outbound IPv4 traffic to authorized IP addresses only.

- 🧱 **Zero-Code Integration**  
  Protects your application without requiring any changes to your source code.

---

## 🖥 System Requirements

To run K-Lock, your system must meet the following requirements:

### Operating System
- Linux Kernel **5.7+** (required for BPF LSM support)

### Architecture
- x86_64

### Required Kernel Configuration

```bash
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
```

---

## 📦 Installation & Building

### 1️⃣ Install Dependencies (Ubuntu / Debian)

```bash
sudo apt update
sudo apt install -y clang llvm libelf-dev libbpf-dev libc6-dev-i386 zlib1g-dev
```

---

### 2️⃣ Clone and Build

```bash
git clone <your-repo-url>
cd k-lock
make
```

After building, the `dist/` folder will contain:

```
dist/
├── rce_guard    # Userspace loader binary
├── rce_core.o   # Compiled eBPF object
└── config.json  # Security policy file
```

---

## 🔧 Configuration (Absolute Path Method)

To ensure K-Lock correctly locates your server files, you **must use absolute paths** (starting from `/`) inside `config.json`.

Edit:

```
dist/config.json
```

### Example Configuration

```json
{
    "run_command": "/usr/bin/node /home/taher/Projects/vulnerable-react-server/node_modules/.bin/next start /home/taher/Projects/vulnerable-react-server -H 0.0.0.0",
    "policy": {
        "allowed_outbound_ips": [
            "127.0.0.1"
        ],
        "blocked_paths": [
            "passwd",
            "shadow",
            ".env",
            "id_rsa"
        ],
        "allowed_commands": [
            "node",
            "npm",
            "next",
            "node_modules/.bin/next"
        ]
    }
}
```

---

### Field Breakdown

**run_command**  
The exact command used to start your application.  
Always use the full absolute path for both:

- The runtime binary (e.g., `/usr/bin/node`)
- The application script

**allowed_outbound_ips**  
Whitelist of trusted IPv4 addresses.

**blocked_paths**  
Path keywords.  
If a file path contains any of these values, access is denied.

**allowed_commands**  
Whitelist of binaries allowed to execute.  
All other executions will be blocked.

---

## 🚀 Usage

Because K-Lock interacts directly with the Linux kernel, it must be run as root.

### 1️⃣ Navigate to the Distribution Folder

```bash
cd dist
```

### 2️⃣ Execute the Guard

```bash
sudo ./rce_guard
```

---

## ⚙ How It Works

1. K-Lock reads your configuration file.
2. It loads the eBPF programs into the Linux kernel.
3. Your application is launched as a **Protected Process**.
4. The kernel enforces policy rules in real-time.

If your application (or an attacker exploiting RCE) attempts to:

- Run `whoami`
- Execute `curl`
- Read `/etc/passwd`

The kernel immediately blocks the action by returning:

```
-EPERM (Operation not permitted)
```

The action is stopped **before it even begins**.

---

## 🏗 Project Structure

```
.
├── bpf/
│   └── rce_core.c      # Kernel-level eBPF logic (LSM hooks)
├── src/
│   ├── main.cpp        # Userspace Loader & Policy Engine
│   └── include/        # Header files
├── dist/               # Compiled binaries (after running 'make')
└── Makefile            # Build system
```

---

## 🛡 Security Logic (The "Why")

K-Lock attaches to the **LSM (Linux Security Module)** layer.

When a protected process attempts an action:

1. The Linux kernel triggers a security hook.
2. K-Lock’s eBPF program evaluates the whitelist.
3. If the action is unauthorized:
   - The kernel denies it immediately.
   - The syscall returns `-EPERM`.

This ensures violations are prevented — not merely logged.

---

## 📜 License


# 👤 Author

**Md. Abu Taher Shekh**

📧 Email: [taherkng83@gmail.com](mailto:taherkng83@gmail.com)
🐙 GitHub: [muhammad-taher](https://github.com/muhammad-taher)

---

This project is licensed under the **GNU General Public License (GPL)**.

---

**K-Lock — Kernel-Level Runtime Enforcement for Modern Linux Security.**
