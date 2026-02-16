# 🔐 K-Lock  
## eBPF-Powered RCE Guard

**K-Lock** is a kernel-level security tool designed to protect Linux applications from **Remote Code Execution (RCE)** and unauthorized activities.

It leverages **eBPF (Extended Berkeley Packet Filter)** and **Linux Security Module (LSM)** hooks to monitor and restrict processes directly inside the Linux kernel — enforcing a custom runtime security policy without modifying your application code.

---

## ✨ Features

- 🧱 **Process Sandboxing**  
  Automatically tracks and protects child processes spawned by the target application.

- 🚫 **Command Whitelisting**  
  Blocks execution of any binary not explicitly allowed in the configuration.

- 🌍 **Network Restriction**  
  Restricts outbound IPv4 connections to trusted IP addresses only.

- 📂 **File Access Control**  
  Blocks access to sensitive files (e.g., `/etc/passwd`) based on path keywords.

---

## ⚙️ Prerequisites

Before installing, ensure your system meets the following requirements:

### 🖥 System Requirements

- **OS:** Linux (Kernel **5.7+** required for BPF LSM support)  
- **Architecture:** x86_64  
- **Kernel Config Required:**

```bash
CONFIG_BPF_LSM=y
CONFIG_DEBUG_INFO_BTF=y
```

---

## 📦 Dependencies

Install required build tools and libraries.

### Ubuntu / Debian Example:

```bash
sudo apt update
sudo apt install -y clang llvm libelf-dev libbpf-dev libc6-dev-i386 zlib1g-dev
```

---

## 🛠 Installation & Building

### 1️⃣ Clone the Repository

```bash
git clone <your-repo-url>
cd K-Lock_Source-main
```

---

### 2️⃣ Build the Project

The provided `Makefile` compiles both:

- The eBPF kernel program
- The userspace loader

```bash
make
```

After building, the following files will be generated inside the `dist/` directory:

```
dist/
├── rce_core.o     # Compiled eBPF bytecode
├── rce_guard      # Userspace loader binary
└── config.json    # Security policy configuration
```

---

## 🔧 Configuration

The security policy is defined in:

```
dist/config.json
```

You can modify this file based on your application’s needs.

### Configuration Fields

- **run_command**  
  The command you want to protect  
  Example: `"npm run start"`

- **allowed_outbound_ips**  
  List of IPv4 addresses the application is allowed to contact

- **blocked_paths**  
  Filenames or path keywords that should be inaccessible

- **allowed_commands**  
  Whitelist of binaries the application is allowed to execute

---

### Example Configuration

```json
{
    "run_command": "npm run start",
    "policy": {
        "allowed_outbound_ips": ["127.0.0.1", "8.8.8.8"],
        "blocked_paths": ["passwd"],
        "allowed_commands": ["ls", "node", "npm", "sh"]
    }
}
```

---

## 🚀 Usage

Since K-Lock interacts directly with the Linux kernel via eBPF, it must be run with root privileges.

### 1️⃣ Navigate to the Distribution Folder

```bash
cd dist
```

### 2️⃣ Execute the Guard

```bash
sudo ./rce_guard
```

K-Lock will:

- Launch your protected application  
- Attach BPF programs to its PID  
- Monitor for policy violations  
- Block unauthorized execution, file access, or outbound connections  

---

## 🏗 Project Structure

```
bpf/
└── rce_core.c        # eBPF kernel logic (LSM hooks for exec, network, file access)

src/
├── main.cpp          # Userspace loader (reads config.json & loads BPF programs)
└── include/          # Header files

Makefile              # Build instructions for clang and clang++
```

---

## 🛡 Security Model

K-Lock attaches eBPF programs to Linux Security Module (LSM) hooks to intercept:

- `execve()` system calls  
- File open operations  
- Outbound socket connections  

All policy decisions are enforced **inside the kernel before execution completes**, preventing exploitation rather than detecting it afterward.

---

## 📌 Best Practices

- Test policies in staging before production deployment  
- Start with minimal restrictions and tighten gradually  
- Monitor kernel logs during initial rollout  
- Keep your Linux kernel updated  
- Regularly audit allowed IPs and commands  

---

## 📜 License

This project is licensed under the **GPL (GNU General Public License)**.

---

## ⭐ Contributing

Contributions, security discussions, and improvements are welcome.

If you find this project useful, consider giving it a ⭐.

---

**K-Lock — Kernel-Level Runtime Enforcement for Modern Linux Security.**
