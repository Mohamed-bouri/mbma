# Mbma - High-Performance Network Security Auditor

`Mbma` is a fast, multi-threaded network security auditor and port scanner built with Python 3. Designed for security professionals, system administrators, and penetration testers, it leverages concurrent processing to audit thousands of network ports efficiently, gather service banners, and map potential entry points.[cite: 1]

---

## 🚀 Features

- **High-Velocity Multi-Threading:** Utilizes Python's `concurrent.futures.ThreadPoolExecutor` to handle hundreds of concurrent connection workers simultaneously.[cite: 1]
- **Service Banner Grabbing:** Attempts to extract protocol banners from open ports to facilitate immediate service and version identification.[cite: 1]
- **Flexible Port Targeting:** Supports scanning predefined single ports, custom comma-separated lists (e.g., `80,443,8080`), or sequential ranges (e.g., `1-1024`).[cite: 1]
- **Cross-Platform Compatibility:** Native ANSI escape sequences optimized for clear, colorized command-line terminal outputs on Linux, macOS, and Windows 10+.[cite: 1]
- **Robust Input & Signal Handling:** Gracefully manages host resolution translation failures and user keyboard interrupts (`Ctrl+C`).[cite: 1]

---

## 🛠️ Installation & Setup

1. **Clone the Repository:**
   ```bash
   git clone [https://github.com/Mohamed-bouri/mbma.git](https://github.com/Mohamed-bouri/mbma.git)
   cd Mbma
   ```[cite: 1]

2. **Verify Python Installation:**
   Ensure you have Python 3.6 or higher installed on your system:
   ```bash
   python --version
   ```[cite: 1]

---

## 📖 Usage Guide

Run the tool directly from your command-line terminal interface by passing the required configuration flags:

```bash
python mbma.py -t <target-ip-or-domain> [options]
```[cite: 1]

### Command Line Arguments

| Flag | Long Flag | Required | Default | Description |
| :---: | :--- | :---: | :---: | :--- |
| `-t` | `--target` | **Yes** | — | Target IP address or host domain name to audit. |
| `-p` | `--ports` | No | `1-1024` | Port sequence to scan. Supports ranges (`20-80`) or lists (`80,443`). |
| `-w` | `--workers` | No | `100` | Number of concurrent execution threads (workers). |
| | `--timeout` | No | `1.0` | Network socket connection timeout threshold in seconds. |[cite: 1]

### Practical Examples

- **Audit a local loopback target across a specific range:**
  ```bash
  python mbma.py -t 127.0.0.1 -p 20-150
  ```[cite: 1]

- **Scan a specific remote domain for standard web ports with optimized thread speed:**
  ```bash
  python mbma.py -t example.com -p 80,443,8080,8443 -w 50 --timeout 1.5
  ```[cite: 1]

---

## 📊 Sample Output

When executed successfully, `Mbma` generates a cleanly colorized terminal summary detailing the target attributes, real-time port states, and corresponding service signatures:

```text
-                                                                        
     ______  _______         _____       ______  _______         _____   
    |      \/       \   ___|\     \     |      \/       \    ___|\    \  
   /          /\     \ |    |\     \   /          /\     \  /    /\    \ 
  /     /\   / /\     ||    | |     | /     /\   / /\     ||    |  |    |
 /     /\ \_/ / /    /||    | /_ _ / /     /\ \_/ / /    /||    |__|    |
|     |  \|_|/ /    / ||    |\    \ |     |  \|_|/ /    / ||    .--.    |
|     |       |    |  ||    | |    ||     |       |    |  ||    |  |    |
|\____\       |____|  /|____|/____/||\____\       |____|  /|____|  |____|
| |    |      |    | / |    /     ||| |    |      |    | / |    |  |    |
 \|____|      |____|/  |____|_____|/ \|____|      |____|/  |____|  |____|
    \(          )/       \(    )/       \(          )/       \(      )/  
     '          '         '    '         '          '         '      '   
                                                                         
[ Network Security Auditor v2.0 ]

[+] Target Identity : 127.0.0.1 (127.0.0.1)
[+] Audit Launched  : 2026-07-18 14:06:53
[+] Thread Count    : 100 active workers
[+] Scope Size      : 131 targets
-----------------------------------------------------------------
[OPEN] Port 135   | Banner: Unknown Service
-----------------------------------------------------------------
[+] Audit Finished. Discovered 1 active entry points.
```[cite: 1]

---

## ⚖️ Legal & Ethical Disclaimer

**Important Notice:** This tool is developed strictly for authorized security auditing, defensive vulnerability assessments, and educational research purposes. Unauthorized network scanning against infrastructure without explicit, written prior consent from the system owner is highly illegal and unethical. The author accepts no liability and is not responsible for any misuse or damage caused by this software program.[cite: 1]

---

## 📝 License

Distributed under the **MIT License**. See `LICENSE` for more information.[cite: 1]

---
Created with 💻 by [Mohamed BOURI](https://github.com/Mohamed-bouri)[cite: 1]
