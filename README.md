# Interactive Nmap Wrapper

A cross‑platform, menu‑driven Python script that simplifies building and running complex **Nmap** commands.
Instead of memorizing dozens of switches, you can compose scans interactively, preview the exact command that will be executed.

---

## Table of Contents

1. [Features](#features)
2. [Requirements](#requirements)
3. [Quick Start](#quick-start)
4. [Usage Guide](#usage-guide)
   * [Main menu](#main-menu)
   * [Scan profiles](#scan-profiles)
   * [Saving results](#saving-results)
   * [Example workflows](#example-workflows)
5. [Troubleshooting](#troubleshooting)


---

## Features

* **Cross‑platform** – runs on Windows, Linux and macOS (not tested).
* **Full Nmap power** – exposes virtually every relevant flag (scan type, port list, timing, OS & service detection, scripts, output formats, etc.).
* **Interactive wizard** – clear, color‑free menus guide you through each decision.
* **Scan profiles** – pre‑defined presets for the most common tasks (quick, full, stealth, vulnerability).
* **Last‑scan replay** – rebuild and run the previous parameter set with one key‑press.
* **Clean output** – choose console, normal text, XML or grepable output files.
* **Graceful fall‑back** – warns if required tools (e.g. `nmap`) are missing.

---

## Requirements

| Requirement | Tested Versions             |
| ----------- |-----------------------------|
| **Python**  | 3.9 – 3.12                  |
| **Nmap**    | 7.95                        |
| **OS**      | Windows 10/11, Ubuntu 22.04 |

> **Note** – SYN, ACK, Window, FIN, Null and Xmas scans (anything that isn’t a TCP *connect* scan) typically require root/administrator privileges.

## Quick Start

```bash
py main.py
```

You’ll be greeted with a short banner confirming your platform and whether Nmap is located. From there, navigate the menu with the keys shown in square brackets.

---

## Usage Guide

### Main menu

```
[1] Set target (current: 192.168.1.1 ip)
[2] Set scan type (current: TCP SYN)
[3] Set ports (current: 1‑1000. Using top ports: False)
[4] Set service scanning (current: True with intensity 7. OS detection: False)

[P] Select a scan profile

[O] Set output option (current: stdout)
[T] Set timing/performance (current: 3)
[A] Set additional parameters (current: )
[E] Execute scan
[L] Use last used parameters
[Q] Quit
```

Pick an entry and follow the prompts. A few highlights:

| Key                | Action                                                        |
| ------------------ | ------------------------------------------------------------- |
| **1 Target**       | IP / range / CIDR, file list, or random selection.            |
| **2 Scan type**    | Build TCP (connect / SYN / ACK / FIN / etc.) or UDP scans.    |
| **3 Ports**        | Specific list, all, or *N* top common ports.                  |
| **4 Service scan** | Adds `‑sV`, optional intensity (1‑9) and OS detection (`‑O`). |
| **P Profiles**     | One‑shot presets that overwrite multiple fields.              |
| **T Timing**       | Maps to `‑T0`‑`‑T5` templates.                                |
| **A Additional**   | Raw extras (e.g. `‑Pn`, `‑sC`, custom NSE scripts).           |
| **E Execute**      | Shows the full command (`nmap ... -v`) then runs it.          |
| **L Last scan**    | Re‑runs the most recently executed parameter string.          |

### Scan profiles

| Profile       | Description                                   | Equivalent flags          |
| ------------- | --------------------------------------------- | ------------------------- |
| **1 Quick**   | Top 100 ports, SYN, service detection         | `‑sS --top‑ports 100 ‑sV` |
| **2 Full**    | All ports, SYN, service detection             | `‑sS -p‑ ‑sV`             |
| **3 Stealth** | Top 1000 ports, SYN, **no** service detection | `‑sS --top‑ports 1000`    |
| **4 Vuln**    | Current params + `--script vuln`              | `--script vuln`           |

### Saving results

* **Console only** – default (good for quick looks).
* **Normal text** – `‑oN <file>`
* **XML** – `‑oX <file>` (import into tools like Zenmap or Vuln scanners).
* **Grepable** – `‑oG <file>` for post‑processing with `awk/sed/grep`.

### Example workflows

1. **One‑off audit of a LAN host**

   1. `[1]` → `192.168.88.10`
   2. `[P]` → *Full scan*
   3. `[T]` → `4` (Aggressive)
   4. `[O]` → *XML*, output to `reports/host001.xml`
   5. `[E]` — *runs*:

      ```bash
      nmap 192.168.88.10 -p- -sV --version-intensity 7 -T4 -oX reports/host001.xml -v
      ```

2. **Quick sweep of common ports on multiple subnets**

   1. Prepare `targets.txt` with a list of CIDRs.
   2. `[1]` → *Targets from file* → `targets.txt`
   3. `[P]` → *Quick scan*
   4. `[A]` → `-Pn` (skip ping to catch firewalled hosts)
   5. `[E]` → *runs*:

      ```bash
      nmap -iL targets.txt --top-ports 100 -sV --version-intensity 7 -T3 -Pn -v
      ```

---

## Troubleshooting

| Symptom                         | Cause & fix                                                                                 |
| ------------------------------- | ------------------------------------------------------------------------------------------- |
| **“Nmap is not found!”**        | Ensure the binary is installed and `%PATH%`/`$PATH` includes its directory.                 |
| **“No last parameters found.”** | You haven’t executed a scan in this session yet – run one first.                            |