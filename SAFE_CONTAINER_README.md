# PhishGuard AI — Safe Container & Browser Isolation Subsystem
> **Zero-Trust Disposable Browser Sandbox for Threat Analysis & Phishing Forensics**

---

## 🎯 Executive Summary (الملخص التنفيذي للبريسنتيشن)

In modern cyber threats, attackers use sophisticated evasion techniques: **delayed DOM rendering, transparent clickjacking overlays, JavaScript obfuscation, DOM clobbering, credential redirection, and anti-analysis cloaking**. Standard web scrapers or static HTML analyzers fail completely against these threats.

To solve this, **PhishGuard AI** implements an enterprise-grade **Safe Container / Browser Isolation Subsystem**:
* **Zero-Trust Architecture:** Every inspected website is treated as inherently hostile and untrusted.
* **Dual-Phase Air-Gap Design:** Strictly separates **Network Acquisition** (Host Airlock) from **Code Execution** (Disconnected Container).
* **Disposable Execution:** Chromium runs inside a sandboxed Linux container that is spun up on-demand and destroyed immediately after extraction, preventing persistent compromises.
* **Multi-Modal Forensics:** Correlates dynamic DOM observations, interactive click probes, OCR/Visual analysis, and Machine Learning into an **Attack Sequence Timeline**.

---

## 🏗️ Subsystem Architecture: The Dual-Phase Airlock

```
                             [ UNTRUSTED INTERNET ]
                                        │
                                        ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │  PHASE 1: RESTRICTED HTTP BROKER ("THE AIRLOCK" / HOST ISOLATION)      │
   │  ──────────────────────────────────────────────────────────────────    │
   │  • DNS Validation & Rebinding Protection (Pre-flight socket pinning)  │
   │  • Anti-SSRF (Blocks RFC1918, Link-Local, Cloud Metadata 169.254.x.x) │
   │  • Strict Capture Budget (6MB single, 16MB bundle, 24MB transfer)      │
   │  • Per-Hop Redirect Validation (Max 5 hops, refuses HTTPS downgrades)  │
   │  • Content Sanitizer (Discards attachments, binary archives, cookies) │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                      In-Memory Canonical Replay Bundle
                       (Passed strictly via STDIN)
                                       │
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │  PHASE 2: AIR-GAPPED CHROMIUM CONTAINER (--network=none)              │
   │  ──────────────────────────────────────────────────────────────────    │
   │  • ZERO Network Access: No outbound sockets, no DNS, no host mounts    │
   │  • Hardened Linux Kernel: Seccomp filters, cap-drop=ALL, no-new-privs │
   │  • Non-Root Execution: User 65532:65532, Read-Only Root Filesystem     │
   │  • Resource Cgroups v2: 1 CPU, 768MB RAM, 0 Swap, 160 PIDs, 128MB SHM  │
   │  • Multi-Checkpoint DOM Inspection & Clickjacking Hit-Test Sampling    │
   │  • Controlled Probing: Synthetic credentials & form-action tracing    │
   └───────────────────────────────────┬────────────────────────────────────┘
                                       │
                      Structured JSON Report & Screenshots
                       (Returned strictly via STDOUT)
                                       │
                                       ▼
   ┌────────────────────────────────────────────────────────────────────────┐
   │  PHASE 3: FORENSIC CORRELATION & INTERACTIVE THREAT EXPLORER           │
   │  ──────────────────────────────────────────────────────────────────    │
   │  • Computer Vision & RapidOCR matching with DOM geometry               │
   │  • Behavioral Fingerprint (SHA-256 profile of 5 observation groups)   │
   │  • Attack Sequence Timeline (Initial Paint ➔ Mutation ➔ Exfiltration) │
   │  • React-Based Interactive Threat Explorer & Evidence Store (SQLite)   │
   └────────────────────────────────────────────────────────────────────────┘
```

---

## 🛡️ Security Layers & Hardening Specifications

### 1. Network Isolation & SSRF Defense (Phase 1)
| Defense Mechanism | Engineering Implementation |
| :--- | :--- |
| **Connection-Level Pinning** | Resolves DNS, inspects all returned IPs against blacklists, and connects directly to the validated numeric IP. Prevents **DNS Rebinding** mid-stream. |
| **Comprehensive SSRF Filtering** | Denies private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`), Loopback (`127.0.0.0/8`), Link-Local (`169.254.0.0/16`), IPv6 transition ranges, and cloud metadata endpoints (`http://169.254.169.254`). |
| **Strict Redirect Enforcement** | Up to 5 redirect hops. Every redirect destination must undergo full IP verification. Refuses HTTPS-to-HTTP downgrades. |
| **Resource & Response Budgeting** | Bounded reading: Max **6 MB** per asset, **16 MB** total bundle, **24 MB** wire transfer budget. Eliminates Zip Bombs and resource-exhaustion DoS attacks. |
| **Header & Scheme Restrictions** | Only `http` and `https` schemes. Default ports (80/443). Discards dangerous content dispositions and non-web payloads. |

### 2. Container Isolation & Sandboxing (Phase 2)
| Sandbox Dimension | Parameter / Setting | Security Objective |
| :--- | :--- | :--- |
| **Network Egress** | `--network=none` | Absolute air-gap: The container cannot initiate or receive network packets during inspection. |
| **Filesystem Security** | `--read-only`, `--tmpfs /tmp:size=160m,noexec,nosuid,nodev` | Prevents disk persistence, malware staging, or root modification. |
| **Privilege Level** | `--user 65532:65532` (`nonroot`), `--security-opt no-new-privileges=true` | Eliminates privilege escalation attacks (e.g. SUID abuse). |
| **Linux Capabilities** | `--cap-drop=ALL` | Drops all kernel capabilities (no `CAP_SYS_ADMIN`, no `CAP_NET_RAW`, etc.). |
| **Syscall Filtering** | Custom Seccomp BPF Profile (`src/sandbox/isolation_seccomp.json`) | Restricts Linux system calls to the bare minimum needed for Chromium and headless rendering. |
| **Resource Quotas** | `--cpus=1.0`, `--memory=768m`, `--memory-swap=768m`, `--pids-limit=160` | Protects host against CPU starvation, memory leaks, fork-bombs, or browser hangs. |
| **Chromium Sandbox** | Zygote chroot + User Namespaces enabled | Does **NOT** disable Chrome's internal sandbox (avoids the vulnerable `--no-sandbox` flag). |
| **Stronger Isolation Option** | Supports gVisor (`PHISHGUARD_SANDBOX_RUNTIME=runsc`) | Hypervisor-grade virtualization of kernel syscalls where available. |

### 3. Secure Inter-Process Communication (IPC)
* **No Host Mounts & No Docker Socket:** The container has zero visibility into the host filesystem or Docker daemon socket (`/var/run/docker.sock`).
* **Clean Stdin / Stdout Protocol:** The capture bundle is streamed to container `stdin`. The execution results (evidence JSON and base64 screenshots) are streamed back over `stdout`.
* **Automatic Watchdog Termination:** Disposable containers are automatically killed and pruned via timeout watchdogs (`--kill-after=2s`, host timeout 60s, supervisor deadline 210s).

---

## 🔍 Dynamic Threat Analysis & Forensic Capabilities

### 1. Multi-Checkpoint Temporal Analysis (Anti-Cloaking)
* **The Problem:** Modern phishing sites delay rendering login boxes (e.g., via `setTimeout` for 1–3 seconds) to trick automated scanners that take immediate snapshots.
* **PhishGuard Solution:** Takes two discrete temporal observations:
  - **Early Checkpoint:** Captures initial paint and DOM structure.
  - **Late Checkpoint:** Waits 1.1s to 6.0s (bounded by readiness heuristics: settled fonts, decoded images, zero pending network/JS promises).
  - Detects **dynamic overlay creation**, **cloaked modals**, and **visibility tampering**.

### 2. Interactive Probing & Click Trapping Detection
* Samples coordinate grid (8x6 hit-test matrix) using native `elementFromPoint`.
* Identifies **transparent clickjacking layers** covering legitimate buttons or inputs.
* Safely exercises up to **4 top-level interactive controls** (buttons, form submitters) in fresh isolated contexts using synthetic inputs only.
* Tracks if submitting a form alters the `form.action` destination to a suspicious third-party exfiltration server.

### 3. DOM Clobbering & Adversarial Resilience
* Resistant to malicious DOM structures designed to break JavaScript analyzers (e.g. `<input name="type">` or `<input name="length">` overwriting DOM properties).
* Sanitizes input types, prototype methods, and recursive node trees.

### 4. Deterministic Replay & Behavior Fingerprinting
* Every capture is hashed via **SHA-256** and privately archived in SQLite.
* Analysts can execute an exact **Offline Replay** at any time without ever contacting the live target again.
* **Behavior Profile:** Generates 5 distinct SHA-256 digests across:
  1. DOM Structure
  2. JavaScript Execution Traces
  3. Network Destination Attempts
  4. Navigation & Redirect State
  5. Visual Layout & OCR Findings
* Enables automated detection of evasion drift between successive scans.

---

## 💻 Tech Stack & Component Architecture

| Component | Technology | Role |
| :--- | :--- | :--- |
| **Host Supervisor & API** | Python 3.12, FastAPI, Uvicorn, SQLite3 | Job admission, rate-limiting, supervisor lifecycle, artifact store |
| **Capture Broker** | Python `urllib`, Socket-level IP validation | Airlock HTTP client, SSRF/DNS rebinding barrier |
| **Browser Engine** | Chromium (Playwright headless engine) | DOM rendering, hit-testing, layout calculation, JS runtime |
| **Container Engine** | Docker Engine / cgroup v2 / Seccomp BPF | Process and kernel isolation, quota enforcement |
| **Visual Analysis** | RapidOCR, OpenCV, PIL | Text recognition, coordinate alignment, full-page stitching |
| **Frontend UI** | React 19, Vite, Tailwind CSS, Lucide | Interactive Threat Explorer, DOM layer inspector, sequence viewer |

---

## 📊 Key Performance Metrics & Benchmarks

* **Comprehensive Test Suite:** **297 Automated Tests** (`275 passed`, `22 skipped`, `0 failed`).
* **Real-World Complex Scan Benchmark (`ums.asu.edu.eg`):**
  - **Raw HTML Payload:** 3.61 MB (Massive enterprise portal).
  - **Total Pipeline Execution Time:** 55.4 seconds.
  - **Container Execution:** 13.5 seconds.
  - **DOM Regions Extracted & Analyzed:** 200 interactive elements.
  - **Screenshots Generated:** 11 full forensic images (`viewport`, `annotated`, `full_page`, before/after action captures).
  - **Container Peak Memory:** 465 MB (Well within 768 MB quota).
* **Storage Deduplication:** Image aliasing reduces stored screenshot bytes by **74.7%** on multi-phase runs.

---

## 🎤 Presentation Slides Breakdown (خطة شرائح العرض التقديمي)

### 📌 Slide 1: The Challenge (لماذا تفشل الطرق التقليدية؟)
* **Title:** The Blind Spot in Phishing Detection: Dynamic & Evasive Web Threats
* **Key Points:**
  - Modern phishing is not static HTML: uses dynamic JavaScript, delayed rendering, clickjacking, and DOM clobbering.
  - Scanning live malicious websites directly exposes host machines to drive-by downloads, IP leakage, and zero-day browser exploits.
  - Simple HTTP fetchers (like `requests` or `curl`) miss all client-side rendered attacks.

### 📌 Slide 2: The Solution (الحل: نظام الحاوية الآمنة)
* **Title:** PhishGuard Safe Container: Air-Gapped Browser Isolation
* **Key Points:**
  - Zero-Trust disposable Chromium environment.
  - **Dual-Phase Architecture:** Decoupling network capture from code execution.
  - Live inspection of hostile sites without any risk to analyst systems.

### 📌 Slide 3: Defensive Engineering & Hardening (الطبقات الأمنية للحاوية)
* **Title:** Defense-in-Depth: From Host to Kernel
* **Key Points:**
  - **Host Airlock (SSRF Shield):** Pre-flight DNS validation, IP pinning, cloud metadata blocking (`169.254.169.254`).
  - **Container Hardening:** `--network=none`, `--read-only` rootfs, `cap-drop=ALL`, non-root user `65532`, Seccomp BPF filter.
  - **Resource Cgroups:** Strict 1 CPU / 768 MB RAM boundaries prevent DoS or fork-bombs.

### 📌 Slide 4: Behavioral & Forensic Inspection (التحليل السلوكي والاستكشاف)
* **Title:** Beyond Static Screenshots: Dynamic Forensics
* **Key Points:**
  - **Multi-Checkpoint Timing:** Early vs. late observations catch delayed rendering evasion (1.1s–6s).
  - **Hit-Test Coordinate Sampling:** Exposing invisible overlays, clickjacking traps, and disguised inputs.
  - **Controlled Probing:** Testing buttons and forms with synthetic data to observe exfiltration destinations.

### 📌 Slide 5: Multi-Modal Fusion & Attack Sequence (الذكاء الاصطناعي والتسلسل الهجومي)
* **Title:** Attack Sequence Reconstruction & Vision Fusion
* **Key Points:**
  - Automatic timeline reconstruction: `Initial Paint ➔ DOM Mutation ➔ Redirection ➔ Exfiltration`.
  - Geometric fusion of RapidOCR text with DOM elements.
  - Machine Learning integration (URL models + heuristic risk correlation).

### 📌 Slide 6: Validation & Live Demo (الأدلة التجريبية والتشغيل الفعلي)
* **Title:** Real-World Validation & Performance
* **Key Points:**
  - Tested on complex real-world portals (e.g. Ain Shams University Portal: 3.6 MB HTML, 200 DOM regions, 11 screenshots in 55s).
  - Resilient to DOM Clobbering (handled adversarial portals like `arabseed.press`).
  - **100% Passing Tests:** 275 unit, adversarial, and integration tests passed.

---

## ❓ Defense Q&A: Expected Jury Questions & Model Answers

### Q1: Why didn't you just use standard Playwright/Selenium connected to the internet?
> **Answer:** Standard browser automation with direct internet access allows malicious websites to perform SSRF attacks against internal networks, probe cloud metadata endpoints (`169.254.169.254`), or exploit browser vulnerabilities to compromise the host. By introducing our **Restricted HTTP Airlock** and running Chromium with `--network=none`, the browser is 100% air-gapped. It only sees pre-validated, sanitized web assets.

### Q2: How do you defeat sites that use delayed execution (Cloaking) to fool scanners?
> **Answer:** PhishGuard implements **Multi-Checkpoint Temporal Inspection**. Rather than taking a single instant screenshot, the engine records an early checkpoint, checks document readiness (font settlement, layout stability, pending timers), waits at least 1.1s (up to 6s), and records a late checkpoint. Any dynamic DOM shifts, popup overlays, or modified button targets are explicitly detected and reported.

### Q3: What prevents a malicious script from breaking out of the container (Container Escape)?
> **Answer:** We enforce five independent isolation boundaries:
> 1. Chromium's internal sandbox is preserved (not disabled).
> 2. The container runs as unprivileged user (`65532:65532`) with `no-new-privileges`.
> 3. All Linux capabilities are dropped (`cap-drop=ALL`).
> 4. Root filesystem is strictly read-only (`--read-only`).
> 5. Syscalls are filtered through a custom Seccomp profile blocking sensitive kernel interfaces.
> 6. Optional gVisor (`runsc`) support virtualizes the kernel interface entirely.

### Q4: What is "Deterministic Replay" and why does it matter for SOC analysts?
> **Answer:** When an incident responder investigates an alert, contacting a live phishing URL weeks later might fail because the attacker took it down. PhishGuard hashes and stores the complete raw web bundle in SQLite. An analyst can execute a **Deterministic Replay** offline inside the container at any time, reproducing the exact visual and behavioral state as when it was first observed.

---

## 🚀 How to Run the System (Quickstart)

### 1. Build the Hardened Container Image
```powershell
docker --host npipe:////./pipe/docker_engine buildx build --builder default --load -f Dockerfile.sandbox -t phishguard-browser:local .
```

### 2. Start the API Server
```powershell
$env:PHISHGUARD_SANDBOX_TOKEN = "phishguard-safe-container-token-2026"
.\.venv\Scripts\python.exe -m uvicorn src.api.main:app --host 127.0.0.1 --port 8000
```

### 3. Open the Interactive Threat Explorer
Navigate to: **`http://127.0.0.1:8000/explorer/`**
Enter the authentication token and submit any target URL for safe inspection.
