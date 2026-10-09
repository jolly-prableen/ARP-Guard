# ARP Spoofing Detector — Project Plan & Role Division

**Team size:** 2
**Duration:** ~2–3 weeks
**Tech stack:** Python, Scapy, (optional) Flask/curses for dashboard

---

## 1. Project Overview

**Goal:** Build a tool that monitors a local network's ARP traffic and detects ARP spoofing attacks — where an attacker sends forged ARP replies to associate their MAC address with another device's IP (commonly the router), allowing them to intercept traffic (man-in-the-middle).

**Core idea:** Maintain a trusted table of IP → MAC mappings. Continuously sniff ARP traffic. If an IP suddenly resolves to a *different* MAC than what's trusted, or if there's a burst of unsolicited ARP replies, raise an alert.

**Deliverables at the end:**
1. Working detector script/application
2. Attack simulation script (used to test/demo the detector)
3. Alerting mechanism (console/log/notification)
4. Optional simple dashboard
5. Written report + demo video/screenshots
6. Presentation slides (if required)

---

## 2. Environment Setup (Both members, Day 1–2)

Before splitting work, set this up together so you're both testing on the same environment:

- Install **VirtualBox/VMware** or use **Docker containers** to create an isolated test network (do NOT run spoofing attacks on a real/shared network — this can get you in trouble on college or public Wi-Fi).
- Set up at least **3 machines/VMs** on the same virtual subnet:
  - **Victim** (normal machine)
  - **Attacker** (runs the spoofing tool)
  - **Detector** (runs your project)
- Install Python 3 + required libraries: `scapy`, `netifaces`, `scapy.all`, optionally `flask` for a dashboard.
- Agree on GitHub repo structure, branching strategy (e.g., `main`, `dev`, feature branches), and a shared task board (Trello/GitHub Projects/Notion).

---

## 3. Phase-Wise Workflow

### Phase 1: Research (Day 1–3, both)
- Understand ARP protocol (request/reply, broadcast, gratuitous ARP)
- Understand how ARP spoofing/poisoning attacks work
- Study existing tools for reference (arpwatch, XArp, Arpwatch) — not to copy, but to understand detection approaches
- Decide detection strategy (see Section 5)

### Phase 2: Core Development (Day 4–10, split by role — see Section 4)

### Phase 3: Integration & Testing (Day 11–14, both)
- Merge detection engine with alerting/dashboard
- Run real spoofing attacks in the VM lab and confirm detection works
- Tune thresholds to reduce false positives (e.g., DHCP lease changes can look like spoofing)
- Cross-test: each person tries to break/bypass the other's component

### Phase 4: Documentation & Presentation (Day 15–18, split)
- Write report, prepare slides, record demo

---

## 4. Detailed Role Division

### 👤 Person A — Detection Engine (Core Backend / Network Logic)

**Responsibility:** Everything related to capturing and analyzing ARP packets, and deciding when something is malicious.

| Task | Details |
|---|---|
| ARP packet sniffing | Use `scapy.sniff()` with filter `arp` to capture ARP packets in real time on the chosen interface |
| Baseline table builder | On startup, populate a trusted IP→MAC table — either by actively sending ARP requests to known hosts, or by passively learning for a short "safe" window |
| Core detection logic | Compare incoming ARP replies against the trusted table. Flag: (a) IP resolving to new/unexpected MAC, (b) same MAC claiming multiple IPs, (c) burst of unsolicited/gratuitous ARP replies in a short time window |
| Rate limiting / de-duplication | Avoid flooding alerts for the same event repeatedly |
| Logging | Write structured, timestamped logs (JSON or CSV) of all alerts: `timestamp, suspicious_ip, old_mac, new_mac, reason` |
| Config handling | Let network interface, whitelist IPs (e.g., router, printer), and detection sensitivity be configurable via a config file or CLI args |
| Unit tests | Test detection logic using pre-captured/mock ARP packets (no live network needed) |

**Skills needed:** Python, Scapy, basic networking (ARP/Ethernet headers), a bit of concurrency (sniffing runs in a loop/thread)

---

### 👤 Person B — Alerting, Interface & Attack Simulation

**Responsibility:** Everything the user sees, and the "attacker side" used to prove the detector works.

| Task | Details |
|---|---|
| Alert/notification system | Console warnings (colored via `colorama`), optional desktop notification (`plyer`/`notify2`) or webhook (Slack/Discord/email) when Person A's engine raises an alert |
| Live status display | A simple CLI table (using `rich` or `tabulate`) or lightweight Flask dashboard showing: known devices, current alert count, alert history |
| Attack simulation script | Build (or configure existing tool like `arpspoof`/`ettercap`) a controlled ARP spoofing script to run against your own VM lab — this is what you'll use to demonstrate detection working |
| Demo scenario scripting | Plan and script the actual demo: start detector → launch attack → show alert firing in real time → screen record it |
| UI/UX polish | Make the output readable and presentable — this matters a lot for grading/demo impact |
| Error handling & usability | Handle cases like missing permissions (ARP sniffing needs root/admin), invalid interface names, etc., with clear user-facing messages |

**Skills needed:** Python, basic frontend/CLI design, familiarity with existing ARP attack tools, screen recording

---

### 🤝 Shared Responsibilities (Both)

- Integration: connecting Person A's detection engine to Person B's alert/UI layer via a clean function call or event system (e.g., `on_alert(callback)`)
- End-to-end testing in the VM lab
- Writing the final report (split by section — see below)
- Preparing and rehearsing the presentation/demo
- Code reviews on each other's pull requests

---

## 5. Detection Strategy Options (decide together before coding)

| Approach | Pros | Cons |
|---|---|---|
| Static baseline (snapshot IP-MAC table once at start) | Simple, fast to implement | Breaks if legitimate IP changes (DHCP renewal) |
| Continuous learning with trust window | More realistic | Slightly more complex, needs tuning |
| Passive monitoring only (alert, don't act) | Safe, simpler, recommended for this scope | Doesn't stop the attack, only detects |
| Active defense (auto-restore correct ARP entries) | Impressive "extra credit" feature | Riskier, more complex, can cause network issues if buggy |

**Recommendation:** Start with passive monitoring + continuous learning with a whitelist for known static devices (router, printer). Only add active defense if time permits, as a stretch goal.

---

## 6. Suggested Repository Structure

```
arp-guard/
├── detector/
│   ├── sniffer.py         # Person A
│   ├── baseline.py        # Person A
│   └── detect.py          # Person A
├── alerts/
│   ├── notifier.py        # Person B
│   └── dashboard.py       # Person B
├── attack_sim/
│   └── spoof_test.py      # Person B
├── config/
│   └── settings.yaml      # Shared
├── tests/
│   ├── test_detect.py     # Person A
│   └── test_alerts.py     # Person B
├── docs/
│   ├── report.pdf         # Shared
│   └── demo.mp4           # Shared
├── main.py                 # Shared (integration entry point)
├── requirements.txt
└── README.md
```

---

## 7. Report Section Split (for final writeup)

| Section | Owner |
|---|---|
| Introduction & Problem Statement | Shared |
| ARP & ARP Spoofing Background | Person A |
| System Design / Architecture | Person A |
| Detection Methodology | Person A |
| Implementation Details (Alerting/UI) | Person B |
| Attack Simulation & Testing Methodology | Person B |
| Results & Screenshots | Shared |
| Limitations & Future Work | Shared |
| Conclusion | Shared |

---

## 8. Timeline Summary

| Days | Milestone |
|---|---|
| 1–3 | Research + environment setup |
| 4–7 | Person A: sniffing + baseline + detection logic |
| 4–7 | Person B: attack simulation + alert system skeleton |
| 8–10 | Both: integrate detection engine with alerting/dashboard |
| 11–13 | Live testing in VM lab, bug fixing, threshold tuning |
| 14–16 | Documentation, report writing |
| 17–18 | Slides, demo recording, rehearsal |

---

## 9. Stretch Goals (if time allows)

- Auto-restore correct ARP entries (active defense mode)
- Email/SMS alert integration
- Web-based real-time dashboard (Flask + WebSocket)
- Export alert history as PDF report
- Support for detecting spoofing across VLANs
