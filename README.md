# ARP Guard

ARP Guard is a passive ARP spoofing detector. The Member A detection engine learns a trusted IP-to-MAC baseline during a configurable startup window, analyzes ARP replies, suppresses duplicate alerts, and writes JSON Lines logs.

## Setup

Install the detector and canonical dashboard dependencies from the project root:

```powershell
py -m pip install -r requirements.txt
```

Configure the capture interface and thresholds in `config/settings.yaml`. Live ARP capture generally requires administrator privileges. The engine does not modify ARP tables or inject packets.

## Configuration Validation

`config/settings.yaml` must provide every documented setting. The loader rejects malformed YAML, missing or unknown keys, empty interface names, invalid IP/MAC whitelist entries, non-finite or invalid numeric thresholds, unsupported log levels, and log paths that name a directory. Interface availability is checked only when capture is requested so Windows and Linux interface names are both supported. Choose the interface reported by your operating system; `eth0` is only the sample setting.

## Canonical dashboard

The canonical dashboard is the dark-themed `web/` application, which connects to the
real detection engine and runs on port 5001. Start it from the project root with:

```powershell
py -m web.app
```

Open <http://127.0.0.1:5001/> in a browser. Use `POST /api/start` to request live
ARP capture after confirming that the configured interface is valid and that the
process has the required administrator privileges.

For a safe local demonstration, send `POST /api/test-alert`. This exercises the
detection engine with in-memory ARP-shaped test packets, updates the dashboard, and
persists one clearly labeled `simulated: true` JSONL event without transmitting any
packets or sending a desktop notification. It does not replace isolated VM-lab
testing of the real attack workflow.

## Alert Pipeline

`DetectionEngine` creates a JSON event with `timestamp`, `suspicious_ip`,
`old_mac`, `new_mac`, `reason`, `severity`, and `simulated`. It appends each emitted
event once to the configured `log_file` (default: `logs/arp_alerts.jsonl`) before
calling registered callbacks. `main.py` registers its CLI callback, which calls
`trigger_alert()` once for each real event. The canonical web callback appends every
event to its in-memory view and calls `trigger_alert()` once only for real events.
Simulated dashboard events use the same JSONL and dashboard path but intentionally
skip desktop notifications.

`alerts.log` is legacy notifier output. It is no longer written or read by the
canonical dashboard; existing entries are retained but are not migrated into JSONL.

## Attack Simulation Safety

`attack_sim/spoof_test.py` is dry-run by default and sends no packets. Transmission
is blocked unless all of `--transmit`, `--confirm-isolated-lab`, and an available
`--interface` are supplied. Even then, it sends at most 100 packets for at most 300
seconds. Only use transmission in an authorized, isolated lab. The dashboard
`POST /api/test-alert` endpoint remains an in-memory detector exercise and never
transmits packets.

## Tests

```powershell
py -m pytest -q
```

The sniffer accepts an injected `sniff_func`, so tests and integrations do not need live network capture.
