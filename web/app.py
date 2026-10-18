
"""Unified ARP-Guard web dashboard and detection backend."""

import json
import sys
import threading
from collections import deque
from pathlib import Path
from types import SimpleNamespace

from flask import Flask, jsonify, render_template

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from detector.config import DetectorConfig, load_config
from detector.detect import DetectionEngine
from detector.sniffer import Sniffer
from alerts.notifier import trigger_alert

app = Flask(
    __name__,
    template_folder=str(ROOT / "web" / "templates"),
    static_folder=str(ROOT / "web" / "static"),
)

try:
    config = load_config(ROOT / "config" / "settings.yaml")
    configuration_error = None
except ValueError as exc:
    configuration_error = str(exc)
    config = DetectorConfig()
engine = DetectionEngine(config)

alerts = deque(maxlen=200)
lock = threading.Lock()
state = {
    "running": False,
    "starting": False,
    "error": None,
    "started": False,
}


def receive_alert(event):
    """Store each emitted event and notify only for real detections."""
    event = dict(event)

    with lock:
        alerts.append(event)

    if event.get("simulated"):
        return

    try:
        trigger_alert(
            str(event.get("suspicious_ip", "Unknown")),
            str(event.get("old_mac") or "Unknown"),
            str(event.get("new_mac") or "Unknown"),
            reason=str(event.get("reason", "ARP anomaly detected")),
        )
    except Exception:
        app.logger.exception("Notification handler failed")


engine.on_alert(receive_alert)


def capture_packets(sniffer):
    """Run passive packet capture in a background thread."""
    try:
        sniffer.start(on_ready=mark_capture_running)
    except Exception as exc:
        app.logger.exception("ARP capture failed")
        with lock:
            state["error"] = str(exc)
    finally:
        with lock:
            state["running"] = False
            state["starting"] = False


def mark_capture_running():
    """Mark capture running only after interface setup has been validated."""
    with lock:
        state["running"] = True
        state["starting"] = False


@app.get("/")
def dashboard():
    return render_template("index.html")


@app.get("/api/status")
def status():
    with lock:
        current_alerts = list(reversed(alerts))
        baseline = engine.baseline
        trusted_devices = [
            {"ip": ip, "mac": mac}
            for ip, mac in sorted(baseline.mappings.items())
        ]
        severity_counts = {}
        for event in alerts:
            sev = event.get("severity", "unknown")
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        return jsonify({
            "running": state["running"],
            "starting": state["starting"],
            "error": state["error"] or configuration_error,
            "configuration_error": configuration_error,
            "interface": config.interface or "Not configured",
            "learning": baseline.is_learning(),
            "learning_window_seconds": baseline.learning_window_seconds,
            "trusted_devices": trusted_devices,
            "trusted_device_count": len(trusted_devices),
            "alert_count": len(alerts),
            "high_count": severity_counts.get("high", 0),
            "medium_count": severity_counts.get("medium", 0),
            "severity_counts": severity_counts,
            "alerts": current_alerts,
        })


@app.get("/api/baseline")
def baseline_api():
    """Read-only access to current trusted IP-to-MAC mappings."""
    baseline = engine.baseline
    mappings = baseline.mappings
    devices = [
        {"ip": ip, "mac": mac}
        for ip, mac in sorted(mappings.items())
    ]
    return jsonify({
        "learning": baseline.is_learning(),
        "learning_window_seconds": baseline.learning_window_seconds,
        "device_count": len(devices),
        "devices": devices,
    })


@app.post("/api/start")
def start_detector():
    """Start live passive ARP capture once."""
    if configuration_error:
        return jsonify({
            "error": "Detector configuration is invalid",
            "details": configuration_error,
        }), 503

    with lock:
        if state["running"] or state["starting"]:
            return jsonify({
                "message": "Detector startup is already in progress"
            }), 200

        if state["started"]:
            return jsonify({
                "error": "Capture has already stopped. Restart the backend to retry.",
                "details": state["error"],
            }), 409

        state["starting"] = True
        state["started"] = True
        state["error"] = None

    try:
        sniffer = Sniffer(engine)
        sniffer.validate_interface()
    except RuntimeError as exc:
        with lock:
            state["starting"] = False
            state["started"] = False
            state["error"] = str(exc)
        return jsonify({
            "error": "Unable to start ARP capture",
            "details": str(exc),
        }), 400

    thread = threading.Thread(
        target=capture_packets,
        args=(sniffer,),
        name="arp-guard-capture",
        daemon=True,
    )
    thread.start()

    return jsonify({
        "message": "ARP capture validation passed; startup is pending",
        "interface": config.interface,
        "starting": True,
    }), 202


@app.get("/api/logs")
def recent_logs():
    """Read actual detector JSONL events."""
    path = ROOT / config.log_file
    entries = []

    try:
        if path.exists():
            lines = path.read_text(encoding="utf-8").splitlines()[-100:]
            for line in lines:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    app.logger.warning("Skipping malformed detector event log entry")
                    continue
    except OSError:
        app.logger.exception("Unable to read detector log")

    return jsonify(list(reversed(entries)))


@app.post("/api/test-alert")
def test_alert():
    """
    Exercise the actual detection engine with in-memory ARP packets.
    No packets are transmitted onto the network.
    """
    try:
        test_config = load_config(ROOT / "config" / "settings.yaml")
    except ValueError as exc:
        return jsonify({
            "error": "Detector configuration is invalid",
            "details": str(exc),
        }), 503

    # Keep the test isolated from the live engine's baseline and cooldowns.
    test_engine = DetectionEngine(test_config, simulated=True)
    generated = []

    # Demo events follow the same persistence and dashboard callback path as real
    # detections, but receive_alert intentionally skips desktop notification.
    test_engine.on_alert(receive_alert)
    test_engine.on_alert(lambda event: generated.append(dict(event)))

    test_ip = "192.0.2.10"
    original_mac = "02:00:00:00:00:10"
    changed_mac = "02:00:00:00:00:20"

    def packet(mac):
        return SimpleNamespace(
            arp=SimpleNamespace(
                op=2,
                psrc=test_ip,
                hwsrc=mac,
                pdst="192.0.2.1",
            )
        )

    # First packet establishes the trusted IP-to-MAC mapping.
    test_engine.process_packet(packet(original_mac))
    test_engine.process_packet(packet(original_mac))

    # Second packet claims the same IP with a different MAC.
    test_engine.process_packet(packet(changed_mac))

    if not generated:
        return jsonify({
            "error": (
                "The detection engine did not emit an alert. "
                "Check the baseline configuration and detection rules."
            )
        }), 500

    return jsonify({
        "message": "Detection engine demo completed",
        "simulated": True,
        "alerts": generated,
    }), 201


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=False,
        threaded=True,
    )
