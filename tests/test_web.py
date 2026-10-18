"""Tests for the web dashboard routes and real-data integration."""

import json
from pathlib import Path
from types import SimpleNamespace

from scapy.all import ARP
import web.app as dashboard
from detector.baseline import Baseline
from detector.config import DetectorConfig
from detector.detect import DetectionEngine


# ──────────────────────────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────────────────────────

def _reset_dashboard(monkeypatch, baseline=None, running=False, error=None):
    """Reset dashboard state for a clean test."""
    if baseline is None:
        baseline = Baseline()
    monkeypatch.setattr(dashboard.engine, "baseline", baseline)
    dashboard.alerts.clear()
    dashboard.state.update(running=running, starting=False, error=error, started=False)


def _client():
    return dashboard.app.test_client()


def _packet(ip="192.168.1.1", mac="AA-BB-CC-DD-EE-01", op=2, target=None):
    return SimpleNamespace(
        arp=SimpleNamespace(psrc=ip, hwsrc=mac, op=op, pdst=target)
    )


# ──────────────────────────────────────────────────────────────────
# /api/status — empty baseline
# ──────────────────────────────────────────────────────────────────

def test_status_exposes_empty_baseline_and_real_runtime_state(monkeypatch):
    _reset_dashboard(monkeypatch)

    response = _client().get("/api/status")

    assert response.status_code == 200
    body = response.get_json()
    assert body["trusted_devices"] == []
    assert body["trusted_device_count"] == 0
    assert body["running"] is False
    assert body["interface"] == dashboard.config.interface
    assert body["alert_count"] == 0
    assert body["alerts"] == []
    assert body["high_count"] == 0
    assert body["medium_count"] == 0


# ──────────────────────────────────────────────────────────────────
# /api/status — with baseline mappings
# ──────────────────────────────────────────────────────────────────

def test_status_exposes_actual_baseline_mapping(monkeypatch):
    baseline = Baseline()
    _reset_dashboard(monkeypatch, baseline=baseline)
    dashboard.engine.baseline.add_mapping(
        "192.0.2.10", "AA-BB-CC-DD-EE-FF"
    )

    response = _client().get("/api/status")

    assert response.status_code == 200
    body = response.get_json()
    assert body["trusted_devices"] == [{
        "ip": "192.0.2.10",
        "mac": "aa:bb:cc:dd:ee:ff",
    }]
    assert body["trusted_device_count"] == 1


def test_status_exposes_multiple_baseline_mappings_sorted(monkeypatch):
    baseline = Baseline()
    baseline.add_mapping("192.168.1.20", "11:22:33:44:55:66")
    baseline.add_mapping("192.168.1.10", "aa:bb:cc:dd:ee:ff")
    _reset_dashboard(monkeypatch, baseline=baseline)

    body = _client().get("/api/status").get_json()

    ips = [d["ip"] for d in body["trusted_devices"]]
    assert ips == ["192.168.1.10", "192.168.1.20"]
    assert body["trusted_device_count"] == 2


# ──────────────────────────────────────────────────────────────────
# /api/status — learning state
# ──────────────────────────────────────────────────────────────────

def test_status_reflects_learning_state(monkeypatch):
    # Baseline with a long learning window → should be learning
    baseline = Baseline(learning_window_seconds=9999.0, clock=lambda: 0)
    _reset_dashboard(monkeypatch, baseline=baseline)

    body = _client().get("/api/status").get_json()
    assert body["learning"] is True
    assert body["learning_window_seconds"] == 9999.0


def test_status_reflects_learning_complete(monkeypatch):
    baseline = Baseline(learning_window_seconds=0.0)
    _reset_dashboard(monkeypatch, baseline=baseline)

    body = _client().get("/api/status").get_json()
    assert body["learning"] is False


# ──────────────────────────────────────────────────────────────────
# /api/status — severity counts
# ──────────────────────────────────────────────────────────────────

def test_status_counts_severity_from_real_alerts(monkeypatch):
    _reset_dashboard(monkeypatch)
    dashboard.alerts.append({"severity": "high", "reason": "test"})
    dashboard.alerts.append({"severity": "high", "reason": "test2"})
    dashboard.alerts.append({"severity": "medium", "reason": "test3"})

    body = _client().get("/api/status").get_json()
    assert body["high_count"] == 2
    assert body["medium_count"] == 1
    assert body["alert_count"] == 3
    assert body["severity_counts"] == {"high": 2, "medium": 1}


def test_dashboard_retains_event_when_notification_fails(monkeypatch, caplog):
    _reset_dashboard(monkeypatch)
    event = {
        "timestamp": "2026-01-01T00:00:00+00:00",
        "suspicious_ip": "192.0.2.1",
        "old_mac": "00:00:00:00:00:01",
        "new_mac": "00:00:00:00:00:02",
        "reason": "test event",
        "severity": "high",
        "simulated": False,
    }

    def failing_notifier(*args, **kwargs):
        raise RuntimeError("notifier unavailable")

    monkeypatch.setattr(dashboard, "trigger_alert", failing_notifier)
    with caplog.at_level("ERROR", logger=dashboard.app.logger.name):
        dashboard.receive_alert(event)

    assert _client().get("/api/status").get_json()["alerts"] == [event]
    assert "Notification handler failed" in caplog.text


# ──────────────────────────────────────────────────────────────────
# /api/status — error state
# ──────────────────────────────────────────────────────────────────

def test_status_exposes_error_state(monkeypatch):
    _reset_dashboard(monkeypatch, error="Permission denied")

    body = _client().get("/api/status").get_json()
    assert body["error"] == "Permission denied"
    assert body["running"] is False


# ──────────────────────────────────────────────────────────────────
# /api/status — running state
# ──────────────────────────────────────────────────────────────────

def test_status_exposes_running_state(monkeypatch):
    _reset_dashboard(monkeypatch, running=True)

    body = _client().get("/api/status").get_json()
    assert body["running"] is True


def test_start_rejects_invalid_interface_before_creating_thread(monkeypatch):
    _reset_dashboard(monkeypatch)

    class InvalidSniffer:
        def __init__(self, engine):
            self.engine = engine

        def validate_interface(self):
            raise RuntimeError("Invalid network interface 'missing0'")

    monkeypatch.setattr(dashboard, "Sniffer", InvalidSniffer)

    response = _client().post("/api/start")

    assert response.status_code == 400
    assert response.get_json()["details"] == "Invalid network interface 'missing0'"
    status = _client().get("/api/status").get_json()
    assert status["running"] is False
    assert status["starting"] is False
    assert status["error"] == "Invalid network interface 'missing0'"


def test_start_reports_pending_until_capture_is_ready(monkeypatch):
    _reset_dashboard(monkeypatch)

    class PreparedSniffer:
        def __init__(self, engine):
            self.engine = engine

        def validate_interface(self):
            return None

    class DeferredThread:
        def __init__(self, *, target, args, **kwargs):
            self.target = target
            self.args = args

        def start(self):
            return None

    monkeypatch.setattr(dashboard, "Sniffer", PreparedSniffer)
    monkeypatch.setattr(dashboard.threading, "Thread", DeferredThread)

    response = _client().post("/api/start")

    assert response.status_code == 202
    assert response.get_json()["starting"] is True
    status = _client().get("/api/status").get_json()
    assert status["running"] is False
    assert status["starting"] is True
    html = _client().get("/").get_data(as_text=True)
    assert "Starting capture" in html
    assert "} else if (data.starting) {\n        dot.className = 'dot dot-active';" in html


def test_startup_failure_is_exposed_by_status(monkeypatch):
    _reset_dashboard(monkeypatch)

    class FailingSniffer:
        def __init__(self, engine):
            self.engine = engine

        def validate_interface(self):
            return None

        def start(self, **kwargs):
            raise RuntimeError("ARP capture requires administrator/root privileges")

    class ImmediateThread:
        def __init__(self, *, target, args, **kwargs):
            self.target = target
            self.args = args

        def start(self):
            self.target(*self.args)

    monkeypatch.setattr(dashboard, "Sniffer", FailingSniffer)
    monkeypatch.setattr(dashboard.threading, "Thread", ImmediateThread)

    response = _client().post("/api/start")

    assert response.status_code == 202
    status = _client().get("/api/status").get_json()
    assert status["running"] is False
    assert status["starting"] is False
    assert status["error"] == "ARP capture requires administrator/root privileges"


def test_start_rejects_invalid_configuration(monkeypatch):
    _reset_dashboard(monkeypatch)
    monkeypatch.setattr(dashboard, "configuration_error", "'interface' must be a non-empty network interface name")

    response = _client().post("/api/start")

    assert response.status_code == 503
    assert response.get_json()["details"] == "'interface' must be a non-empty network interface name"


# ──────────────────────────────────────────────────────────────────
# /api/baseline — dedicated endpoint
# ──────────────────────────────────────────────────────────────────

def test_baseline_api_returns_empty_when_no_mappings(monkeypatch):
    _reset_dashboard(monkeypatch)

    response = _client().get("/api/baseline")

    assert response.status_code == 200
    body = response.get_json()
    assert body["devices"] == []
    assert body["device_count"] == 0
    assert "learning" in body
    assert "learning_window_seconds" in body


def test_baseline_api_returns_actual_mappings(monkeypatch):
    baseline = Baseline()
    baseline.add_mapping("10.0.0.1", "00:11:22:33:44:55")
    baseline.add_mapping("10.0.0.2", "aa:bb:cc:dd:ee:ff")
    _reset_dashboard(monkeypatch, baseline=baseline)

    response = _client().get("/api/baseline")

    assert response.status_code == 200
    body = response.get_json()
    assert body["device_count"] == 2
    assert body["devices"] == [
        {"ip": "10.0.0.1", "mac": "00:11:22:33:44:55"},
        {"ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:ff"},
    ]


def test_baseline_api_reflects_learning_flag(monkeypatch):
    baseline = Baseline(learning_window_seconds=9999.0, clock=lambda: 0)
    _reset_dashboard(monkeypatch, baseline=baseline)

    body = _client().get("/api/baseline").get_json()
    assert body["learning"] is True


def test_baseline_api_is_read_only(monkeypatch):
    """The /api/baseline endpoint rejects POST, PUT, DELETE."""
    _reset_dashboard(monkeypatch)
    client = _client()

    assert client.post("/api/baseline").status_code == 405
    assert client.put("/api/baseline").status_code == 405
    assert client.delete("/api/baseline").status_code == 405


# ──────────────────────────────────────────────────────────────────
# /api/baseline — data flows from detector engine
# ──────────────────────────────────────────────────────────────────

def test_baseline_reflects_packets_processed_by_engine(monkeypatch):
    """Mappings learned through process_packet appear in the API."""
    config = DetectorConfig(
        learning_window_seconds=60,
        learning_confirmations=2,
        log_file="logs/test_alerts.jsonl",
    )
    test_engine = DetectionEngine(config, clock=lambda: 0)
    monkeypatch.setattr(dashboard, "engine", test_engine)
    dashboard.alerts.clear()

    # Feed two identical ARP replies → baseline learns the mapping
    test_engine.process_packet(_packet("10.0.0.5", "de:ad:be:ef:00:01"), now=1)
    test_engine.process_packet(_packet("10.0.0.5", "de:ad:be:ef:00:01"), now=2)

    body = _client().get("/api/baseline").get_json()
    assert body["device_count"] == 1
    assert body["devices"][0]["ip"] == "10.0.0.5"
    assert body["devices"][0]["mac"] == "de:ad:be:ef:00:01"

    # Also visible through /api/status
    status = _client().get("/api/status").get_json()
    assert status["trusted_device_count"] == 1
    assert status["trusted_devices"][0]["ip"] == "10.0.0.5"


# ──────────────────────────────────────────────────────────────────
# Dashboard HTML rendering
# ──────────────────────────────────────────────────────────────────

def test_dashboard_renders_baseline_and_empty_state():
    response = _client().get("/")

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Trusted Devices" in html
    assert 'id="device-table"' in html
    assert "Connecting to detector" in html


def test_dashboard_includes_status_elements():
    html = _client().get("/").get_data(as_text=True)

    assert 'id="detector-status"' in html
    assert 'id="alert-count"' in html
    assert 'id="high-count"' in html
    assert 'id="interface"' in html
    assert 'id="banner"' in html
    assert 'id="status-dot"' in html


def test_dashboard_includes_alert_table():
    html = _client().get("/").get_data(as_text=True)

    assert 'id="alert-table"' in html
    assert "SEVERITY" in html
    assert "EVENT" in html


def test_dashboard_includes_event_log_section():
    html = _client().get("/").get_data(as_text=True)

    assert 'id="event-list"' in html
    assert "Recent Events" in html


def test_dashboard_js_polls_api_status():
    """The JS code calls /api/status for live updates."""
    html = _client().get("/").get_data(as_text=True)
    assert "fetch('/api/status')" in html
    assert "refreshDashboard" in html


def test_dashboard_js_handles_simulated_alerts():
    """The JS marks demo events with SIMULATED label."""
    html = _client().get("/").get_data(as_text=True)
    assert "SIMULATED" in html
    assert "alert.simulated" in html


# ──────────────────────────────────────────────────────────────────
# /api/test-alert — safe demo behavior
# ──────────────────────────────────────────────────────────────────

def test_safe_demo_is_simulated_persisted_once_and_updates_dashboard(monkeypatch, tmp_path):
    test_config = DetectorConfig(
        learning_window_seconds=60,
        learning_confirmations=2,
        burst_threshold=99,
        log_file=str(tmp_path / "demo-events.jsonl"),
    )
    monkeypatch.setattr(dashboard, "config", test_config)
    monkeypatch.setattr(dashboard, "load_config", lambda path: test_config)
    notify = []
    monkeypatch.setattr(dashboard, "trigger_alert", lambda *args, **kwargs: notify.append((args, kwargs)))
    dashboard.alerts.clear()

    response = _client().post("/api/test-alert")

    assert response.status_code == 201
    body = response.get_json()
    assert body["simulated"] is True
    assert len(body["alerts"]) == 1
    assert all(event["simulated"] is True for event in body["alerts"])
    assert notify == []

    status = _client().get("/api/status").get_json()
    assert status["alerts"] == body["alerts"]

    persisted = [json.loads(line) for line in Path(test_config.log_file).read_text().splitlines()]
    assert persisted == body["alerts"]
    assert _client().get("/api/logs").get_json() == body["alerts"]


def test_demo_alert_does_not_modify_live_baseline(monkeypatch, tmp_path):
    """The test-alert endpoint uses an isolated engine, not the live baseline."""
    baseline = Baseline()
    _reset_dashboard(monkeypatch, baseline=baseline)
    test_config = DetectorConfig(log_file=str(tmp_path / "demo-events.jsonl"))
    monkeypatch.setattr(dashboard, "load_config", lambda path: test_config)

    _client().post("/api/test-alert")

    # The live engine's baseline should be empty — the demo used its own engine
    body = _client().get("/api/baseline").get_json()
    assert body["device_count"] == 0


def test_demo_alert_appears_in_status_alerts(monkeypatch, tmp_path):
    _reset_dashboard(monkeypatch)
    test_config = DetectorConfig(log_file=str(tmp_path / "demo-events.jsonl"))
    monkeypatch.setattr(dashboard, "load_config", lambda path: test_config)

    _client().post("/api/test-alert")

    status = _client().get("/api/status").get_json()
    assert status["alert_count"] > 0
    assert any(a.get("simulated") for a in status["alerts"])


# ──────────────────────────────────────────────────────────────────
# /api/status — alerts are newest-first
# ──────────────────────────────────────────────────────────────────

def test_status_alerts_are_newest_first(monkeypatch):
    _reset_dashboard(monkeypatch)
    dashboard.alerts.append({"reason": "first", "severity": "medium"})
    dashboard.alerts.append({"reason": "second", "severity": "high"})

    body = _client().get("/api/status").get_json()
    assert body["alerts"][0]["reason"] == "second"
    assert body["alerts"][1]["reason"] == "first"


# ──────────────────────────────────────────────────────────────────
# Integration: end-to-end packet → baseline → dashboard
# ──────────────────────────────────────────────────────────────────

def test_real_event_is_persisted_notified_once_and_updates_dashboard(monkeypatch, tmp_path):
    """Verify the full flow: packet -> JSONL -> callback -> notifier/dashboard."""
    config = DetectorConfig(
        learning_window_seconds=60,
        learning_confirmations=2,
        alert_cooldown_seconds=0,
        log_file=str(tmp_path / "events.jsonl"),
    )
    test_engine = DetectionEngine(config, clock=lambda: 0)

    monkeypatch.setattr(dashboard, "engine", test_engine)
    monkeypatch.setattr(dashboard, "config", config)
    notifications = []
    monkeypatch.setattr(
        dashboard,
        "trigger_alert",
        lambda *args, **kwargs: notifications.append((args, kwargs)),
    )
    dashboard.alerts.clear()
    dashboard.state.update(running=True, error=None, started=True)
    test_engine.on_alert(dashboard.receive_alert)

    client = _client()

    # Step 1: Learn baseline
    test_engine.process_packet(_packet("10.0.0.1", "aa:bb:cc:00:00:01"), now=1)
    test_engine.process_packet(_packet("10.0.0.1", "aa:bb:cc:00:00:01"), now=2)

    status = client.get("/api/status").get_json()
    assert status["trusted_device_count"] == 1
    assert status["trusted_devices"][0]["ip"] == "10.0.0.1"
    assert status["running"] is True

    # Step 2: Spoof → alert generated
    events = test_engine.process_packet(
        _packet("10.0.0.1", "de:ad:be:ef:00:01"), now=3
    )
    assert len(events) == 1
    assert events[0]["severity"] == "high"
    assert events[0]["simulated"] is False

    # One emitted event has one callback notification, one dashboard entry, and one log line.
    assert len(notifications) == 1
    status = client.get("/api/status").get_json()
    assert status["alerts"] == events
    persisted = [json.loads(line) for line in Path(config.log_file).read_text().splitlines()]
    assert persisted == events
    assert client.get("/api/logs").get_json() == events


def test_scapy_arp_packet_flow_learns_detects_and_updates_dashboard(monkeypatch, tmp_path):
    """Use real in-memory Scapy ARP objects without sniffing or transmitting."""
    config = DetectorConfig(
        learning_window_seconds=60,
        learning_confirmations=2,
        burst_threshold=99,
        alert_cooldown_seconds=0,
        log_file=str(tmp_path / "scapy-events.jsonl"),
    )
    test_engine = DetectionEngine(config, clock=lambda: 0)
    monkeypatch.setattr(dashboard, "engine", test_engine)
    monkeypatch.setattr(dashboard, "config", config)
    notifications = []
    callback_events = []
    monkeypatch.setattr(
        dashboard,
        "trigger_alert",
        lambda *args, **kwargs: notifications.append((args, kwargs)),
    )
    dashboard.alerts.clear()
    dashboard.state.update(running=True, starting=False, error=None, started=True)

    def dashboard_callback(event):
        callback_events.append(dict(event))
        dashboard.receive_alert(event)

    test_engine.on_alert(dashboard_callback)

    def arp_reply(mac):
        return ARP(
            op=2,
            psrc="198.51.100.10",
            hwsrc=mac,
            pdst="198.51.100.1",
        )

    test_engine.process_packet(arp_reply("02:00:00:00:00:10"), now=1)
    test_engine.process_packet(arp_reply("02:00:00:00:00:10"), now=2)
    assert test_engine.baseline.mappings == {"198.51.100.10": "02:00:00:00:00:10"}

    events = test_engine.process_packet(arp_reply("02:00:00:00:00:20"), now=3)

    assert len(events) == 1
    assert events[0]["old_mac"] == "02:00:00:00:00:10"
    assert events[0]["new_mac"] == "02:00:00:00:00:20"
    assert events[0]["simulated"] is False
    assert callback_events == events
    assert len(notifications) == 1

    client = _client()
    assert client.get("/api/status").get_json()["alerts"] == events
    persisted = [json.loads(line) for line in Path(config.log_file).read_text().splitlines()]
    assert persisted == events
    assert client.get("/api/logs").get_json() == events
