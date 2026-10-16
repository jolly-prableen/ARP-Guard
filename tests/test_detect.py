import sys
from types import ModuleType, SimpleNamespace

import pytest

from detector.baseline import Baseline
from detector.config import DetectorConfig, load_config
from detector.detect import DetectionEngine
from detector.sniffer import Sniffer


def packet(ip="192.168.1.1", mac="AA-BB-CC-DD-EE-01", op=2, target=None):
    return SimpleNamespace(arp=SimpleNamespace(psrc=ip, hwsrc=mac, op=op, pdst=target))


def config(tmp_path, **kwargs):
    values = dict(
        learning_window_seconds=60,
        learning_confirmations=2,
        burst_threshold=99,
        burst_window_seconds=10,
        alert_cooldown_seconds=30,
        log_file=str(tmp_path / "alerts.jsonl"),
    )
    values.update(kwargs)
    return DetectorConfig(**values)


def test_first_time_mapping_is_learned(tmp_path):
    engine = DetectionEngine(config(tmp_path))
    assert engine.process_packet(packet()) == []
    assert engine.baseline.get_trusted_mac("192.168.1.1") is None
    assert engine.process_packet(packet()) == []
    assert engine.baseline.get_trusted_mac("192.168.1.1") == "aa:bb:cc:dd:ee:01"


def test_trusted_ip_change_emits_event(tmp_path):
    engine = DetectionEngine(config(tmp_path))
    engine.process_packet(packet())
    engine.process_packet(packet())
    events = engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"))
    assert events[0]["old_mac"] == "aa:bb:cc:dd:ee:01"
    assert events[0]["new_mac"] == "aa:bb:cc:dd:ee:02"
    assert events[0]["severity"] == "high"


def test_whitelisted_devices_are_ignored(tmp_path):
    engine = DetectionEngine(config(tmp_path, whitelisted_ips={"192.168.1.1"}))
    assert engine.process_packet(packet()) == []
    assert engine.baseline.mappings == {}


def test_one_mac_claiming_multiple_ips_is_detected(tmp_path):
    engine = DetectionEngine(config(tmp_path))
    engine.process_packet(packet(ip="192.168.1.1"))
    events = engine.process_packet(packet(ip="192.168.1.2"))
    assert any("multiple IP" in event["reason"] for event in events)


def test_whitelist_does_not_disable_other_detection(tmp_path):
    engine = DetectionEngine(config(tmp_path, whitelisted_ips={"192.168.1.9"}))
    engine.process_packet(packet(ip="192.168.1.1"))
    engine.process_packet(packet(ip="192.168.1.1"))
    events = engine.process_packet(packet(ip="192.168.1.1", mac="00:11:22:33:44:55"))
    assert any(event["severity"] == "high" for event in events)
    assert engine.process_packet(packet(ip="192.168.1.9", mac="00:11:22:33:44:55")) == []


def test_reply_burst_is_detected(tmp_path):
    engine = DetectionEngine(config(tmp_path, burst_threshold=3, alert_cooldown_seconds=0))
    engine.process_packet(packet(ip="192.168.1.1"), now=1)
    engine.process_packet(packet(ip="192.168.1.2"), now=2)
    events = engine.process_packet(packet(ip="192.168.1.3"), now=3)
    assert any("Burst" in event["reason"] for event in events)


def test_reply_burst_expires_outside_time_window(tmp_path):
    engine = DetectionEngine(config(tmp_path, burst_threshold=2, burst_window_seconds=5))
    engine.process_packet(packet(ip="192.168.1.1"), now=1)
    events = engine.process_packet(packet(ip="192.168.1.2"), now=7)
    assert not any("Burst" in event["reason"] for event in events)


def test_solicited_replies_do_not_count_as_unsolicited_burst(tmp_path):
    engine = DetectionEngine(config(tmp_path, burst_threshold=2))
    engine.process_packet(packet(ip="192.168.1.50", op=1, target="192.168.1.1"), now=1)
    engine.process_packet(packet(ip="192.168.1.1", mac="00:00:00:00:00:01"), now=2)
    engine.process_packet(packet(ip="192.168.1.50", op=1, target="192.168.1.1"), now=3)
    events = engine.process_packet(packet(ip="192.168.1.1", mac="00:00:00:00:00:01"), now=4)
    assert not any("Burst" in event["reason"] for event in events)


def test_learning_does_not_trust_one_unstable_observation(tmp_path):
    engine = DetectionEngine(config(tmp_path))
    engine.process_packet(packet(mac="00:00:00:00:00:01"), now=1)
    engine.process_packet(packet(mac="00:00:00:00:00:02"), now=2)
    assert engine.baseline.get_trusted_mac("192.168.1.1") is None


def test_learning_window_does_not_admit_new_mapping_after_expiry(tmp_path):
    engine = DetectionEngine(config(tmp_path, learning_window_seconds=5), clock=lambda: 0)
    engine.process_packet(packet(), now=1)
    engine.process_packet(packet(), now=2)
    assert engine.baseline.get_trusted_mac("192.168.1.1") == "aa:bb:cc:dd:ee:01"
    engine.process_packet(packet(ip="192.168.1.2"), now=7)
    engine.process_packet(packet(ip="192.168.1.2"), now=8)
    assert engine.baseline.get_trusted_mac("192.168.1.2") is None


def test_duplicate_alerts_are_suppressed(tmp_path):
    engine = DetectionEngine(config(tmp_path))
    engine.process_packet(packet())
    engine.process_packet(packet())
    first = engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"), now=1)
    second = engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"), now=2)
    assert len(first) == 1
    assert second == []


def test_recurring_alert_returns_after_cooldown(tmp_path):
    engine = DetectionEngine(config(tmp_path, alert_cooldown_seconds=5))
    engine.process_packet(packet())
    engine.process_packet(packet())
    first = engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"), now=1)
    suppressed = engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"), now=2)
    recurring = engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"), now=7)
    assert len(first) == 1
    assert suppressed == []
    assert len(recurring) == 1


def test_alert_callback_receives_alert_and_can_be_unregistered(tmp_path):
    engine = DetectionEngine(config(tmp_path))
    received = []
    remove = engine.on_alert(received.append)

    engine.process_packet(packet())
    engine.process_packet(packet())
    engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"))
    assert len(received) == 1

    remove()
    engine.process_packet(packet(mac="aa:bb:cc:dd:ee:03"))
    assert len(received) == 1


def test_callback_failure_does_not_block_other_callbacks(tmp_path):
    engine = DetectionEngine(config(tmp_path))
    received = []

    def failing_callback(event):
        raise RuntimeError("callback failed")

    engine.on_alert(failing_callback)
    engine.on_alert(received.append)
    engine.process_packet(packet())
    engine.process_packet(packet())

    events = engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"))
    assert len(events) == 1
    assert received == events


def test_malformed_and_requests_are_ignored(tmp_path):
    engine = DetectionEngine(config(tmp_path))
    assert engine.process_packet(SimpleNamespace()) == []
    assert engine.process_packet(packet(op=1)) == []
    assert engine.process_packet(SimpleNamespace(arp=SimpleNamespace(op=2, psrc="", hwsrc=None))) == []


def test_log_contains_structured_event_fields(tmp_path):
    engine = DetectionEngine(config(tmp_path))
    engine.process_packet(packet())
    engine.process_packet(packet())
    engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"))
    line = (tmp_path / "alerts.jsonl").read_text(encoding="utf-8").splitlines()[0]
    import json

    event = json.loads(line)
    assert {"timestamp", "suspicious_ip", "old_mac", "new_mac", "reason", "severity"} <= event.keys()


def test_logging_failure_does_not_crash_detection(tmp_path):
    log_directory = tmp_path / "not-a-file"
    log_directory.mkdir()
    engine = DetectionEngine(config(tmp_path, log_file=str(log_directory)))
    engine.process_packet(packet())
    engine.process_packet(packet())
    assert engine.process_packet(packet(mac="aa:bb:cc:dd:ee:02"))


def test_sniffer_reports_capture_errors_and_stops_cleanly(tmp_path):
    engine = DetectionEngine(config(tmp_path))

    def permission_error(**kwargs):
        raise PermissionError("denied")

    try:
        Sniffer(engine, interface="test0", sniff_func=permission_error).start()
    except RuntimeError as error:
        assert "privileges" in str(error)
    else:
        raise AssertionError("permission errors must be reported")

    def interrupted(**kwargs):
        raise KeyboardInterrupt

    Sniffer(engine, interface="test0", sniff_func=interrupted).start()


def test_sniffer_forwards_packets_and_capture_options(tmp_path):
    engine = DetectionEngine(config(tmp_path, interface="test0"))
    captured = {}
    forwarded = []

    def fake_process(packet_value, now=None):
        forwarded.append(packet_value)
        return []

    engine.process_packet = fake_process

    def fake_sniff(**kwargs):
        captured.update(kwargs)
        kwargs["prn"]("captured packet")

    Sniffer(engine, sniff_func=fake_sniff).start()

    assert captured["iface"] == "test0"
    assert captured["filter"] == "arp"
    assert captured["store"] is False
    assert forwarded == ["captured packet"]


@pytest.mark.parametrize("interface", [None, ""])
def test_sniffer_requires_interface(tmp_path, interface):
    engine = DetectionEngine(config(tmp_path, interface=None))

    with pytest.raises(RuntimeError, match="No network interface configured"):
        Sniffer(engine, interface=interface).start()


def test_sniffer_rejects_invalid_interface_without_capture(tmp_path, monkeypatch):
    scapy_all = ModuleType("scapy.all")
    scapy_all.get_if_list = lambda: ["eth0"]
    scapy_all.sniff = lambda **kwargs: None
    scapy = ModuleType("scapy")
    scapy.all = scapy_all
    monkeypatch.setitem(sys.modules, "scapy", scapy)
    monkeypatch.setitem(sys.modules, "scapy.all", scapy_all)
    engine = DetectionEngine(config(tmp_path, interface="missing0"))

    with pytest.raises(RuntimeError, match="Invalid network interface 'missing0'"):
        Sniffer(engine).start()


@pytest.mark.parametrize(
    ("failure", "message"),
    [
        (OSError("device unavailable"), "Unable to capture on interface 'test0'"),
        (RuntimeError("unexpected failure"), "ARP capture failed on interface 'test0'"),
    ],
)
def test_sniffer_wraps_capture_failures(tmp_path, failure, message):
    engine = DetectionEngine(config(tmp_path))

    def failing_sniff(**kwargs):
        raise failure

    with pytest.raises(RuntimeError, match=message):
        Sniffer(engine, interface="test0", sniff_func=failing_sniff).start()


def test_yaml_configuration_loads():
    loaded = load_config("config/settings.yaml")
    assert loaded.burst_threshold >= 1
