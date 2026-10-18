"""Safety tests for the controlled ARP simulation utility."""

import math
from unittest.mock import Mock

import pytest

from attack_sim import spoof_test


SIMULATION_ARGS = {
    "target_ip": "192.0.2.20",
    "target_mac": "02:00:00:00:00:20",
    "spoof_ip": "192.0.2.1",
    "spoof_mac": "02:00:00:00:00:01",
}


def test_simulator_defaults_to_dry_run_and_sends_no_packets():
    send_packet = Mock()

    sent = spoof_test.spoof_arp(**SIMULATION_ARGS, send_func=send_packet)

    assert sent == 0
    send_packet.assert_not_called()


def test_simulator_blocks_transmission_without_isolated_lab_confirmation():
    send_packet = Mock()

    with pytest.raises(spoof_test.SimulationSafetyError, match="confirm-isolated-lab"):
        spoof_test.spoof_arp(
            **SIMULATION_ARGS,
            interface="lab0",
            transmit=True,
            send_func=send_packet,
        )

    send_packet.assert_not_called()


def test_simulator_blocks_unavailable_lab_interface(monkeypatch):
    send_packet = Mock()
    monkeypatch.setattr(spoof_test, "get_if_list", lambda: ["other-lab"])

    with pytest.raises(spoof_test.SimulationSafetyError, match="not available"):
        spoof_test.spoof_arp(
            **SIMULATION_ARGS,
            interface="lab0",
            transmit=True,
            confirm_isolated_lab=True,
            send_func=send_packet,
        )

    send_packet.assert_not_called()


def test_simulator_respects_configured_packet_limit(monkeypatch):
    send_packet = Mock()
    monkeypatch.setattr(spoof_test, "get_if_list", lambda: ["lab0"])

    sent = spoof_test.spoof_arp(
        **SIMULATION_ARGS,
        interface="lab0",
        transmit=True,
        confirm_isolated_lab=True,
        packet_count=3,
        duration_seconds=30,
        interval_seconds=0,
        send_func=send_packet,
        clock=lambda: 0,
    )

    assert sent == 3
    assert send_packet.call_count == 3


def test_simulator_respects_configured_duration_limit(monkeypatch):
    send_packet = Mock()
    monkeypatch.setattr(spoof_test, "get_if_list", lambda: ["lab0"])
    clock_values = iter([0, 0, 1.1])

    sent = spoof_test.spoof_arp(
        **SIMULATION_ARGS,
        interface="lab0",
        transmit=True,
        confirm_isolated_lab=True,
        packet_count=10,
        duration_seconds=1,
        interval_seconds=0,
        send_func=send_packet,
        clock=lambda: next(clock_values),
    )

    assert sent == 1
    send_packet.assert_called_once()


def test_simulator_rejects_unbounded_or_invalid_limits():
    with pytest.raises(spoof_test.SimulationSafetyError, match="packet_count"):
        spoof_test.spoof_arp(**SIMULATION_ARGS, packet_count=spoof_test.MAX_PACKETS + 1)
    with pytest.raises(spoof_test.SimulationSafetyError, match="duration_seconds"):
        spoof_test.spoof_arp(**SIMULATION_ARGS, duration_seconds=0)
    with pytest.raises(spoof_test.SimulationSafetyError, match="interval_seconds"):
        spoof_test.spoof_arp(**SIMULATION_ARGS, interval_seconds=math.nan)
