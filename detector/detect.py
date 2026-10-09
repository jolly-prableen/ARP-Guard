"""ARP packet analysis, alert suppression, and JSONL logging."""

from collections import defaultdict, deque
from datetime import datetime, timezone
import json
from pathlib import Path
from time import monotonic
from typing import Any, Callable

from .baseline import Baseline, normalize_mac
from .config import DetectorConfig


class DetectionEngine:
    """Analyze ARP replies without modifying the host's ARP state."""

    def __init__(
        self,
        config: DetectorConfig | None = None,
        baseline: Baseline | None = None,
        clock=monotonic,
    ) -> None:
        self.config = config or DetectorConfig()
        self.baseline = baseline or Baseline(
            learning_window_seconds=self.config.learning_window_seconds,
            learning_confirmations=self.config.learning_confirmations,
            whitelisted_ips=self.config.whitelisted_ips,
            whitelisted_macs=self.config.whitelisted_macs,
            clock=clock,
        )
        self._clock = clock
        self._callbacks: list[Callable[[dict[str, Any]], None]] = []
        self._last_alerts: dict[tuple[Any, ...], float] = {}
        self._mac_to_ips: dict[str, set[str]] = defaultdict(set)
        self._reply_times: deque[tuple[float, str, str]] = deque()
        self._requests: deque[tuple[float, str]] = deque()
        self._logger = self._create_logger()

    def _create_logger(self):
        try:
            path = Path(self.config.log_file)
            path.parent.mkdir(parents=True, exist_ok=True)
            return path
        except OSError:
            return None

    def on_alert(self, callback: Callable[[dict[str, Any]], None]) -> Callable[[], None]:
        """Register an alert callback and return a function that unregisters it."""
        self._callbacks.append(callback)

        def remove() -> None:
            if callback in self._callbacks:
                self._callbacks.remove(callback)

        return remove

    def process_packet(self, packet: Any, now: float | None = None) -> list[dict[str, Any]]:
        """Process one ARP packet-like object and return newly emitted events."""
        arp = getattr(packet, "arp", packet)
        operation = getattr(arp, "op", None)
        current = self._clock() if now is None else now
        if operation == 1:
            target_ip = getattr(arp, "pdst", None)
            if isinstance(target_ip, str) and target_ip:
                self._requests.append((current, target_ip))
                self._prune_requests(current)
            return []
        if operation != 2:
            return []
        ip = getattr(arp, "psrc", None)
        mac = normalize_mac(getattr(arp, "hwsrc", None))
        if not isinstance(ip, str) or not ip or mac is None:
            return []
        if ip in self.config.whitelisted_ips or mac in self.config.whitelisted_macs:
            return []

        events: list[dict[str, Any]] = []
        trusted = self.baseline.get_trusted_mac(ip)
        if trusted is None:
            self.baseline.observe(ip, mac, current)
        elif trusted != mac:
            events.append(self._event(ip, trusted, mac, "IP is associated with a different MAC address", "high"))

        if mac not in self.config.multi_ip_mac_exceptions:
            known_ips = self._mac_to_ips[mac]
            if known_ips and ip not in known_ips:
                events.append(self._event(ip, None, mac, "One MAC address is claiming multiple IP addresses", "medium"))
            known_ips.add(ip)

        pdst = getattr(arp, "pdst", None)
        is_gratuitous = pdst == ip
        is_solicited = any(target_ip == ip for _, target_ip in self._requests)
        if is_gratuitous or not is_solicited:
            self._reply_times.append((current, ip, mac))
        cutoff = current - self.config.burst_window_seconds
        while self._reply_times and self._reply_times[0][0] < cutoff:
            self._reply_times.popleft()
        self._prune_requests(current)
        if len(self._reply_times) >= self.config.burst_threshold:
            events.append(self._event(ip, None, mac, "Burst of unsolicited or gratuitous ARP replies", "medium"))

        emitted: list[dict[str, Any]] = []
        for event in events:
            if self._emit_if_allowed(event, current):
                emitted.append(event)
        return emitted

    def _prune_requests(self, now: float) -> None:
        cutoff = now - self.config.burst_window_seconds
        while self._requests and self._requests[0][0] < cutoff:
            self._requests.popleft()

    def _event(self, ip: str, old_mac: str | None, new_mac: str, reason: str, severity: str) -> dict[str, Any]:
        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "suspicious_ip": ip,
            "old_mac": old_mac,
            "new_mac": new_mac,
            "reason": reason,
            "severity": severity,
        }

    def _emit_if_allowed(self, event: dict[str, Any], now: float) -> bool:
        key = (event["suspicious_ip"], event["old_mac"], event["new_mac"], event["reason"])
        previous = self._last_alerts.get(key)
        if previous is not None and now - previous < self.config.alert_cooldown_seconds:
            return False
        self._last_alerts[key] = now
        self._write_log(event)
        for callback in tuple(self._callbacks):
            try:
                callback(event)
            except Exception:
                continue
        return True

    def _write_log(self, event: dict[str, Any]) -> None:
        if self._logger is None:
            return
        try:
            with self._logger.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True) + "\n")
        except OSError:
            return
