"""Trusted IP to MAC baseline management."""

from time import monotonic


def normalize_mac(mac: str | None) -> str | None:
    """Return a comparable lowercase, colon-separated MAC address."""
    if mac is None:
        return None
    value = mac.strip().lower().replace("-", ":")
    return value or None


class Baseline:
    """Passively learns trusted mappings during an initial time-limited window."""

    def __init__(
        self,
        learning_window_seconds: float = 60.0,
        learning_confirmations: int = 2,
        whitelisted_ips: set[str] | None = None,
        whitelisted_macs: set[str] | None = None,
        clock=monotonic,
    ) -> None:
        self.learning_window_seconds = max(0.0, learning_window_seconds)
        self.learning_confirmations = max(1, learning_confirmations)
        self.whitelisted_ips = set(whitelisted_ips or set())
        self.whitelisted_macs = {
            normalized
            for mac in (whitelisted_macs or set())
            if (normalized := normalize_mac(mac))
        }
        self._mappings: dict[str, str] = {}
        self._candidates: dict[str, tuple[str, int]] = {}
        self._started_at = clock()
        self._clock = clock

    @property
    def mappings(self) -> dict[str, str]:
        return dict(self._mappings)

    def is_learning(self, now: float | None = None) -> bool:
        current = self._clock() if now is None else now
        return current - self._started_at < self.learning_window_seconds

    def get_trusted_mac(self, ip: str) -> str | None:
        return self._mappings.get(ip)

    def add_mapping(self, ip: str, mac: str) -> bool:
        """Add an absent mapping; never overwrite an existing trusted value."""
        normalized = normalize_mac(mac)
        if not ip or not normalized or ip in self.whitelisted_ips or normalized in self.whitelisted_macs:
            return False
        if ip in self._mappings:
            return False
        self._mappings[ip] = normalized
        self._candidates.pop(ip, None)
        return True

    def update_mapping(self, ip: str, mac: str) -> None:
        """Explicitly replace a trusted mapping after external verification."""
        normalized = normalize_mac(mac)
        if not ip or not normalized:
            raise ValueError("IP and MAC are required")
        self._mappings[ip] = normalized
        self._candidates.pop(ip, None)

    def observe(self, ip: str, mac: str, now: float | None = None) -> bool:
        """Learn only during the initial window, or when no mapping exists then."""
        if self.is_learning(now) and self.get_trusted_mac(ip) is None:
            normalized = normalize_mac(mac)
            if not normalized or ip in self.whitelisted_ips or normalized in self.whitelisted_macs:
                return False
            candidate_mac, count = self._candidates.get(ip, (normalized, 0))
            count = count + 1 if candidate_mac == normalized else 1
            self._candidates[ip] = (normalized, count)
            if count >= self.learning_confirmations:
                return self.add_mapping(ip, normalized)
        return False
