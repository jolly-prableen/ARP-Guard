"""Configuration loading for the ARP detector."""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_DEFAULTS: dict[str, Any] = {
    "interface": None,
    "learning_window_seconds": 60.0,
    "learning_confirmations": 2,
    "whitelisted_ips": [],
    "whitelisted_macs": [],
    "multi_ip_mac_exceptions": [],
    "burst_threshold": 5,
    "burst_window_seconds": 10.0,
    "alert_cooldown_seconds": 30.0,
    "log_file": "logs/arp_alerts.jsonl",
    "log_level": "INFO",
}


@dataclass(frozen=True)
class DetectorConfig:
    interface: str | None = None
    learning_window_seconds: float = 60.0
    learning_confirmations: int = 2
    whitelisted_ips: set[str] = field(default_factory=set)
    whitelisted_macs: set[str] = field(default_factory=set)
    multi_ip_mac_exceptions: set[str] = field(default_factory=set)
    burst_threshold: int = 5
    burst_window_seconds: float = 10.0
    alert_cooldown_seconds: float = 30.0
    log_file: str = "logs/arp_alerts.jsonl"
    log_level: str = "INFO"


def _normalize_mac(mac: str) -> str:
    return mac.strip().lower().replace("-", ":")


def load_config(path: str | Path = "config/settings.yaml") -> DetectorConfig:
    """Load YAML configuration, falling back to safe defaults for missing values."""
    values = dict(_DEFAULTS)
    config_path = Path(path)
    if config_path.exists():
        try:
            import yaml

            loaded = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise ValueError("configuration root must be a mapping")
            values.update(loaded)
        except (OSError, ValueError, ImportError) as exc:
            raise ValueError(f"Unable to load configuration from {config_path}: {exc}") from exc

    return DetectorConfig(
        interface=values["interface"],
        learning_window_seconds=float(values["learning_window_seconds"]),
        learning_confirmations=max(1, int(values["learning_confirmations"])),
        whitelisted_ips={str(item).strip() for item in values["whitelisted_ips"]},
        whitelisted_macs={_normalize_mac(str(item)) for item in values["whitelisted_macs"]},
        multi_ip_mac_exceptions={_normalize_mac(str(item)) for item in values["multi_ip_mac_exceptions"]},
        burst_threshold=max(1, int(values["burst_threshold"])),
        burst_window_seconds=max(0.0, float(values["burst_window_seconds"])),
        alert_cooldown_seconds=max(0.0, float(values["alert_cooldown_seconds"])),
        log_file=str(values["log_file"]),
        log_level=str(values["log_level"]).upper(),
    )
