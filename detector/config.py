"""Configuration loading for the ARP detector."""

from dataclasses import dataclass, field
import ipaddress
import math
from pathlib import Path
import re
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

_REQUIRED_KEYS = frozenset(_DEFAULTS)
_MAC_PATTERN = re.compile(r"^[0-9a-fA-F]{2}([:-][0-9a-fA-F]{2}){5}$")
_LOG_LEVELS = frozenset({"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"})


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


def _require_number(values: dict[str, Any], key: str, *, minimum: float, integer: bool = False) -> float | int:
    value = values[key]
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        kind = "an integer" if integer else "a number"
        raise ValueError(f"'{key}' must be {kind}")
    if not math.isfinite(value) or value < minimum:
        comparison = "at least" if minimum else "zero or greater"
        raise ValueError(f"'{key}' must be {comparison} {minimum}")
    if integer and int(value) != value:
        raise ValueError(f"'{key}' must be an integer")
    return int(value) if integer else float(value)


def _validate_ips(values: dict[str, Any], key: str) -> set[str]:
    entries = values[key]
    if not isinstance(entries, list):
        raise ValueError(f"'{key}' must be a list of IP addresses")
    validated = set()
    for entry in entries:
        if not isinstance(entry, str) or not entry.strip():
            raise ValueError(f"'{key}' contains an empty or non-string IP address")
        try:
            validated.add(str(ipaddress.ip_address(entry.strip())))
        except ValueError as exc:
            raise ValueError(f"'{key}' contains invalid IP address '{entry}'") from exc
    return validated


def _validate_macs(values: dict[str, Any], key: str) -> set[str]:
    entries = values[key]
    if not isinstance(entries, list):
        raise ValueError(f"'{key}' must be a list of MAC addresses")
    normalized = set()
    for entry in entries:
        if not isinstance(entry, str) or not _MAC_PATTERN.fullmatch(entry.strip()):
            raise ValueError(f"'{key}' contains invalid MAC address '{entry}'")
        normalized.add(_normalize_mac(entry))
    return normalized


def load_config(path: str | Path = "config/settings.yaml") -> DetectorConfig:
    """Load and validate the detector's YAML configuration file."""
    config_path = Path(path)
    if not config_path.is_file():
        raise ValueError(f"Configuration file not found: {config_path}")
    try:
        import yaml
    except ImportError as exc:
        raise ValueError("PyYAML is required to load configuration; install requirements.txt") from exc
    try:
        loaded = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ValueError(f"Unable to load configuration from {config_path}: {exc}") from exc

    if not isinstance(loaded, dict):
        raise ValueError(f"Configuration in {config_path} must be a mapping")
    if any(not isinstance(key, str) for key in loaded):
        raise ValueError(f"Configuration in {config_path} must use string keys")
    missing = sorted(_REQUIRED_KEYS - loaded.keys())
    if missing:
        raise ValueError(f"Configuration in {config_path} is missing required keys: {', '.join(missing)}")
    unknown = sorted(loaded.keys() - _REQUIRED_KEYS)
    if unknown:
        raise ValueError(f"Configuration in {config_path} has unknown keys: {', '.join(unknown)}")

    values = loaded
    interface = values["interface"]
    if not isinstance(interface, str) or not interface.strip() or "\x00" in interface:
        raise ValueError("'interface' must be a non-empty network interface name")
    log_file = values["log_file"]
    if not isinstance(log_file, str) or not log_file.strip():
        raise ValueError("'log_file' must be a non-empty JSONL file path")
    log_path = Path(log_file)
    if log_path.exists() and log_path.is_dir():
        raise ValueError(f"'log_file' must be a file, not a directory: {log_file}")
    if log_path.parent.exists() and not log_path.parent.is_dir():
        raise ValueError(f"'log_file' parent is not a directory: {log_path.parent}")
    if not log_path.name:
        raise ValueError("'log_file' must include a file name")
    log_level = values["log_level"]
    if not isinstance(log_level, str) or log_level.upper() not in _LOG_LEVELS:
        raise ValueError("'log_level' must be DEBUG, INFO, WARNING, ERROR, or CRITICAL")

    return DetectorConfig(
        interface=interface.strip(),
        learning_window_seconds=_require_number(values, "learning_window_seconds", minimum=0.0),
        learning_confirmations=_require_number(values, "learning_confirmations", minimum=1, integer=True),
        whitelisted_ips=_validate_ips(values, "whitelisted_ips"),
        whitelisted_macs=_validate_macs(values, "whitelisted_macs"),
        multi_ip_mac_exceptions=_validate_macs(values, "multi_ip_mac_exceptions"),
        burst_threshold=_require_number(values, "burst_threshold", minimum=1, integer=True),
        burst_window_seconds=_require_number(values, "burst_window_seconds", minimum=0.0),
        alert_cooldown_seconds=_require_number(values, "alert_cooldown_seconds", minimum=0.0),
        log_file=log_file.strip(),
        log_level=log_level.upper(),
    )
