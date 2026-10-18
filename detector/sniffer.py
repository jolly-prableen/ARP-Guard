"""Scapy capture adapter for the passive detection engine."""

from collections.abc import Callable
from typing import Any

from .detect import DetectionEngine


class Sniffer:
    """Capture ARP packets and forward them to a DetectionEngine."""

    def __init__(
        self,
        engine: DetectionEngine,
        interface: str | None = None,
        sniff_func: Callable[..., Any] | None = None,
    ) -> None:
        self.engine = engine
        self.interface = interface or engine.config.interface
        self._sniff_func = sniff_func

    def _handle_packet(self, packet: Any) -> None:
        """Process a packet without returning a value to Scapy."""
        self.engine.process_packet(packet)

    def _resolve_sniff_func(self) -> Callable[..., Any]:
        """Validate the configured interface without beginning packet capture."""
        if not self.interface:
            raise RuntimeError(
                "No network interface configured; set interface in config/settings.yaml"
            )
        if self._sniff_func is not None:
            return self._sniff_func
        try:
            from scapy.all import get_if_list, sniff

            if self.interface not in get_if_list():
                raise RuntimeError(f"Invalid network interface '{self.interface}'")
            return sniff
        except ImportError as exc:
            raise RuntimeError(
                "Scapy is required for live ARP capture; install requirements.txt"
            ) from exc

    def validate_interface(self) -> None:
        """Validate capture prerequisites without invoking Scapy's sniff function."""
        self._resolve_sniff_func()

    def start(
        self,
        *,
        count: int = 0,
        timeout: int | None = None,
        on_ready: Callable[[], None] | None = None,
    ) -> None:
        """Start capture and report setup or capture failures."""
        sniff_func = self._resolve_sniff_func()

        kwargs: dict[str, Any] = {
            "iface": self.interface,
            "filter": "arp",
            "prn": self._handle_packet,
            "store": False,
        }

        if count:
            kwargs["count"] = count

        if timeout is not None:
            kwargs["timeout"] = timeout

        try:
            if on_ready is not None:
                on_ready()
            sniff_func(**kwargs)
        except PermissionError as exc:
            raise RuntimeError(
                "ARP capture requires administrator/root privileges"
            ) from exc
        except OSError as exc:
            raise RuntimeError(
                f"Unable to capture on interface '{self.interface}': {exc}"
            ) from exc
        except KeyboardInterrupt:
            return
        except Exception as exc:
            raise RuntimeError(
                f"ARP capture failed on interface '{self.interface}': {exc}"
            ) from exc

    def on_alert(
        self, callback: Callable[[dict[str, Any]], None]
    ) -> Callable[[], None]:
        """Register an alert callback with the detection engine."""
        return self.engine.on_alert(callback)
