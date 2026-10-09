"""Startup entry point for the passive ARP-Guard detector."""

import logging

from detector.config import load_config
from detector.detect import DetectionEngine
from detector.sniffer import Sniffer


LOGGER = logging.getLogger(__name__)


def show_alert(event: dict[str, object]) -> None:
    """Display an alert event for future alerting or dashboard integrations."""
    print(
        "\nARP alert"
        f"\n  timestamp: {event.get('timestamp')}"
        f"\n  suspicious IP: {event.get('suspicious_ip')}"
        f"\n  old MAC: {event.get('old_mac')}"
        f"\n  new MAC: {event.get('new_mac')}"
        f"\n  reason: {event.get('reason')}"
        f"\n  severity: {event.get('severity')}"
    )


def main() -> int:
    """Load configuration and start passive ARP monitoring."""
    try:
        config = load_config("config/settings.yaml")
        log_level = getattr(logging, config.log_level.upper(), logging.INFO)
        logging.basicConfig(level=log_level, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

        engine = DetectionEngine(config)
        engine.on_alert(show_alert)
        sniffer = Sniffer(engine)
        sniffer.start()
    except RuntimeError as error:
        print(f"Unable to start ARP-Guard: {error}")
        return 1
    except KeyboardInterrupt:
        print("ARP-Guard stopped.")
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
