"""Startup entry point for the passive ARP-Guard detector."""

import logging

from detector.config import load_config
from detector.detect import DetectionEngine
from detector.sniffer import Sniffer
# Person B notification integration
from alerts.notifier import trigger_alert


def show_alert(event: dict[str, object]) -> None:
    """Display a detected ARP alert using Person B's notification system."""
    suspicious_ip = str(event.get('suspicious_ip'))
    old_mac = str(event.get('old_mac'))
    new_mac = str(event.get('new_mac'))
    reason = str(event.get('reason', 'ARP Spoofing Detected'))

    # Call Person B's console colorizer, file logger, and desktop popup!
    trigger_alert(suspicious_ip, old_mac, new_mac, reason=reason)


def main() -> int:
    """Load configuration and start passive ARP monitoring."""
    try:
        config = load_config("config/settings.yaml")

        log_level = getattr(
            logging, config.log_level.upper(), logging.INFO
        )
        logging.basicConfig(
            level=log_level,
            format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        )

        engine = DetectionEngine(config)
        engine.on_alert(show_alert)

        sniffer = Sniffer(engine)

        print(
            f"ARP-Guard listening on {config.interface}...",
            flush=True,
        )

        sniffer.start()

    except RuntimeError as error:
        print(f"Unable to start ARP-Guard: {error}", flush=True)
        return 1

    except KeyboardInterrupt:
        print("\nARP-Guard stopped.", flush=True)
        return 0

    return 0


if __name__ == "__main__":
    raise SystemExit(main())