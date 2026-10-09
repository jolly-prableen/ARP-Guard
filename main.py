"""Startup entry point for the passive ARP-Guard detector."""

import logging

from detector.config import load_config
from detector.detect import DetectionEngine
from detector.sniffer import Sniffer


def show_alert(event: dict[str, object]) -> None:
    """Display a detected ARP alert."""
    print(
        "\nARP ALERT"
        f"\n  Timestamp: {event.get('timestamp')}"
        f"\n  Suspicious IP: {event.get('suspicious_ip')}"
        f"\n  Old MAC: {event.get('old_mac')}"
        f"\n  New MAC: {event.get('new_mac')}"
        f"\n  Reason: {event.get('reason')}"
        f"\n  Severity: {event.get('severity')}",
        flush=True,
    )


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
