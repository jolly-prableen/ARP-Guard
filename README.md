# ARP Guard

ARP Guard is a passive ARP spoofing detector. The Member A detection engine learns a trusted IP-to-MAC baseline during a configurable startup window, analyzes ARP replies, suppresses duplicate alerts, and writes JSON Lines logs.

## Setup

```powershell
py -m pip install -r requirements.txt
```

Configure the capture interface and thresholds in `config/settings.yaml`. Live ARP capture generally requires administrator privileges. The engine does not modify ARP tables or inject packets.

## Tests

```powershell
py -m pytest -q
```

The sniffer accepts an injected `sniff_func`, so tests and integrations do not need live network capture.
