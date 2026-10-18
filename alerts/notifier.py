import logging
from colorama import Fore, Style, init
from plyer import notification

# Initialize colorama so terminal colors work correctly on Windows
init(autoreset=True)

logger = logging.getLogger(__name__)

def trigger_alert(suspicious_ip, old_mac, new_mac, reason="ARP Spoofing Detected"):
    """
    Called whenever an attack or anomalous packet is flagged by the detector.
    """
    msg = f"[!] ALERT: {reason} | IP: {suspicious_ip} | Old MAC: {old_mac} -> New MAC: {new_mac}"
    
    # 1. Print formatted warning in bright red text to your terminal window
    print(f"{Fore.RED}{Style.BRIGHT}{msg}{Style.RESET_ALL}")
    
    # The detector owns JSONL persistence so CLI and dashboard share one history.
    # Trigger a desktop pop-up notification banner on Windows.
    try:
        notification.notify(
            title="⚠️ ARP Spoofing Detected!",
            message=f"IP: {suspicious_ip}\nNew MAC: {new_mac}",
            app_name="ARP Guard",
            timeout=5
        )
    except Exception:
        logger.exception("Desktop notification failed for %s", suspicious_ip)
