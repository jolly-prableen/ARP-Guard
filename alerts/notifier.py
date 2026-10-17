# alerts/notifier.py
import logging
from colorama import Fore, Style, init
from plyer import notification

# Initialize colorama so terminal colors work correctly on Windows
init(autoreset=True)

# Set up logging to save historical alerts into a file named alerts.log
logging.basicConfig(
    filename="alerts.log",
    level=logging.WARNING,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

def trigger_alert(suspicious_ip, old_mac, new_mac, reason="ARP Spoofing Detected"):
    """
    Called whenever an attack or anomalous packet is flagged by the detector.
    """
    msg = f"[!] ALERT: {reason} | IP: {suspicious_ip} | Old MAC: {old_mac} -> New MAC: {new_mac}"
    
    # 1. Print formatted warning in bright red text to your terminal window
    print(f"{Fore.RED}{Style.BRIGHT}{msg}{Style.RESET_ALL}")
    
    # 2. Automatically save the alert details into 'alerts.log'
    logging.warning(msg)
    
    # 3. Trigger a desktop pop-up notification banner on Windows
    try:
        notification.notify(
            title="⚠️ ARP Spoofing Detected!",
            message=f"IP: {suspicious_ip}\nNew MAC: {new_mac}",
            app_name="ARP Guard",
            timeout=5
        )
    except Exception:
        pass  # Fails silently if desktop notifications are turned off on your system