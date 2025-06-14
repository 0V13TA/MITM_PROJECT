from scapy.all import sniff
from scapy.layers.l2 import ARP, Ether
from scapy.all import srp
from DEFENSE.utils.logger import log
from DEFENSE.db.database import get_ip_mac_bindings, insert_ip_mac, init_db


def confirm_ip_mac_bindings(existing_ip, existing_mac, ip, mac):
    if not existing_ip and not existing_mac:
        success = insert_ip_mac(ip, mac)
        if success:
            log(
                message=f"Inserted new IP-MAC binding from scan: {ip} - {mac}",
                to_db=True,
                to_console=True,
                level="info",
            )
        else:
            log(
                message=f"Failed to insert IP-MAC binding from scan: {ip} - {mac}",
                to_db=True,
                to_console=True,
                level="error",
            )
    elif existing_ip and existing_ip[0][2] != mac:
        # If the IP exists but the MAC has changed, log a warning
        # This indicates a possible ARP spoofing attack
        log(
            message=f"Possible ARP spoofing detected from scan: {ip} now maps to {mac} (was {existing_ip[0][2]})",
            to_db=True,
            to_console=True,
            level="warning",
        )
    elif existing_mac and existing_ip[0][1] != ip:
        # If the MAC exists but the IP has changed, log a warning
        # This indicates a possible ARP spoofing attack
        log(
            message=f"Possible ARP spoofing detected from scan: {mac} now maps to {ip} (was {existing_ip[0][1]})",
            to_db=True,
            to_console=True,
            level="warning",
        )
    else:
        # If both IP and MAC exist and match, do nothing
        log(
            message=f"IP-MAC binding already exists: {ip} - {mac}",
            to_db=True,
            to_console=True,
            level="debug",
        )


def arp_display(pkt):
    if pkt.haslayer(ARP):
        arp_layer = pkt.getlayer(ARP)
        ip = arp_layer.psrc
        mac = arp_layer.hwsrc
        log(message=f"ARP Packet: {ip} is at {mac}")

        # Check if IP or MAC already exists in DB
        existing_ip = get_ip_mac_bindings(ip=ip)
        existing_mac = get_ip_mac_bindings(mac=mac)

        confirm_ip_mac_bindings(existing_ip, existing_mac, ip, mac)


def arp_scan(subnet: str):
    """
    Scan the local subnet for ARP responses to populate baseline.
    """
    arp = ARP(pdst=subnet)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether / arp

    result = srp(packet, timeout=3, verbose=0)[0]

    for sent, received in result:
        ip = received.psrc
        mac = received.hwsrc
        log(message=f"ARP Scan found: {ip} is at {mac}")

        existing_ip = get_ip_mac_bindings(ip=ip)
        existing_mac = get_ip_mac_bindings(mac=mac)

        confirm_ip_mac_bindings(existing_ip, existing_mac, ip, mac)


def start_live_arp_sniff():
    """Begin live ARP sniffing on all interfaces."""
    sniff(filter="arp", prn=arp_display, store=0)


if __name__ == "__main__":
    init_db()  # Ensure the database is initialized
    start_live_arp_sniff()
