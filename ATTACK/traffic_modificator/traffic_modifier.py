# Here is a simple Python example using Scapy to capture and modify HTTP (unencrypted) traffic. This script listens for TCP packets on port 80, 
# replaces the word "Hello" with "Hi" in the payload, and resends the modified packet.

import logging
from scapy.all import sniff, send, IP, TCP, Raw

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')

# Configurable strings to replace
ORIGINAL_STRING = b'Hello'
REPLACEMENT_STRING = b'Hi'

def modify_packet(packet):
    try:
        if packet.haslayer(Raw):
            payload = packet[Raw].load
            if ORIGINAL_STRING in payload:
                modified_payload = payload.replace(ORIGINAL_STRING, REPLACEMENT_STRING)
                packet[Raw].load = modified_payload
                # Recalculate checksums
                del packet[IP].chksum
                del packet[TCP].chksum
                send(packet)
                logging.info("Modified and sent a packet.")
    except Exception as e:
        logging.error(f"Error modifying packet: {e}")

# Capture TCP packets on port 80 (HTTP)
def start_http_modifier():
    sniff(filter="tcp port 80", prn=modify_packet, store=0)
