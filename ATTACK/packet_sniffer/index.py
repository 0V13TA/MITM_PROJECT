import sys
import os
from scapy.all import sniff

# Add project root to sys.path for imports
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../'))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from ATTACK.utils.logger import log

def packet_callback(packet):
    log(packet.summary(), level="info", to_file=True)

def main():
    log("Starting packet sniffer... Press Ctrl+C to stop.", level="info", to_file=True)
    try:
        sniff(prn=packet_callback, store=False)
    except KeyboardInterrupt:
        log("Packet sniffer stopped.", level="info", to_file=True)

if __name__ == "__main__":
    main()
