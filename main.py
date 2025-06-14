import argparse
import sys

def run_arp_spoofer():
    from ATTACK.arp_spoofer import index as arp_spoofer
    target_ip = input("Enter target IP: ")
    gateway_ip = input("Enter gateway IP: ")
    arp_spoofer.main([target_ip, gateway_ip])

def run_packet_sniffer():
    from ATTACK.packet_sniffer import index as packet_sniffer
    packet_sniffer.main()

def run_traffic_modificator():
    from ATTACK.traffic_modificator import index as traffic_modificator
    traffic_modificator.main()

def run_defense():
    from DEFENSE import main as defense_main
    defense_main.main()

def main():
    parser = argparse.ArgumentParser(description="MITM Project CLI")
    parser.add_argument('module', choices=['arp_spoofer', 'packet_sniffer', 'traffic_modificator', 'defense'], help="Module to run")
    args = parser.parse_args()

    if args.module == 'arp_spoofer':
        run_arp_spoofer()
    elif args.module == 'packet_sniffer':
        run_packet_sniffer()
    elif args.module == 'traffic_modificator':
        run_traffic_modificator()
    elif args.module == 'defense':
        run_defense()
    else:
        print("Unknown module")
        sys.exit(1)

if __name__ == "__main__":
    main()
