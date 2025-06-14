import argparse
import sys

def run_arp_detector():
    from DEFENSE.detectors import arp_detectors
    arp_detectors.init_db()
    arp_detectors.start_live_arp_sniff()

def main():
    parser = argparse.ArgumentParser(description="Defense Module CLI")
    parser.add_argument('detector', choices=['arp_detector'], help="Detector to run")
    args = parser.parse_args()

    if args.detector == 'arp_detector':
        run_arp_detector()
    else:
        print("Unknown detector")
        sys.exit(1)

if __name__ == "__main__":
    main()
