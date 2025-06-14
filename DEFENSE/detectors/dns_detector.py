from scapy.all import sniff
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP
from DEFENSE.utils.logger import log
from DEFENSE.db.database import get_dns_record, insert_dns_record, init_db


def dns_display(pkt):
    if pkt.haslayer(DNS) and pkt.getlayer(DNS).qr == 1:  # qr==1 means response
        dns_layer = pkt.getlayer(DNS)
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        domain = dns_layer.qd.qname.decode() if dns_layer.qd else None
        answers = []
        for i in range(dns_layer.ancount):
            ans = dns_layer.an[i]
            rdata = None
            if isinstance(ans, DNSRR):
                rdata = ans.rdata
            answers.append(rdata)

        # Check if domain exists and resolves to a different IP
        if domain is not None:
            existing_records = get_dns_record(domain=domain)
            if existing_records:
                existing_ip = existing_records[0][2]  # resolved_ip column
                if existing_ip != answers[0]:
                    log(
                        message=f"Domain {domain} resolved to new IP {answers[0]} (was {existing_ip})",
                        to_db=True,
                        to_console=True,
                        level="warning",
                    )
        else:
            if domain is not None:
                try:
                    success = insert_dns_record(domain, answers[0])
                    if success:
                        log(
                            message=f"Inserted DNS record: {domain} -> {answers[0]}",
                            to_db=True,
                            to_console=True,
                            level="info",
                        )
                    else:
                        log(
                            message=f"Failed to insert DNS record: {domain} -> {answers[0]}",
                            to_db=True,
                            to_console=True,
                            level="error",
                        )
                except ValueError as e:
                    log(
                        message=f"Warning: {e}",
                        to_db=True,
                        to_console=True,
                        level="warning",
                    )

        log(
            message=f"DNS Response from {src_ip} to {dst_ip}: Query: {domain}, Answers: {answers}",
            to_db=True,
            to_console=True,
            level="info",
        )


def start_dns_sniffer():
    sniff(filter="udp and port 53", prn=dns_display, store=0)


if __name__ == "__main__":
    init_db()  # Initialize the database connection
    log(
        message="Starting DNS sniffer...",
        to_db=True,
        to_console=True,
        level="info",
    )
    start_dns_sniffer()
