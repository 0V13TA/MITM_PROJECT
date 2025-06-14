import sqlite3
import re
from datetime import datetime


DB_PATH = "../defense.db"


def init_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS ip_mac_bindings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL UNIQUE,
                mac_address TEXT NOT NULL UNIQUE,
                last_verified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS dns_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL UNIQUE,
                resolved_ip TEXT NOT NULL UNIQUE,
                last_verified TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
            """
        )


def is_valid_ip(ip: str) -> bool:
    # Validate IPv4 address
    pattern = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
    if pattern.match(ip):
        parts = ip.split(".")
        return all(0 <= int(part) <= 255 for part in parts)
    return False


def is_valid_mac(mac: str) -> bool:
    # Validate MAC address (formats like XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX)
    pattern = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$")
    return bool(pattern.match(mac))


def is_valid_domain(domain: str) -> bool:
    # Basic domain validation
    pattern = re.compile(
        r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z]{2,})+$"
    )
    return bool(pattern.match(domain))


def insert_ip_mac(ip: str, mac: str) -> bool:
    if not is_valid_ip(ip):
        raise ValueError(f"Invalid IP address: {ip}")
    if not is_valid_mac(mac):
        raise ValueError(f"Invalid MAC address: {mac}")

    with sqlite3.connect(DB_PATH) as conn:
        try:
            conn.execute(
                "INSERT INTO ip_mac_bindings (ip_address, mac_address, last_verified) VALUES (?, ?, ?)",
                (ip, mac, datetime.now()),
            )
            return True
        except sqlite3.IntegrityError as e:
            print(f"Error inserting ip_mac binding: {e}")
            return False


def get_all_ip_mac_bindings():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT * FROM ip_mac_bindings")
        return cursor.fetchall()


def insert_dns_record(domain: str, resolved_ip: str) -> bool:
    if not is_valid_domain(domain):
        raise ValueError(f"Invalid domain: {domain}")
    if not is_valid_ip(resolved_ip):
        raise ValueError(f"Invalid IP address: {resolved_ip}")

    with sqlite3.connect(DB_PATH) as conn:
        try:
            conn.execute(
                "INSERT INTO dns_records (domain, resolved_ip, last_verified) VALUES (?, ?, ?)",
                (domain, resolved_ip, datetime.now()),
            )
            return True
        except sqlite3.IntegrityError as e:
            print(f"Error inserting dns record: {e}")
            return False


def get_all_dns_records():
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT * FROM dns_records")
        return cursor.fetchall()


def test_db() -> None:
    with sqlite3.connect(DB_PATH) as conn:
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = cursor.fetchall()
        print("Tables in database:")
        for table in tables:
            print(f"- {table[0]}")

        print("\nSample ip_mac_bindings:")
        cursor = conn.execute("SELECT * FROM ip_mac_bindings LIMIT 5")
        for row in cursor.fetchall():
            print(row)

        print("\nSample dns_records:")
        cursor = conn.execute("SELECT * FROM dns_records LIMIT 5")
        for row in cursor.fetchall():
            print(row)


if __name__ == "__main__":
    init_db()
    test_db()
    # Example inserts
    try:
        insert_ip_mac("192.168.1.1", "00:1A:2B:3C:4D:5E")
    except ValueError as e:
        print(e)

    try:
        insert_dns_record("example.com", "93.184.216.34")
    except ValueError as e:
        print(e)

    print(get_all_ip_mac_bindings())
    print(get_all_dns_records())
