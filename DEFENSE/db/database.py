import re
import sqlite3
from datetime import datetime
from DEFENSE.utils.config import DB_PATH

LOG_LEVELS = ["severe", "error", "warning", "info", "debug", "default"]


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

            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                level TEXT NOT NULL,
                message TEXT NOT NULL
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


def get_ip_mac_bindings(ip: str | None = None, mac: str | None = None):
    with sqlite3.connect(DB_PATH) as conn:
        if ip and mac:
            cursor = conn.execute(
                "SELECT * FROM ip_mac_bindings WHERE ip_address = ? AND mac_address = ?",
                (ip, mac),
            )
        elif ip:
            cursor = conn.execute(
                "SELECT * FROM ip_mac_bindings WHERE ip_address = ?", (ip)
            )
        elif mac:
            cursor = conn.execute(
                "SELECT * FROM ip_mac_bindings WHERE mac_address = ?", (mac)
            )
        else:
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


def get_dns_record(domain: str | None = None, resolved_ip: str | None = None):
    with sqlite3.connect(DB_PATH) as conn:
        if domain and resolved_ip:
            cursor = conn.execute(
                "SELECT * FROM dns_records WHERE domain = ? AND resolved_ip = ?",
                (domain, resolved_ip),
            )
        elif domain:
            cursor = conn.execute(
                "SELECT * FROM dns_records WHERE domain = ?", (domain,)
            )
        elif resolved_ip:
            cursor = conn.execute(
                "SELECT * FROM dns_records WHERE resolved_ip = ?", (resolved_ip,)
            )
        else:
            cursor = conn.execute("SELECT * FROM dns_records")
        return cursor.fetchall()


def write_log(level: str, message: str) -> None:
    with sqlite3.connect(DB_PATH) as conn:
        try:
            conn.execute(
                "INSERT INTO logs (level, message) VALUES (?, ?)",
                (level, message),
            )
        except sqlite3.Error as e:
            print(f"Error writing log: {e}")


def get_logs(level: str | None = None):
    with sqlite3.connect(DB_PATH) as conn:
        if level:
            if level not in LOG_LEVELS:
                raise ValueError(
                    f"Invalid log level: {level}. Must be one of {LOG_LEVELS}."
                )
            cursor = conn.execute("SELECT * FROM logs WHERE level = ?", (level))
        else:
            cursor = conn.execute("SELECT * FROM logs")
        return cursor.fetchall()
