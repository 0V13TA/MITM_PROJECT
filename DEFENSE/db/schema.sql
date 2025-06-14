CREATE TABLE IF NOT EXISTS ip_mac_bindings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address TEXT NOT NULL,
    mac_address TEXT NOT NULL,
    last_verified TIMESTAMP
);
CREATE TABLE IF NOT EXISTS dns_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain UNIQUE TEXT NOT NULL,
    resolved_ip UNIQUE TEXT NOT NULL,
    last_verified TIMESTAMP
);