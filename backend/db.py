import sqlite3

def get_conn():
    conn = sqlite3.connect("netwatch.db")
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_conn()
    conn.executescript("""
    CREATE TABLE IF NOT EXISTS scans(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT, started_at TEXT);
    CREATE TABLE IF NOT EXISTS hosts(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER, ip TEXT, hostname TEXT, state TEXT);
    CREATE TABLE IF NOT EXISTS ports(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER, ip TEXT, port INTEGER,
        protocol TEXT, service TEXT);
    CREATE TABLE IF NOT EXISTS findings(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        scan_id INTEGER, ip TEXT, port INTEGER,
        category TEXT, severity TEXT, title TEXT, detail TEXT, fix TEXT);
    """)
    conn.commit()
    conn.close()
    