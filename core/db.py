"""
Database module for persisting device scan history and detecting changes.
"""

import os
import sqlite3
from datetime import datetime

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "devices.db")


def _connect():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    with _connect() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                hostname    TEXT,
                vendor      TEXT,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL,
                UNIQUE(ip_address, mac_address)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS mac_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address  TEXT NOT NULL,
                mac_address TEXT NOT NULL,
                seen_at     TEXT NOT NULL
            )
        """)
        conn.commit()


def upsert_device(ip_address, mac_address, hostname, vendor):
    """
    Insert or update a device record.
    Returns a string tag: 'new', 'mac_changed', or 'seen'.
    """
    now = datetime.utcnow().isoformat()
    with _connect() as conn:
        existing = conn.execute(
            "SELECT mac_address FROM devices WHERE ip_address = ?", (ip_address,)
        ).fetchone()

        if existing is None:
            conn.execute(
                """INSERT INTO devices (ip_address, mac_address, hostname, vendor, first_seen, last_seen)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (ip_address, mac_address, hostname, vendor, now, now),
            )
            conn.execute(
                "INSERT INTO mac_history (ip_address, mac_address, seen_at) VALUES (?, ?, ?)",
                (ip_address, mac_address, now),
            )
            conn.commit()
            return "new"

        if existing["mac_address"].lower() != mac_address.lower():
            conn.execute(
                """UPDATE devices SET mac_address=?, hostname=?, vendor=?, last_seen=?
                   WHERE ip_address=?""",
                (mac_address, hostname, vendor, now, ip_address),
            )
            conn.execute(
                "INSERT INTO mac_history (ip_address, mac_address, seen_at) VALUES (?, ?, ?)",
                (ip_address, mac_address, now),
            )
            conn.commit()
            return "mac_changed"

        conn.execute(
            "UPDATE devices SET hostname=?, vendor=?, last_seen=? WHERE ip_address=?",
            (hostname, vendor, now, ip_address),
        )
        conn.commit()
        return "seen"


def get_all_devices():
    """Return all known devices as a list of dicts."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT ip_address, mac_address, hostname, vendor, first_seen, last_seen FROM devices"
        ).fetchall()
    return [dict(r) for r in rows]


def get_mac_history(ip_address):
    """Return the MAC history for a given IP (for spoofing audit trail)."""
    with _connect() as conn:
        rows = conn.execute(
            "SELECT mac_address, seen_at FROM mac_history WHERE ip_address = ? ORDER BY seen_at",
            (ip_address,),
        ).fetchall()
    return [dict(r) for r in rows]
