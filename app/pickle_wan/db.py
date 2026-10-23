"""SQLite storage. All access happens on the event loop thread."""
import json
import os
import sqlite3
import time

DB_PATH = os.environ.get("PICKLE_DB", "/data/pickle.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS results (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    check_id TEXT NOT NULL,
    ok INTEGER NOT NULL,
    latency_ms REAL,
    loss REAL,
    target TEXT,
    detail TEXT
);
CREATE INDEX IF NOT EXISTS results_check_ts ON results (check_id, ts);
CREATE INDEX IF NOT EXISTS results_ts ON results (ts);

CREATE TABLE IF NOT EXISTS incidents (
    id INTEGER PRIMARY KEY,
    check_id TEXT NOT NULL,
    start REAL NOT NULL,
    end REAL,
    fail_count INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS incidents_start ON incidents (start);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY,
    ts REAL NOT NULL,
    source TEXT NOT NULL,
    kind TEXT NOT NULL,
    message TEXT NOT NULL,
    data TEXT,
    uid TEXT UNIQUE
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);

-- Gateway load, one row per UniFi poll. Rates are bits/s averaged since the previous poll.
CREATE TABLE IF NOT EXISTS load (
    ts REAL NOT NULL,
    rx_bps REAL,
    tx_bps REAL,
    cpu REAL,
    mem REAL,
    temp REAL,
    clients INTEGER
);
CREATE INDEX IF NOT EXISTS load_ts ON load (ts);

CREATE TABLE IF NOT EXISTS kv (
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


class DB:
    def __init__(self, path=DB_PATH):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self.conn.executescript(SCHEMA)
        self.conn.commit()

    def q(self, sql, args=()):
        return self.conn.execute(sql, args).fetchall()

    def x(self, sql, args=()):
        cur = self.conn.execute(sql, args)
        self.conn.commit()
        return cur

    def add_result(self, ts, check_id, ok, latency_ms, loss, target, detail):
        self.x("INSERT INTO results (ts, check_id, ok, latency_ms, loss, target, detail) "
               "VALUES (?, ?, ?, ?, ?, ?, ?)",
               (ts, check_id, 1 if ok else 0, latency_ms, loss, target, detail))

    def add_event(self, source, kind, message, data=None, ts=None, uid=None):
        """Returns True if the event was new (uid not seen before)."""
        cur = self.x("INSERT OR IGNORE INTO events (ts, source, kind, message, data, uid) "
                     "VALUES (?, ?, ?, ?, ?, ?)",
                     (ts or time.time(), source, kind, message,
                      json.dumps(data) if data is not None else None, uid))
        return cur.rowcount > 0

    def add_load(self, ts, rx_bps, tx_bps, cpu, mem, temp, clients):
        self.x("INSERT INTO load (ts, rx_bps, tx_bps, cpu, mem, temp, clients) "
               "VALUES (?, ?, ?, ?, ?, ?, ?)", (ts, rx_bps, tx_bps, cpu, mem, temp, clients))

    def get_kv(self, key, default=None):
        rows = self.q("SELECT value FROM kv WHERE key = ?", (key,))
        return json.loads(rows[0]["value"]) if rows else default

    def set_kv(self, key, value):
        self.x("INSERT INTO kv (key, value) VALUES (?, ?) "
               "ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, json.dumps(value)))

    def purge(self, retention_days):
        cutoff = time.time() - retention_days * 86400
        self.x("DELETE FROM results WHERE ts < ?", (cutoff,))
        self.x("DELETE FROM incidents WHERE end IS NOT NULL AND end < ?", (cutoff,))
        self.x("DELETE FROM events WHERE ts < ?", (cutoff,))
        self.x("DELETE FROM load WHERE ts < ?", (cutoff,))
