"""ShieldPro Database Module - Optimized"""
import sqlite3, os, sys
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "shieldpro.db")

_SCHEMA = [
    ("scan_history", """id INTEGER PRIMARY KEY AUTOINCREMENT, scan_type TEXT NOT NULL, scan_path TEXT,
        start_time TEXT NOT NULL, end_time TEXT, files_scanned INTEGER DEFAULT 0,
        threats_found INTEGER DEFAULT 0, threats_quarantined INTEGER DEFAULT 0,
        duration_seconds REAL DEFAULT 0, status TEXT DEFAULT 'running'"""),
    ("detected_threats", """id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER, filepath TEXT NOT NULL,
        threat_name TEXT NOT NULL, threat_type TEXT, severity TEXT, quarantined INTEGER DEFAULT 0,
        quarantine_path TEXT, detection_time TEXT NOT NULL, file_hash TEXT, file_size INTEGER,
        FOREIGN KEY (scan_id) REFERENCES scan_history(id)"""),
    ("quarantine_items", """id INTEGER PRIMARY KEY AUTOINCREMENT, original_path TEXT NOT NULL,
        quarantine_path TEXT NOT NULL, threat_name TEXT NOT NULL, quarantined_time TEXT NOT NULL,
        original_size INTEGER, original_hash TEXT, status TEXT DEFAULT 'quarantined',
        restored_time TEXT, notes TEXT"""),
    ("events", """id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL,
        event_type TEXT NOT NULL, severity TEXT DEFAULT 'info', message TEXT NOT NULL, details TEXT"""),
    ("settings_history", """id INTEGER PRIMARY KEY AUTOINCREMENT, changed_time TEXT NOT NULL,
        setting_key TEXT NOT NULL, old_value TEXT, new_value TEXT"""),
    ("signature_stats", """id INTEGER PRIMARY KEY AUTOINCREMENT, update_time TEXT NOT NULL,
        signature_count INTEGER, last_update_time TEXT, version TEXT"""),
]

def _conn():
    c = sqlite3.connect(DB_PATH); c.row_factory = sqlite3.Row; return c

def init():
    with _conn() as c:
        for name, schema in _SCHEMA:
            c.execute(f"CREATE TABLE IF NOT EXISTS {name} ({schema})")

def log_event(etype, severity, msg, details=None):
    with _conn() as c:
        c.execute("INSERT INTO events (timestamp, event_type, severity, message, details) VALUES (?,?,?,?,?)",
                  (datetime.now().isoformat(), etype, severity, msg, details))

def add_scan(scan_type, scan_path=None):
    with _conn() as c:
        cur = c.execute("INSERT INTO scan_history (scan_type, scan_path, start_time, status) VALUES (?,?,?, 'running')",
                        (scan_type, scan_path, datetime.now().isoformat()))
        return cur.lastrowid

def update_scan(sid, files=0, threats=0, quarantined=0, status='completed'):
    with _conn() as c:
        row = c.execute("SELECT start_time FROM scan_history WHERE id=?", (sid,)).fetchone()
        dur = (datetime.now() - datetime.fromisoformat(row['start_time'])).total_seconds() if row else 0
        c.execute("UPDATE scan_history SET end_time=?, files_scanned=?, threats_found=?, threats_quarantined=?, duration_seconds=?, status=? WHERE id=?",
                  (datetime.now().isoformat(), files, threats, quarantined, dur, status, sid))

def add_threat(sid, fp, name, ttype=None, severity=None, quarantined=False, qpath=None, fhash=None, fsize=None):
    with _conn() as c:
        cur = c.execute("INSERT INTO detected_threats (scan_id, filepath, threat_name, threat_type, severity, quarantined, quarantine_path, detection_time, file_hash, file_size) VALUES (?,?,?,?,?,?,?,?,?,?)",
                        (sid, fp, name, ttype, severity, 1 if quarantined else 0, qpath, datetime.now().isoformat(), fhash, fsize))
        return cur.lastrowid

def add_quarantine(orig, qpath, threat, size=None, fhash=None):
    with _conn() as c:
        cur = c.execute("INSERT INTO quarantine_items (original_path, quarantine_path, threat_name, quarantined_time, original_size, original_hash, status) VALUES (?,?,?,?,'quarantined')",
                        (orig, qpath, threat, datetime.now().isoformat(), size, fhash))
        return cur.lastrowid

def get_quarantine():
    with _conn() as c: return [dict(r) for r in c.execute("SELECT * FROM quarantine_items ORDER BY quarantined_time DESC")]

def restore_quarantine(iid):
    with _conn() as c:
        item = c.execute("SELECT * FROM quarantine_items WHERE id=?", (iid,)).fetchone()
        if item and os.path.exists(item['quarantine_path']):
            try:
                os.makedirs(os.path.dirname(item['original_path']), exist_ok=True)
                import shutil; shutil.move(item['quarantine_path'], item['original_path'])
                c.execute("UPDATE quarantine_items SET status='restored', restored_time=? WHERE id=?", (datetime.now().isoformat(), iid))
                return True
            except: pass
        return False

def delete_quarantine(iid):
    with _conn() as c:
        row = c.execute("SELECT quarantine_path FROM quarantine_items WHERE id=?", (iid,)).fetchone()
        if row and os.path.exists(row['quarantine_path']):
            try: os.remove(row['quarantine_path'])
            except: pass
        c.execute("DELETE FROM quarantine_items WHERE id=?", (iid,))

def get_history(limit=100):
    with _conn() as c: return [dict(r) for r in c.execute("SELECT * FROM scan_history ORDER BY start_time DESC LIMIT ?", (limit,))]

def get_events(limit=100):
    with _conn() as c: return [dict(r) for r in c.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))]

def get_stats():
    with _conn() as c:
        return {
            'total_scans': c.execute("SELECT COUNT(*) as t FROM scan_history").fetchone()['t'],
            'total_threats': c.execute("SELECT SUM(threats_found) as t FROM scan_history").fetchone()['t'] or 0,
            'files_quarantined': c.execute("SELECT COUNT(*) as t FROM quarantine_items WHERE status='quarantined'").fetchone()['t'],
            'total_detected': c.execute("SELECT COUNT(*) as t FROM detected_threats").fetchone()['t'],
            'avg_scan_duration': round(c.execute("SELECT AVG(duration_seconds) as a FROM scan_history WHERE status='completed'").fetchone()['a'] or 0, 1),
            'files_scanned_total': c.execute("SELECT SUM(files_scanned) as t FROM scan_history").fetchone()['t'] or 0
        }

def clear_quarantine():
    with _conn() as c:
        for r in c.execute("SELECT quarantine_path FROM quarantine_items"):
            try: os.remove(r['quarantine_path'])
            except: pass
        c.execute("DELETE FROM quarantine_items")

def delete_all_threats():
    with _conn() as c: c.execute("DELETE FROM detected_threats")

init()
