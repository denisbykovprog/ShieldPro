import sqlite3
import os
import sys
from datetime import datetime

if getattr(sys, 'frozen', False):
    DATA_DIR = os.path.join(sys._MEIPASS, "data")
else:
    DATA_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DB_PATH = os.path.join(DATA_DIR, "shieldpro.db")

os.makedirs(DATA_DIR, exist_ok=True)

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_database():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_type TEXT NOT NULL,
            scan_path TEXT,
            start_time TEXT NOT NULL,
            end_time TEXT,
            files_scanned INTEGER DEFAULT 0,
            threats_found INTEGER DEFAULT 0,
            threats_quarantined INTEGER DEFAULT 0,
            duration_seconds REAL DEFAULT 0,
            status TEXT DEFAULT 'running'
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS detected_threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            filepath TEXT NOT NULL,
            threat_name TEXT NOT NULL,
            threat_type TEXT,
            severity TEXT,
            quarantined INTEGER DEFAULT 0,
            quarantine_path TEXT,
            detection_time TEXT NOT NULL,
            file_hash TEXT,
            file_size INTEGER,
            FOREIGN KEY (scan_id) REFERENCES scan_history(id)
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS quarantine_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            original_path TEXT NOT NULL,
            quarantine_path TEXT NOT NULL,
            threat_name TEXT NOT NULL,
            quarantined_time TEXT NOT NULL,
            original_size INTEGER,
            original_hash TEXT,
            status TEXT DEFAULT 'quarantined',
            restored_time TEXT,
            notes TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            severity TEXT DEFAULT 'info',
            message TEXT NOT NULL,
            details TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS settings_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            changed_time TEXT NOT NULL,
            setting_key TEXT NOT NULL,
            old_value TEXT,
            new_value TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS signature_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            update_time TEXT NOT NULL,
            signature_count INTEGER,
            last_update_time TEXT,
            version TEXT
        )
    """)

    conn.commit()
    conn.close()

def log_event(event_type, severity, message, details=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO events (timestamp, event_type, severity, message, details)
        VALUES (?, ?, ?, ?, ?)
    """, (datetime.now().isoformat(), event_type, severity, message, details))
    conn.commit()
    conn.close()

def add_scan_record(scan_type, scan_path=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scan_history (scan_type, scan_path, start_time, status)
        VALUES (?, ?, ?, 'running')
    """, (scan_type, scan_path, datetime.now().isoformat()))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return scan_id

def update_scan_record(scan_id, files_scanned=0, threats_found=0, threats_quarantined=0, status='completed'):
    conn = get_db_connection()
    cursor = conn.cursor()
    end_time = datetime.now().isoformat()

    cursor.execute("""
        SELECT start_time FROM scan_history WHERE id = ?
    """, (scan_id,))
    row = cursor.fetchone()
    if row:
        start_time = datetime.fromisoformat(row['start_time'])
        duration = (datetime.now() - start_time).total_seconds()
    else:
        duration = 0

    cursor.execute("""
        UPDATE scan_history SET
            end_time = ?,
            files_scanned = ?,
            threats_found = ?,
            threats_quarantined = ?,
            duration_seconds = ?,
            status = ?
        WHERE id = ?
    """, (end_time, files_scanned, threats_found, threats_quarantined, duration, status, scan_id))
    conn.commit()
    conn.close()

def add_threat(scan_id, filepath, threat_name, threat_type=None, severity=None, quarantined=False, quarantine_path=None, file_hash=None, file_size=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO detected_threats (scan_id, filepath, threat_name, threat_type, severity, quarantined, quarantine_path, detection_time, file_hash, file_size)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (scan_id, filepath, threat_name, threat_type, severity, 1 if quarantined else 0, quarantine_path, datetime.now().isoformat(), file_hash, file_size))
    threat_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return threat_id

def add_quarantine_item(original_path, quarantine_path, threat_name, original_size=None, original_hash=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO quarantine_items (original_path, quarantine_path, threat_name, quarantined_time, original_size, original_hash, status)
        VALUES (?, ?, ?, ?, ?, ?, 'quarantined')
    """, (original_path, quarantine_path, threat_name, datetime.now().isoformat(), original_size, original_hash))
    item_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return item_id

def get_quarantine_items():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM quarantine_items ORDER BY quarantined_time DESC")
    items = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return items

def restore_quarantine_item(item_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM quarantine_items WHERE id = ?", (item_id,))
    item = cursor.fetchone()
    if item:
        if os.path.exists(item['quarantine_path']):
            try:
                os.makedirs(os.path.dirname(item['original_path']), exist_ok=True)
                import shutil
                shutil.move(item['quarantine_path'], item['original_path'])
                cursor.execute("""
                    UPDATE quarantine_items SET status = 'restored', restored_time = ? WHERE id = ?
                """, (datetime.now().isoformat(), item_id))
                conn.commit()
                conn.close()
                return True
            except:
                conn.close()
                return False
    conn.close()
    return False

def delete_quarantine_item(item_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT quarantine_path FROM quarantine_items WHERE id = ?", (item_id,))
    row = cursor.fetchone()
    if row and os.path.exists(row['quarantine_path']):
        try:
            os.remove(row['quarantine_path'])
        except:
            pass
    cursor.execute("DELETE FROM quarantine_items WHERE id = ?", (item_id,))
    conn.commit()
    conn.close()

def get_scan_history(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scan_history ORDER BY start_time DESC LIMIT ?", (limit,))
    scans = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return scans

def get_events(limit=100):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,))
    events = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return events

def get_statistics():
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM scan_history")
    total_scans = cursor.fetchone()['total']

    cursor.execute("SELECT SUM(threats_found) as total FROM scan_history")
    total_threats = cursor.fetchone()['total'] or 0

    cursor.execute("SELECT COUNT(*) as total FROM quarantine_items WHERE status = 'quarantined'")
    quarantined = cursor.fetchone()['total']

    cursor.execute("SELECT COUNT(*) as total FROM detected_threats")
    detected = cursor.fetchone()['total']

    cursor.execute("SELECT AVG(duration_seconds) as avg FROM scan_history WHERE status = 'completed'")
    avg_duration = cursor.fetchone()['avg'] or 0

    cursor.execute("SELECT SUM(files_scanned) as total FROM scan_history")
    files_scanned = cursor.fetchone()['total'] or 0

    conn.close()

    return {
        'total_scans': total_scans,
        'total_threats': int(total_threats),
        'files_quarantined': quarantined,
        'total_detected': detected,
        'avg_scan_duration': round(avg_duration, 1),
        'files_scanned_total': files_scanned
    }

def clear_quarantine():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT quarantine_path FROM quarantine_items")
    for row in cursor.fetchall():
        if os.path.exists(row['quarantine_path']):
            try:
                os.remove(row['quarantine_path'])
            except:
                pass
    cursor.execute("DELETE FROM quarantine_items")
    conn.commit()
    conn.close()

def delete_all_threats():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM detected_threats")
    conn.commit()
    conn.close()

init_database()