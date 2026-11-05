# Saves scan results using SQLite.
import sqlite3
import json
from datetime import datetime
from pathlib import Path

DATABASE = Path(__file__).with_name('asm_scans.db')


def setup_database():
    with sqlite3.connect(DATABASE) as connection:
        connection.execute('''CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            date TEXT NOT NULL,
            target TEXT NOT NULL,
            host TEXT NOT NULL,
            ports TEXT NOT NULL,
            findings TEXT NOT NULL,
            openvas_status TEXT NOT NULL
        )''')


def save_scan(target, host, ports, findings, openvas_status):
    with sqlite3.connect(DATABASE) as connection:
        cursor = connection.execute('''INSERT INTO scans
            (date, target, host, ports, findings, openvas_status)
            VALUES (?, ?, ?, ?, ?, ?)''',
            (datetime.now().strftime('%Y-%m-%d %I:%M %p'),
             target, host, json.dumps(ports), json.dumps(findings), openvas_status))
        return cursor.lastrowid


def get_scans():
    with sqlite3.connect(DATABASE) as connection:
        rows = connection.execute('SELECT * FROM scans ORDER BY id DESC').fetchall()
    return [{'id': row[0], 'date': row[1], 'target': row[2],
             'host': row[3], 'ports': json.loads(row[4]),
             'findings': json.loads(row[5]), 'openvas_status': row[6]}
            for row in rows]


def delete_scan(scan_id):
    with sqlite3.connect(DATABASE) as connection:
        connection.execute('DELETE FROM scans WHERE id = ?', (scan_id,))

