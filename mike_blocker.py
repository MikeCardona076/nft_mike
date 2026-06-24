#!/usr/bin/env python3
"""
mike_blocker.py — Bloqueador que ejecuta crontab cada N minutos.

Detecta:
  - SSH brute force (leyendo /var/log/auth.log incrementalmente)
  - Bots/scanners (detectados por nftables rate limit)

Al superar el umbral, la IP se agrega a la set `banned` de nftables
y se registra en la base de datos SQLite.
"""

import configparser
import os
import re
import sqlite3
import subprocess
import sys
from collections import Counter
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(SCRIPT_DIR, 'mike_blocker.db')
CONF_PATH = os.path.join(SCRIPT_DIR, 'mike_blocker.conf')
AUTH_LOG = '/var/log/auth.log'
POS_KEY = 'auth_log_position'


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def get_state(conn, key, default=None):
    cur = conn.execute('SELECT value FROM state WHERE key = ?', (key,))
    row = cur.fetchone()
    return row['value'] if row else default


def set_state(conn, key, value):
    conn.execute('INSERT OR REPLACE INTO state (key, value) VALUES (?, ?)',
                 (key, str(value)))
    conn.commit()


def nft(args, check=False):
    if os.geteuid() != 0:
        cmd = ['sudo', 'nft']
    else:
        cmd = ['nft']
    cmd += args
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if check and r.returncode != 0:
            print(f'  nft error: {r.stderr.strip()}', file=sys.stderr)
        return r
    except subprocess.TimeoutExpired:
        print('  nft: timeout', file=sys.stderr)
        return subprocess.CompletedProcess(cmd, -1, '', 'timeout')


def ban_ip(ip, reason, attempts=0):
    now = datetime.now().isoformat()
    nft(['add', 'element', 'ip', 'blacklist', 'banned', ip], check=False)
    conn = get_db()
    conn.execute(
        'INSERT OR IGNORE INTO banned (ip, reason, attempts, blocked_at)'
        ' VALUES (?, ?, ?, ?)',
        (ip, reason, attempts, now)
    )
    conn.execute(
        'INSERT INTO log (ip, action, detail, created_at)'
        ' VALUES (?, ?, ?, ?)',
        (ip, 'blocked', reason, now)
    )
    conn.commit()
    conn.close()
    print(f'  Bloqueada: {ip} ({reason})')


def get_scanner_ips():
    r = nft(['list', 'set', 'ip', 'blacklist', 'scanners'])
    if r.returncode != 0:
        return []
    ips = set()
    pat = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    for line in r.stdout.split('\n'):
        ips.update(pat.findall(line))
    return sorted(ips)


def get_banned_ips():
    r = nft(['list', 'set', 'ip', 'blacklist', 'banned'])
    if r.returncode != 0:
        return []
    ips = set()
    pat = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    for line in r.stdout.split('\n'):
        ips.update(pat.findall(line))
    return sorted(ips)


def read_auth_log(conn):
    if not os.path.exists(AUTH_LOG):
        return []

    try:
        last_pos = int(get_state(conn, POS_KEY, '0'))
    except ValueError:
        last_pos = 0

    try:
        with open(AUTH_LOG, 'r') as f:
            f.seek(0, 2)
            size = f.tell()
            if size < last_pos:
                last_pos = 0
            f.seek(last_pos)
            lines = f.readlines()
            new_pos = f.tell()
        set_state(conn, POS_KEY, str(new_pos))
    except Exception as e:
        print(f'  Error leyendo {AUTH_LOG}: {e}', file=sys.stderr)
        return []

    pat = re.compile(r'from (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    ips = []
    for line in lines:
        if 'Failed password' in line:
            m = pat.search(line)
            if m:
                ips.append(m.group(1))
    return ips


def main():
    if not os.path.exists(CONF_PATH):
        print(f'Config no encontrado: {CONF_PATH}')
        print('Ejecuta primero: python3 mike_setup.py init')
        sys.exit(1)

    conf = configparser.ConfigParser()
    conf.read(CONF_PATH)
    ssh_threshold = int(conf.get('ssh', 'threshold', fallback='3'))
    conn = get_db()

    print(f'[{datetime.now().strftime("%H:%M:%S")}] NFT Blocker Lite')

    print('  Leyendo intentos SSH...')
    attempts = read_auth_log(conn)
    if attempts:
        counts = Counter(attempts)
        for ip, n in counts.items():
            cur = conn.execute('SELECT 1 FROM whitelist WHERE ip = ?', (ip,))
            if cur.fetchone():
                continue
            cur = conn.execute('SELECT 1 FROM banned WHERE ip = ?', (ip,))
            if cur.fetchone():
                continue
            conn.execute(
                'INSERT INTO log (ip, action, detail, created_at)'
                ' VALUES (?, ?, ?, ?)',
                (ip, 'ssh_attempt', str(n), datetime.now().isoformat())
            )
            cur = conn.execute(
                "SELECT COUNT(*) as cnt FROM log"
                " WHERE ip = ? AND action = 'ssh_attempt'"
                " AND created_at >= datetime('now', '-1 hour')",
                (ip,)
            )
            total = cur.fetchone()['cnt']
            print(f'    {ip}: {total} intentos (umbral: {ssh_threshold})')
            if total >= ssh_threshold:
                ban_ip(ip, 'ssh', total)
        conn.commit()
    else:
        print('  Sin intentos nuevos')

    print('  Revisando scanners en nftables...')
    for ip in get_scanner_ips():
        cur = conn.execute('SELECT 1 FROM whitelist WHERE ip = ?', (ip,))
        if cur.fetchone():
            continue
        cur = conn.execute('SELECT 1 FROM banned WHERE ip = ?', (ip,))
        if cur.fetchone():
            nft(['add', 'element', 'ip', 'blacklist', 'banned', ip], check=False)
            continue
        ban_ip(ip, 'scanner')
    else:
        print('    Sin scanners nuevos')

    conn.close()
    print('  Listo')


if __name__ == '__main__':
    main()
