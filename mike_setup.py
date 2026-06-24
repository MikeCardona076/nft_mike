#!/usr/bin/env python3
"""
mike_setup.py — CLI de configuración única para NFT Blocker Lite.

Ejecutar una sola vez para configurar todo:
    sudo python3 mike_setup.py init

Comandos disponibles:
    init        Setup completo: nftables, SQLite, whitelist, crontab
    whitelist   Gestionar lista blanca
    unban       Desbloquear IPs
    status      Mostrar estado del sistema
    cron        Instalar/remover crontab
    purge       Desinstalar todo
"""

import argparse
import configparser
import json
import os
import re
import sqlite3
import subprocess
import sys
from datetime import datetime

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_FILE = os.path.join(SCRIPT_DIR, 'mike_blocker.db')
CONF_FILE = os.path.join(SCRIPT_DIR, 'mike_blocker.conf')
BLOCKER_FILE = os.path.join(SCRIPT_DIR, 'mike_blocker.py')
CRON_TAG = '# mike_blocker'


def nft(args, check=False):
    if os.geteuid() != 0:
        cmd = ['sudo', 'nft']
    else:
        cmd = ['nft']
    cmd += args
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    if check and r.returncode != 0:
        print(f'  nft error: {r.stderr.strip()}')
    return r


def table_exists():
    r = nft(['list', 'table', 'ip', 'blacklist'], check=False)
    return r.returncode == 0 and 'table ip blacklist' in r.stdout


def ensure_table():
    if not table_exists():
        print('  Creando tabla blacklist...')
        nft(['add', 'table', 'ip', 'blacklist'], check=True)
    else:
        print('  Tabla blacklist ya existe')


SET_DEFS = {
    'whitelist': ['{', 'type', 'ipv4_addr', ';', '}'],
    'banned': ['{', 'type', 'ipv4_addr', ';', '}'],
    'scanners': ['{', 'type', 'ipv4_addr', ';', 'flags', 'dynamic,',
                  'timeout', ';', 'timeout', '10m', ';', '}'],
}


def set_exists(name):
    r = nft(['list', 'set', 'ip', 'blacklist', name], check=False)
    return r.returncode == 0 and name in r.stdout


def ensure_sets():
    for name, definition in SET_DEFS.items():
        if not set_exists(name):
            print(f'  Creando set {name}...')
            nft(['add', 'set', 'ip', 'blacklist', name] + definition, check=True)
        else:
            print(f'  Set {name} ya existe')


def chain_exists():
    r = nft(['list', 'chain', 'ip', 'blacklist', 'input'], check=False)
    return r.returncode == 0 and 'chain input' in r.stdout


def ensure_chain():
    if not chain_exists():
        print('  Creando chain input...')
        nft(['add', 'chain', 'ip', 'blacklist', 'input', '{',
             'type', 'filter', 'hook', 'input', 'priority', '0', ';',
             'policy', 'accept', ';', '}'], check=True)
    else:
        print('  Chain input ya existe')


RULES = [
    ('ip saddr @whitelist accept',
     'Saltar whitelist'),
    ('ip saddr @banned drop',
     'Bloquear IPs baneadas'),
    ('tcp flags syn add @scanners { ip saddr limit rate over 10/minute }'
     ' add @banned drop',
     'Deteccion de scanners + ban automatico'),
    ('ip saddr @scanners drop',
     'Bloquear scanners identificados'),
]


def rules_exist():
    r = nft(['list', 'chain', 'ip', 'blacklist', 'input'], check=False)
    if r.returncode != 0:
        return False
    return 'ip saddr @whitelist accept' in r.stdout


def ensure_rules():
    if rules_exist():
        print('  Reglas ya existen')
        return
    for rule_text, desc in RULES:
        print(f'  Agregando regla: {desc}')
        tokens = rule_text.split()
        nft(['add', 'rule', 'ip', 'blacklist', 'input'] + tokens, check=True)


def nft_add_to_set(set_name, ips):
    if not ips:
        return
    for ip in ips:
        nft(['add', 'element', 'ip', 'blacklist', set_name, ip], check=False)


def nft_delete_from_set(set_name, ip):
    nft(['delete', 'element', 'ip', 'blacklist', set_name, ip], check=False)


def nft_get_set_elements(set_name):
    r = nft(['list', 'set', 'ip', 'blacklist', set_name], check=False)
    if r.returncode != 0:
        return []
    ips = set()
    ip_pattern = re.compile(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b')
    for line in r.stdout.split('\n'):
        ips.update(ip_pattern.findall(line))
    return sorted(ips)


def delete_table():
    nft(['delete', 'table', 'ip', 'blacklist'], check=False)


def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA journal_mode=WAL')
    return conn


def init_db():
    conn = sqlite3.connect(DB_FILE)
    conn.execute('PRAGMA journal_mode=WAL')
    conn.executescript('''
        CREATE TABLE IF NOT EXISTS whitelist (
            ip TEXT PRIMARY KEY,
            description TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS banned (
            ip TEXT PRIMARY KEY,
            reason TEXT,
            attempts INTEGER DEFAULT 0,
            blocked_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ip TEXT NOT NULL,
            action TEXT NOT NULL,
            detail TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        );
    ''')
    conn.commit()
    conn.close()


def check_prerequisites():
    ok = True
    r = subprocess.run(['which', 'nft'], capture_output=True, text=True)
    if r.returncode != 0:
        r = subprocess.run(['command', '-v', 'nft'], capture_output=True, text=True)
    if r.returncode != 0:
        print('ERROR: nft no esta instalado. Instalalo con:')
        print('  apt install nftables  (Debian/Ubuntu)')
        print('  yum install nftables  (CentOS/RHEL)')
        ok = False

    try:
        if os.geteuid() != 0:
            r = subprocess.run(['sudo', '-n', 'true'], capture_output=True, text=True)
            if r.returncode != 0:
                print('ERROR: se requiere sudo sin contrasena para nft')
                ok = False
    except Exception:
        print('ERROR: no se pudo verificar permisos sudo')
        ok = False

    return ok


def install_cron(interval):
    cron_line = (f'*/{interval} * * * * cd {SCRIPT_DIR} &&'
                 f' /usr/bin/python3 {BLOCKER_FILE} >/dev/null 2>&1 {CRON_TAG}')
    r = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
    existing = r.stdout if r.returncode == 0 else ''
    if CRON_TAG in existing:
        lines = [l for l in existing.split('\n') if CRON_TAG not in l]
        existing = '\n'.join(lines)
    new_cron = existing.strip() + '\n' + cron_line + '\n'
    p = subprocess.run(['crontab'], input=new_cron, text=True,
                       capture_output=True, timeout=10)
    if p.returncode == 0:
        print(f'  Crontab instalado (cada {interval} min)')
    else:
        print(f'  No se pudo instalar crontab: {p.stderr.strip()}')
        print(f'  Instalalo manualmente:')
        print(f'    (crontab -l 2>/dev/null; echo "{cron_line}") | crontab -')


def remove_cron():
    r = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
    if r.returncode != 0:
        print('  No hay crontab configurado')
        return
    lines = [l for l in r.stdout.split('\n') if CRON_TAG not in l]
    new_cron = '\n'.join(lines).strip()
    if new_cron:
        p = subprocess.run(['crontab'], input=new_cron + '\n',
                           text=True, capture_output=True, timeout=10)
    else:
        p = subprocess.run(['crontab', '-r'], capture_output=True, text=True, timeout=10)
    if p.returncode == 0:
        print('  Crontab eliminado')
    else:
        print(f'  Error: {p.stderr.strip()}')


def load_whitelist_from_conf():
    conf = configparser.ConfigParser()
    conf.read(CONF_FILE)
    ips = []
    if conf.has_section('whitelist'):
        for ip in conf.options('whitelist'):
            ip = ip.strip()
            if ip:
                ips.append(ip)
    return ips


def sync_whitelist_to_nftables(conn):
    cur = conn.execute('SELECT ip FROM whitelist')
    db_ips = [r['ip'] for r in cur.fetchall()]
    nft_ips = nft_get_set_elements('whitelist')
    to_add = [ip for ip in db_ips if ip not in nft_ips]
    to_remove = [ip for ip in nft_ips if ip not in db_ips]
    if to_add:
        nft_add_to_set('whitelist', to_add)
    if to_remove:
        for ip in to_remove:
            nft_delete_from_set('whitelist', ip)
    return len(db_ips)


def sync_bans_to_nftables(conn):
    cur = conn.execute('SELECT ip FROM banned')
    db_ips = [r['ip'] for r in cur.fetchall()]
    nft_ips = nft_get_set_elements('banned')
    to_add = [ip for ip in db_ips if ip not in nft_ips]
    if to_add:
        nft_add_to_set('banned', to_add)
    return len(db_ips)


def record_bans_from_nftables(conn):
    nft_ips = nft_get_set_elements('banned')
    now = datetime.now().isoformat()
    for ip in nft_ips:
        cur = conn.execute('SELECT 1 FROM banned WHERE ip = ?', (ip,))
        if not cur.fetchone():
            conn.execute(
                'INSERT OR IGNORE INTO banned (ip, reason, attempts, blocked_at)'
                ' VALUES (?, ?, ?, ?)',
                (ip, 'scanner', 0, now)
            )
            conn.execute(
                'INSERT INTO log (ip, action, detail, created_at)'
                ' VALUES (?, ?, ?, ?)',
                (ip, 'blocked', 'scanner', now)
            )
    conn.commit()


def cmd_init(args):
    print('NFT Blocker Lite — Inicializacion\n')

    if not check_prerequisites():
        sys.exit(1)

    if not os.path.exists(CONF_FILE):
        print('Config default no encontrado, creando...')
        default_conf = '''[ssh]
threshold = 3

[scan]
conn_rate = 10

[cron]
interval = 5

[whitelist]
; IPs o redes que nunca seran bloqueadas
; Formato: IP = descripcion
'''
        with open(CONF_FILE, 'w') as f:
            f.write(default_conf)
        print(f'  Creado {CONF_FILE}')
    else:
        print(f'  Config: {CONF_FILE}')

    print('\nConfigurando NFTables...')
    ensure_table()
    ensure_sets()
    ensure_chain()
    ensure_rules()

    print('\nInicializando base de datos...')
    db_exists = os.path.exists(DB_FILE)
    init_db()
    print(f'  {"Base de datos creada" if not db_exists else "Base de datos ya existe"}')

    conn = get_db()

    print('\nCargando whitelist desde config...')
    conf_ips = load_whitelist_from_conf()
    for ip in conf_ips:
        conn.execute('INSERT OR IGNORE INTO whitelist (ip, description) VALUES (?, ?)',
                     (ip, 'config'))
    conn.commit()
    wl_count = sync_whitelist_to_nftables(conn)
    print(f'  {wl_count} IP(s) en whitelist')

    print('\nSincronizando baneos existentes...')
    record_bans_from_nftables(conn)
    ban_count = sync_bans_to_nftables(conn)
    print(f'  {ban_count} IP(s) baneadas en nftables')

    conn.close()

    print('\nConfigurando crontab...')
    if args.no_cron:
        print('  Omitido (--no-cron)')
    else:
        conf = configparser.ConfigParser()
        conf.read(CONF_FILE)
        interval = int(conf.get('cron', 'interval', fallback='5'))
        install_cron(interval)

    print('\nInicializacion completada\n')
    print('  nftables:    tabla blacklist activa')
    print(f'  Base datos:  {DB_FILE}')
    print('  Crontab:     instalado' if not args.no_cron else '  Crontab:     no instalado')
    print()
    print('Proximos pasos:')
    print('  python3 mike_setup.py status          — Ver estado')
    print('  python3 mike_setup.py whitelist add IP — Agregar IP a whitelist')
    print('  python3 mike_setup.py unban IP        — Desbloquear IP')
    print('  python3 mike_setup.py purge           — Desinstalar todo')


def cmd_whitelist(args):
    conn = get_db()
    if args.action == 'list':
        cur = conn.execute('SELECT ip, description, created_at FROM whitelist ORDER BY ip')
        rows = cur.fetchall()
        if not rows:
            print('Whitelist: vacia')
        else:
            print('Whitelist:')
            for r in rows:
                desc = f' — {r["description"]}' if r['description'] else ''
                print(f'  {r["ip"]}{desc}')
    elif args.action == 'add':
        if not args.ip:
            print('Uso: whitelist add <IP> [descripcion]')
            conn.close()
            return
        conn.execute('INSERT OR IGNORE INTO whitelist (ip, description) VALUES (?, ?)',
                     (args.ip, args.desc or ''))
        conn.commit()
        nft_add_to_set('whitelist', [args.ip])
        print(f'IP {args.ip} agregada a whitelist')
    elif args.action == 'del':
        if not args.ip:
            print('Uso: whitelist del <IP>')
            conn.close()
            return
        conn.execute('DELETE FROM whitelist WHERE ip = ?', (args.ip,))
        conn.commit()
        nft_delete_from_set('whitelist', args.ip)
        print(f'IP {args.ip} eliminada de whitelist')
    conn.close()


def cmd_unban(args):
    conn = get_db()
    if args.all:
        cur = conn.execute('SELECT ip FROM banned')
        ips = [r['ip'] for r in cur.fetchall()]
        for ip in ips:
            nft_delete_from_set('banned', ip)
        conn.execute('DELETE FROM banned')
        conn.execute("INSERT INTO log (ip, action, detail) VALUES (?, ?, ?)",
                     ('*', 'unblocked_all', f'{len(ips)} IPs'))
        conn.commit()
        print(f'{len(ips)} IP(s) desbloqueadas')
    else:
        if not args.ip:
            print('Uso: unban <IP>  o  unban --all')
            conn.close()
            return
        conn.execute('DELETE FROM banned WHERE ip = ?', (args.ip,))
        conn.execute("INSERT INTO log (ip, action, detail) VALUES (?, ?, ?)",
                     (args.ip, 'unblocked', 'manual'))
        conn.commit()
        nft_delete_from_set('banned', args.ip)
        print(f'IP {args.ip} desbloqueada')
    conn.close()


def cmd_status(args):
    conn = get_db()

    print('NFT Blocker Lite — Estado\n')

    if table_exists():
        r = nft(['list', 'chain', 'ip', 'blacklist', 'input'], check=False)
        rules_n = r.stdout.count(';') if r.returncode == 0 else 0
        print(f'nftables: activa ({rules_n} reglas)')
    else:
        print('nftables: NO CONFIGURADA — ejecuta: python3 mike_setup.py init')

    for sname, label in [('whitelist', 'Whitelist'),
                         ('banned', 'Baneadas'),
                         ('scanners', 'Scanners activos')]:
        elements = nft_get_set_elements(sname)
        print(f'  {label}: {len(elements)}')

    print()

    cur = conn.execute("SELECT reason, COUNT(*) as cnt FROM banned"
                       " GROUP BY reason")
    print('Baneos por tipo:')
    total_bans = 0
    for r in cur.fetchall():
        print(f'  {r["reason"]}: {r["cnt"]}')
        total_bans += r['cnt']
    if total_bans == 0:
        print('  (ninguno)')

    cur = conn.execute(
        "SELECT COUNT(*) as cnt FROM log"
        " WHERE action = 'blocked' AND created_at >= date('now')"
    )
    today = cur.fetchone()['cnt']
    cur = conn.execute(
        "SELECT COUNT(*) as cnt FROM log WHERE action = 'blocked'"
    )
    total = cur.fetchone()['cnt']
    print(f'\nBloqueos hoy: {today}  |  totales: {total}')

    cur = conn.execute(
        "SELECT ip, COUNT(*) as cnt FROM log"
        " WHERE action = 'ssh_attempt'"
        " GROUP BY ip ORDER BY cnt DESC LIMIT 5"
    )
    rows = cur.fetchall()
    if rows:
        print('\nTop intentos SSH:')
        for r in rows:
            print(f'  {r["ip"]}: {r["cnt"]}')

    cur = conn.execute('SELECT COUNT(*) as cnt FROM whitelist')
    print(f'\nWhitelist: {cur.fetchone()["cnt"]} IP(s)')

    r = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=10)
    print(f'Crontab: {"instalado" if CRON_TAG in r.stdout else "NO instalado"}')

    conn.close()


def cmd_cron(args):
    if args.action == 'install':
        conf = configparser.ConfigParser()
        conf.read(CONF_FILE)
        interval = int(conf.get('cron', 'interval', fallback='5'))
        install_cron(interval)
    elif args.action == 'remove':
        remove_cron()


def cmd_purge(args):
    print('Purge — Desinstalacion completa\n')
    resp = input('Eliminar nftables, DB y config? [s/N]: ')
    if resp.lower() not in ('s', 'si', 'y', 'yes'):
        print('Cancelado.')
        return

    remove_cron()

    if table_exists():
        print('  Eliminando tabla nftables...')
        delete_table()

    for f in [DB_FILE]:
        if os.path.exists(f):
            os.remove(f)
            print(f'  Eliminado {f}')

    if os.path.exists(CONF_FILE):
        if input('Eliminar tambien mike_blocker.conf? [s/N]: ').lower() in ('s', 'si'):
            os.remove(CONF_FILE)
            print(f'  Eliminado {CONF_FILE}')

    print('\nDesinstalacion completada')


def main():
    parser = argparse.ArgumentParser(
        description='NFT Blocker Lite — Configuracion y administracion',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  python3 mike_setup.py init            Configuracion completa
  python3 mike_setup.py init --no-cron  Sin crontab
  python3 mike_setup.py status          Ver estado
  python3 mike_setup.py whitelist add 192.168.1.100 "Admin"
  python3 mike_setup.py unban 10.0.0.5
  python3 mike_setup.py unban --all     Desbloquear todos
  python3 mike_setup.py cron remove     Quitar crontab
  python3 mike_setup.py purge           Desinstalar todo
        """)

    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('init', help='Setup completo: nftables, DB, whitelist, crontab')
    p.add_argument('--no-cron', action='store_true', help='No instalar crontab')
    p.set_defaults(func=cmd_init)

    p = sub.add_parser('whitelist', help='Gestionar whitelist')
    p.add_argument('action', nargs='?', choices=['list', 'add', 'del'], default='list')
    p.add_argument('ip', nargs='?', default=None)
    p.add_argument('desc', nargs='?', default='')
    p.set_defaults(func=cmd_whitelist)

    p = sub.add_parser('unban', help='Desbloquear IP(s)')
    p.add_argument('ip', nargs='?', default=None)
    p.add_argument('--all', action='store_true', help='Desbloquear todas')
    p.set_defaults(func=cmd_unban)

    p = sub.add_parser('status', help='Mostrar estado del sistema')
    p.set_defaults(func=cmd_status)

    p = sub.add_parser('cron', help='Gestionar tarea crontab')
    p.add_argument('action', choices=['install', 'remove'])
    p.set_defaults(func=cmd_cron)

    p = sub.add_parser('purge', help='Desinstalar todo')
    p.set_defaults(func=cmd_purge)

    args = parser.parse_args()
    args.func(args)


if __name__ == '__main__':
    main()
