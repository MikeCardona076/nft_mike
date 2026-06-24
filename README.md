# NFT Blocker Lite

Protege servidores Linux contra ataques SSH brute force y bots/scanners usando **NFTables** + **SQLite**.

Ligero, sin dependencias externas (solo Python stdlib + nftables).

## Requisitos

- Linux con nftables (`apt install nftables` / `yum install nftables`)
- Python 3.6+
- Acceso sudo (sin contraseña para nft)

## Instalacion (un solo comando)

```bash
# 1. Editar config (whitelist, umbrales)
nano mike_blocker.conf

# 2. Configurar todo
sudo python3 mike_setup.py init
```

Esto crea:
- Tabla `blacklist` en nftables con whitelist, banned y deteccion de scanners
- Base de datos SQLite (`mike_blocker.db`)
- Carga whitelist desde el config
- Instala crontab (cada 5 min)

## Comandos

| Comando | Descripcion |
|---------|-------------|
| `init` | Setup completo (nftables, DB, whitelist, crontab) |
| `init --no-cron` | Setup sin crontab |
| `status` | Estado del sistema: baneos, intentos, whitelist |
| `whitelist list` | Listar IPs en whitelist |
| `whitelist add <IP> [desc]` | Agregar IP a whitelist |
| `whitelist del <IP>` | Eliminar IP de whitelist |
| `unban <IP>` | Desbloquear una IP |
| `unban --all` | Desbloquear todas |
| `cron install` | Instalar tarea crontab |
| `cron remove` | Quitar tarea crontab |
| `purge` | Desinstalar todo (nftables, DB, opcional config) |

## Como funciona

### nftables (kernel)

```
chain input:
  1. Whitelist -> aceptar
  2. Baneados -> dropear
  3. >10 conexiones/min desde misma IP -> ban automatico + drop
  4. Scanners detectados -> dropear
```

### Blocker (crontab cada 5 min)

1. Lee `/var/log/auth.log` incrementalmente
2. Cuenta intentos SSH fallidos por IP
3. Si supera umbral (default 3) -> bloquea en nftables + registra en SQLite
4. Detecta IPs en la set `scanners` de nftables (rate limit)
5. Las registra en DB y asegura que esten en `banned`

### SQLite

- `whitelist` — IPs que nunca se bloquean
- `banned` — IPs bloqueadas con motivo y fecha
- `log` — historial de intentos y bloqueos
- `state` — estado interno (posicion en auth.log)

## Archivos

```
mike_blocker.conf   Configuracion (whitelist, umbrales)
mike_setup.py       CLI de administracion
mike_blocker.py     Blocker (ejecutado por crontab)
mike_blocker.db     Base de datos SQLite
```
