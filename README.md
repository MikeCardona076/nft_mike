# 🔒 SSH Bruteforce Blocker - NFTables de Mike

## 📋 Descripción

Script en Python que protege servidores en la nube contra ataques de fuerza bruta por SSH. Mediante **Crontab** y **NFTables**, monitorea intentos fallidos de conexión y bloquea automáticamente las IPs maliciosas al tercer intento, agregándolas a una lista permanente de IPs bloqueadas.

## 🚀 Características Principales

- **🛡️ Protección Automática**: Detección y bloqueo en tiempo real
- **📊 Monitoreo Continuo**: Ejecución periódica via Crontab
- **🎯 Reglas NFTables**: Implementación eficiente de firewall
- **📈 Persistencia**: Lista mantenida de IPs bloqueadas
- **☁️ Optimizado para Cloud**: Diseñado específicamente para servidores en nube

## ⚙️ Como Funciona

1. **Monitoreo**: Analiza logs de SSH (`/var/log/auth.log` o `journalctl`)
2. **Detección**: Identifica múltiples intentos fallidos desde una misma IP
3. **Umbral**: Al **tercer intento fallido**, activa el bloqueo
4. **Bloqueo**: Agrega la IP a la cadena `ssh_blacklist` de NFTables
5. **Persistencia**: Mantiene registro de IPs bloqueadas para evitar duplicados

## 🛠️ Implementación

```bash
# Configuración en Crontab (ejemplo cada 5 minutos)
*/5 * * * * /usr/bin/python3 /ruta/al/script/ssh_blocker.py
