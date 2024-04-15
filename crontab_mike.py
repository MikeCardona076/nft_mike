#Comando para crear la tarea en Crontab y ejecutarse a las 2 am

sudo crontab -e

0 2 * * * sudo /usr/bin/python3 /home/mike/SGSI/tu_script.py
