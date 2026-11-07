import random
from datetime import datetime, timedelta

import pandas as pd

random.seed(7)
inicio = datetime(2026, 10, 20, 8, 0)
filas = []


def add(ts, eid, user, ip, host, ltype="3", proc="", cmd="", action="Éxito", msg=""):
    filas.append({"timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"), "event_id": str(eid), "user": user,
                  "src_ip": ip, "host": host, "logon_type": ltype, "process": proc,
                  "command": cmd, "action": action, "message": msg})


# Tráfico normal
for _ in range(400):
    t = inicio + timedelta(minutes=random.randint(0, 60 * 48))
    add(t, 4624, random.choice(["jperez", "mlopez", "rgomez"]), f"10.0.1.{random.randint(10, 200)}",
        random.choice(["WS-FIN-01", "WS-RRHH-02"]), "2", msg="Inicio de sesión normal")
    if random.random() < 0.05:
        add(t, 4625, "jperez", f"10.0.1.{random.randint(10, 200)}", "WS-FIN-01", "2",
            action="Fallo", msg="Credenciales incorrectas")

# Fuerza bruta desde IP pública seguida de acceso exitoso
t0 = datetime(2026, 10, 21, 2, 13)
for i in range(18):
    add(t0 + timedelta(seconds=i * 20), 4625, "admin_it", "203.0.113.50", "SRV-DC-01", action="Fallo",
        msg="Credenciales incorrectas")
add(t0 + timedelta(minutes=7), 4624, "admin_it", "203.0.113.50", "SRV-DC-01", msg="Inicio de sesión")

# Comando codificado y movimiento lateral
add(t0 + timedelta(minutes=9), 4688, "admin_it", "10.0.1.99", "SRV-DC-01", proc="powershell.exe",
    cmd="powershell.exe -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA")
for i, host in enumerate(["SRV-FILE-01", "WS-RRHH-02", "WS-FIN-01"]):
    add(t0 + timedelta(minutes=12 + i * 2), 4624, "admin_it", "10.0.1.99", host, "3",
        proc="psexec.exe", cmd=f"psexec \\\\{host} cmd.exe")

# Borrado de logs
add(t0 + timedelta(minutes=30), 1102, "admin_it", "10.0.1.99", "SRV-DC-01", msg="Log de auditoría borrado")

df = pd.DataFrame(filas)
df.to_excel("siem_muestra.xlsx", index=False)
print(f"Generado siem_muestra.xlsx con {len(df)} registros")