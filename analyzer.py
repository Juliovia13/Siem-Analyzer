import ipaddress
import re
import warnings

import pandas as pd

COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "@timestamp", "timecreated", "date", "fecha", "hora", "date and time"],
    "event_id": ["event_id", "eventid", "event id", "id", "evento", "event code"],
    "user": ["user", "username", "account", "account name", "usuario", "subjectusername", "targetusername", "target user name"],
    "src_ip": ["src_ip", "source ip", "source_ip", "ip origen", "sourceaddress", "ip address", "client ip", "src", "ip"],
    "host": ["host", "hostname", "computer", "equipo", "workstation", "dest host"],
    "process": ["process", "process name", "image", "newprocessname", "proceso"],
    "command": ["command", "commandline", "command line", "cmdline", "comando", "process command line",
                "process commandline", "process_commandline"],
    "action": ["action", "result", "status", "estado", "resultado", "outcome"],
    "logon_type": ["logon type", "logon_type", "logontype", "tipo de logon"],
    "message": ["message", "description", "mensaje", "descripcion", "raw", "details",
                "event description", "event_description"],
}

FAILED_IDS = {"4625", "529", "530", "531", "532", "533", "534", "535", "537", "539"}
SUCCESS_IDS = {"4624", "528"}
FAIL_WORDS = ("fail", "fallo", "denied", "denegad", "invalid", "incorrect")
SUCCESS_WORDS = ("success", "éxito", "exito", "accepted", "aceptad")
# Evita advertencias de pandas por los grupos de captura en los patrones de comandos
warnings.filterwarnings("ignore", message=".*has match groups.*")

SEVERITY_ORDER = {"Bajo": 1, "Medio": 2, "Alto": 3, "Crítico": 4}

SUSPICIOUS_COMMANDS = [
    (r"-enc(odedcommand)?\s", "PowerShell codificado en Base64", "Alto", "T1059.001"),
    (r"mimikatz|sekurlsa|lsadump", "Herramienta de robo de credenciales (Mimikatz)", "Crítico", "T1003"),
    (r"certutil.*-urlcache|bitsadmin.*/transfer", "Descarga con utilidades nativas del sistema", "Alto", "T1105"),
    (r"vssadmin.*delete|wbadmin.*delete|bcdedit.*recoveryenabled", "Borrado de copias de respaldo o recuperación", "Crítico", "T1490"),
    (r"net\s+user\s+.*/add|net\s+localgroup\s+administrators.*/add", "Creación de cuenta o escalada de privilegios", "Alto", "T1136"),
    (r"reg(\.exe)?\s+add.*\\run", "Persistencia en clave Run del registro", "Alto", "T1547.001"),
    (r"schtasks.*/create", "Creación de tarea programada", "Medio", "T1053.005"),
    (r"wevtutil.*\bcl\b|clear-eventlog", "Borrado de logs de eventos", "Crítico", "T1070.001"),
    (r"psexec|wmic.*process.*call.*create|winrm|invoke-command", "Ejecución remota (posible movimiento lateral)", "Alto", "T1021"),
    (r"whoami\s*/priv|nltest|domain admins", "Reconocimiento de dominio o privilegios", "Medio", "T1087"),
    (r"get-localgroupmember|get-smbshare|net(\.exe)?\s+view", "Enumeración de grupos, recursos compartidos o red", "Medio", "T1135"),
    (r"\b7z(\.exe)?\s+a\s|\btar(\.exe)?\s.*-a\s", "Compresión de datos para posible exfiltración", "Alto", "T1560.001"),
    (r"\bnmap\b|netstat\s+-an|arp\s+-a", "Reconocimiento de red", "Medio", "T1046"),
]

EVENT_RULES = {
    "1102": ("Borrado del registro de auditoría de seguridad", "Crítico", "Evasión de defensas", "T1070.001"),
    "104": ("Borrado de un log de eventos", "Crítico", "Evasión de defensas", "T1070.001"),
    "7045": ("Instalación de servicio nuevo", "Alto", "Persistencia", "T1543.003"),
    "4698": ("Tarea programada creada", "Medio", "Persistencia", "T1053.005"),
    "4720": ("Cuenta de usuario creada", "Medio", "Persistencia", "T1136.001"),
    "4732": ("Usuario agregado a grupo de seguridad", "Alto", "Escalada de privilegios", "T1098"),
    "4672": ("Privilegios especiales asignados a una sesión", "Medio", "Escalada de privilegios", "T1078"),
}


def load_table(ruta):
    if ruta.lower().endswith(".csv"):
        return pd.read_csv(ruta, dtype=str, keep_default_na=False)
    hojas = pd.read_excel(ruta, sheet_name=None, dtype=str, keep_default_na=False)
    return pd.concat(hojas.values(), ignore_index=True)


def normalize(raw):
    df = raw.copy()
    df.columns = [str(c) for c in df.columns]
    mapping, used = {}, set()
    for std, aliases in COLUMN_ALIASES.items():
        names = {a.replace("_", " ") for a in aliases}
        for col in df.columns:
            if col not in used and col.strip().lower().replace("_", " ") in names:
                mapping[col] = std
                used.add(col)
                break
    df = df.rename(columns=mapping)
    for std in COLUMN_ALIASES:
        if std not in df.columns:
            df[std] = ""
    df = df[list(COLUMN_ALIASES)].fillna("").astype(str)

    # Si el SIEM no trae columna de tipo de logon, se extrae del texto del evento (LogonType=3, LogonType=10...)
    extraido = df["message"].str.extract(r"LogonType=(\d+)", expand=False).fillna("")
    df["logon_type"] = df["logon_type"].where(df["logon_type"] != "", extraido)

    df["ts"] = pd.to_datetime(df["timestamp"], errors="coerce")
    return df


REDES_INTERNAS = [
    ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                      "127.0.0.0/8", "169.254.0.0/16")
]


def is_external(ip):
    # No usamos ip.is_private: Python lo marca True para rangos de documentación
    # (192.0.2.x, 198.51.100.x, 203.0.113.x), que en el laboratorio hacen de IP pública.
    try:
        addr = ipaddress.ip_address(ip.strip())
    except ValueError:
        return False
    return not any(addr in red for red in REDES_INTERNAS)


def outcome(row):
    eid = row["event_id"].strip()
    txt = f"{row['action']} {row['message']}".lower()
    if eid in FAILED_IDS or any(w in txt for w in FAIL_WORDS):
        return "fallo"
    if eid in SUCCESS_IDS or any(w in txt for w in SUCCESS_WORDS):
        return "exito"
    return "otro"


def _finding(rows, title, category, severity, description, entities, mitre=""):
    ts = rows["ts"].dropna()
    return {
        "title": title,
        "category": category,
        "severity": severity,
        "description": description,
        "count": int(len(rows)),
        "first_seen": str(ts.min()) if len(ts) else "N/D",
        "last_seen": str(ts.max()) if len(ts) else "N/D",
        "entities": sorted({e for e in entities if e})[:15],
        "mitre": mitre,
        "evidence": rows.head(5)[["timestamp", "user", "src_ip", "host", "event_id", "command"]]
        .astype(str).to_dict("records"),
    }


def detect_bruteforce(df, umbral=10, ventana="10min"):
    out = []
    fallos = df[(df["result"] == "fallo") & df["ts"].notna() & (df["src_ip"] != "")].sort_values("ts")
    for ip, g in fallos.groupby("src_ip"):
        if len(g) < umbral:
            continue
        conteo = pd.Series(1, index=pd.DatetimeIndex(g["ts"])).rolling(ventana).sum()
        if conteo.max() < umbral:
            continue
        fin = conteo.idxmax()
        ventana_rows = g[(g["ts"] <= fin) & (g["ts"] > fin - pd.Timedelta(ventana))]
        exitos = df[(df["result"] == "exito") & (df["src_ip"] == ip) & df["ts"].notna()
                    & (df["ts"] >= fin) & (df["ts"] <= fin + pd.Timedelta("30min"))]
        base_desc = f"{int(conteo.max())} fallos de autenticación en {ventana} desde {ip}."
        if len(exitos):
            out.append(_finding(
                pd.concat([ventana_rows, exitos]),
                f"Fuerza bruta seguida de acceso exitoso desde {ip}",
                "Acceso inicial / Credenciales", "Crítico",
                base_desc + f" Hubo {len(exitos)} inicio(s) de sesión exitoso(s) en los 30 minutos siguientes: posible compromiso de credenciales.",
                list(g["user"].unique()) + list(exitos["user"].unique()), "T1110"))
        else:
            out.append(_finding(
                ventana_rows, f"Posible fuerza bruta desde {ip}",
                "Acceso inicial / Credenciales", "Alto",
                base_desc + " No se observó un inicio exitoso posterior, pero el patrón es característico de un ataque de adivinación de contraseñas.",
                list(g["user"].unique()), "T1110"))
    return out


def detect_external_logins(df):
    ext = df[(df["result"] == "exito") & df["src_ip"].map(is_external)]
    return [
        _finding(g, f"Inicio de sesión exitoso desde IP pública {ip}", "Acceso inicial", "Alto",
                 f"Se registraron {len(g)} inicios de sesión exitosos desde una dirección pública. En entornos internos esto no es esperado y debe validarse.",
                 list(g["user"].unique()), "T1078")
        for ip, g in ext.groupby("src_ip")
    ]


def detect_off_hours(df):
    ok = df[(df["result"] == "exito") & df["ts"].notna()]
    h = ok["ts"].dt.hour
    fuera = ok[(h < 6) | (h >= 22)]
    out = []
    for user, g in fuera.groupby("user"):
        if not user or user in ("-", ""):
            continue
        out.append(_finding(g, f"Inicio de sesión fuera de horario: {user}", "Anomalía de comportamiento", "Medio",
                            f"La cuenta {user} tuvo {len(g)} inicios de sesión entre las 22:00 y las 06:00.",
                            [user], "T1078"))
    return out


def detect_commands(df):
    out = []
    texto = df["command"] + " " + df["process"] + " " + df["message"]
    for pat, desc, sev, mitre in SUSPICIOUS_COMMANDS:
        m = df[texto.str.contains(pat, flags=re.IGNORECASE, regex=True, na=False)]
        if len(m):
            out.append(_finding(m, desc, "Ejecución de comandos", sev,
                                f"Se detectaron {len(m)} eventos que coinciden con el patrón: {desc.lower()}.",
                                list(m["host"].unique()) + list(m["user"].unique()), mitre))
    return out


def detect_lateral(df, min_hosts=3):
    ok = df[(df["result"] == "exito") & df["logon_type"].isin(["3", "10"]) & df["ts"].notna() & (df["user"] != "")]
    out = []
    for user, g in ok.groupby("user"):
        por_ventana = g.set_index("ts")["host"].resample("15min").nunique()
        if por_ventana.max() >= min_hosts:
            out.append(_finding(g, f"Posible movimiento lateral con la cuenta {user}", "Movimiento lateral", "Alto",
                                f"La cuenta {user} inició sesiones remotas (tipo 3/10) en {int(por_ventana.max())} hosts distintos dentro de 15 minutos.",
                                list(g["host"].unique()) + [user], "T1021"))
    return out


def detect_exfiltration(df, umbral_bytes=10_000_000):
    texto = df["command"] + " " + df["message"]
    bytes_out = pd.to_numeric(texto.str.extract(r"bytes_out=(\d+)", expand=False), errors="coerce")
    grandes = df[bytes_out.fillna(0) > 0].copy()
    grandes["bytes"] = bytes_out[grandes.index]
    out = []
    for ip, g in grandes.groupby("src_ip"):
        total = int(g["bytes"].sum())
        if total >= umbral_bytes:
            out.append(_finding(g, f"Transferencia saliente de datos desde {ip}", "Exfiltración", "Alto",
                                f"Se registraron {len(g)} transferencias salientes que suman {total / 1_000_000:.1f} MB. Revisar si el volumen corresponde a datos sensibles.",
                                list(g["user"].unique()) + [ip], "T1041"))
    return out


def detect_events(df):
    out = []
    for eid, (title, sev, cat, mitre) in EVENT_RULES.items():
        m = df[df["event_id"] == eid]
        if len(m):
            out.append(_finding(m, title, cat, sev,
                                f"Se registraron {len(m)} eventos con ID {eid}: {title.lower()}.",
                                list(m["host"].unique()) + list(m["user"].unique()), mitre))
    return out


def analyze(raw_df):
    df = normalize(raw_df)
    df["result"] = df.apply(outcome, axis=1)

    findings = []
    for det in (detect_bruteforce, detect_external_logins, detect_off_hours,
                detect_commands, detect_lateral, detect_exfiltration, detect_events):
        findings += det(df)
    findings.sort(key=lambda f: -SEVERITY_ORDER[f["severity"]])

    entidades = {e for f in findings for e in f["entities"]}
    ext_ips = sorted({ip for ip in df["src_ip"].unique() if ip and is_external(ip)})
    sev_counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev_counts[f["severity"]] += 1

    return {
        "stats": {
            "eventos_totales": int(len(df)),
            "rango": [str(df["ts"].min()), str(df["ts"].max())],
            "fallos": int((df["result"] == "fallo").sum()),
            "exitos": int((df["result"] == "exito").sum()),
            "usuarios_unicos": int(df.loc[df["user"] != "", "user"].nunique()),
            "ips_origen": int(df.loc[df["src_ip"] != "", "src_ip"].nunique()),
            "hosts": int(df.loc[df["host"] != "", "host"].nunique()),
        },
        "findings": findings,
        "severidades": sev_counts,
        "overall_risk": max((f["severity"] for f in findings), key=SEVERITY_ORDER.get, default="Bajo"),
        "iocs": {
            "ips_externas": ext_ips,
            "usuarios": sorted(entidades & set(df["user"].unique())),
            "hosts": sorted(entidades & set(df["host"].unique())),
        },
    }