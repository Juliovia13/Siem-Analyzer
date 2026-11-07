from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

ST = getSampleStyleSheet()


def P(texto, estilo="BodyText"):
    return Paragraph(escape(str(texto)), ST[estilo])


def tabla(filas, anchos):
    datos = [[P(c) for c in fila] for fila in filas]
    t = Table(datos, colWidths=anchos, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e2e8f0")),
        ("GRID", (0, 0), (-1, -1), 0.3, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]))
    return t


def _doc(ruta, titulo):
    return SimpleDocTemplate(ruta, pagesize=A4, title=titulo,
                             leftMargin=50, rightMargin=50, topMargin=50, bottomMargin=50)


def build_executive(a, n, meta, ruta):
    filas = [["Hallazgo", "Riesgo", "Eventos"]] + [
        [f["title"], f["severity"], str(f["count"])] for f in a["findings"][:12]
    ]
    s = [
        P("Informe ejecutivo de incidente de seguridad", "Title"),
        P(f"Archivo analizado: {meta['filename']}"),
        P(f"SHA-256 (integridad de la evidencia): {meta['sha256']}"),
        Spacer(1, 10),
        P(f"Nivel de riesgo global: {a['overall_risk']}", "Heading2"),
        P("Resumen", "Heading2"),
        P(n.get("resumen_ejecutivo", "")),
        P("Hallazgos principales", "Heading2"),
        tabla(filas, [330, 80, 80]) if len(filas) > 1 else P("No se identificaron hallazgos."),
        P("Recomendaciones", "Heading2"),
    ]
    s += [P("• " + r) for r in n.get("recomendaciones", [])]
    _doc(ruta, "Informe ejecutivo").build(s)


def build_technical(a, n, meta, ruta):
    st, io = a["stats"], a["iocs"]
    s = [
        P("Informe técnico de análisis de logs SIEM", "Title"),
        P(f"Archivo: {meta['filename']} | SHA-256: {meta['sha256']}"),
        P(f"Eventos: {st['eventos_totales']} | Fallos: {st['fallos']} | Éxitos: {st['exitos']} | "
          f"Periodo: {st['rango'][0]} a {st['rango'][1]}"),
        P("Metodología", "Heading2"),
        P("Normalización de columnas, clasificación de eventos en éxito o fallo y correlación por ventana temporal. "
          "Reglas: fuerza bruta (umbral por IP en 10 minutos), accesos exitosos desde IP pública, horario inusual, "
          "comandos sospechosos, movimiento lateral (logon tipo 3/10 a varios hosts), persistencia y borrado de logs. "
          "La severidad la asignan las reglas; la IA solo explica y recomienda."),
        P("Resumen técnico", "Heading2"),
        P(n.get("resumen_tecnico", "")),
        P("Indicadores de compromiso (IOC)", "Heading2"),
        P("IPs externas: " + (", ".join(io["ips_externas"]) or "ninguna")),
        P("Cuentas involucradas: " + (", ".join(io["usuarios"]) or "ninguna")),
        P("Hosts involucrados: " + (", ".join(io["hosts"]) or "ninguno")),
    ]
    for f in a["findings"]:
        evid = [["Timestamp", "Usuario", "IP origen", "Host", "EventID", "Comando"]] + [
            [e["timestamp"], e["user"], e["src_ip"], e["host"], e["event_id"], e["command"][:70]]
            for e in f["evidence"]
        ]
        s += [
            Spacer(1, 10),
            P(f"{f['title']} [{f['severity']}] MITRE {f['mitre'] or 'N/D'}", "Heading3"),
            P(f["description"]),
            P(f"Eventos: {f['count']} | Ventana: {f['first_seen']} a {f['last_seen']}"),
            P("Explicación técnica: " + f.get("explicacion_tecnica", "")),
            P("Acciones: " + " ; ".join(f.get("recomendaciones", []))),
            tabla(evid, [75, 65, 75, 65, 45, 170]),
        ]
    _doc(ruta, "Informe técnico").build(s)