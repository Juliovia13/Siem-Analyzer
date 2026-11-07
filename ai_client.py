import json
import os

MODEL = os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5")

DEFAULT_RECS = [
    "Validar el hallazgo contra el contexto del negocio y descartar falsos positivos.",
    "Revisar la actividad adicional de las cuentas y hosts involucrados en las últimas 72 horas.",
    "Documentar la evidencia y escalar según el procedimiento de respuesta a incidentes.",
]

FINDING_PROMPT = """Eres un analista SOC nivel 2 de ciberseguridad. Con base ÚNICAMENTE en el hallazgo JSON siguiente, responde en español y devuelve SOLO un objeto JSON, sin texto adicional, con las claves:
"explicacion_ejecutiva": 2 o 3 frases claras para gerencia, sin jerga;
"explicacion_tecnica": qué ocurrió, qué indicadores lo sustentan y posibles falsos positivos;
"recomendaciones": lista de 3 acciones concretas de respuesta.

Hallazgo:
{data}"""

SUMMARY_PROMPT = """Eres un analista SOC nivel 2. Con base ÚNICAMENTE en las estadísticas y hallazgos siguientes, responde en español y devuelve SOLO un objeto JSON con las claves:
"resumen_ejecutivo": un párrafo para gerencia: qué pasó, impacto probable y nivel de riesgo;
"resumen_tecnico": un párrafo técnico con IOC y la cadena de ataque probable;
"recomendaciones": lista de 5 acciones priorizadas.

Datos:
{data}"""


def _client():
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        return None
    import anthropic
    return anthropic.Anthropic(api_key=key)


def _ask(prompt):
    client = _client()
    if client is None:
        return None
    msg = client.messages.create(model=MODEL, max_tokens=900,
                                 messages=[{"role": "user", "content": prompt}])
    text = msg.content[0].text.strip()
    text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    return json.loads(text)


def explain_finding(f):
    base = {
        "explicacion_ejecutiva": f["description"],
        "explicacion_tecnica": f"{f['description']} Técnica MITRE: {f['mitre'] or 'N/D'}.",
        "recomendaciones": DEFAULT_RECS,
    }
    try:
        return _ask(FINDING_PROMPT.format(data=json.dumps(f, ensure_ascii=False, default=str))) or base
    except Exception as e:
        return {**base, "nota": f"IA no disponible: {e}"}


def global_summary(a):
    base = {
        "resumen_ejecutivo": (f"Se analizaron {a['stats']['eventos_totales']} eventos y se "
                              f"identificaron {len(a['findings'])} hallazgos. Riesgo global: {a['overall_risk']}."),
        "resumen_tecnico": "Revisar los hallazgos y los IOC listados en el informe técnico.",
        "recomendaciones": DEFAULT_RECS,
    }
    datos = {
        "estadisticas": a["stats"],
        "riesgo_global": a["overall_risk"],
        "iocs": a["iocs"],
        "hallazgos": [{"titulo": f["title"], "severidad": f["severity"],
                       "eventos": f["count"], "descripcion": f["description"]} for f in a["findings"]],
    }
    try:
        return _ask(SUMMARY_PROMPT.format(data=json.dumps(datos, ensure_ascii=False, default=str))) or base
    except Exception as e:
        return {**base, "nota": f"IA no disponible: {e}"}