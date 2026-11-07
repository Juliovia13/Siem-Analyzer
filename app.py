import hashlib
import os
import tempfile

from flask import Flask, abort, jsonify, render_template, request, send_file

from ai_client import explain_finding, global_summary
from analyzer import analyze, load_table
from reports import build_executive, build_technical

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024
ESTADO = {}  # último análisis en memoria; la app es de uso local por un analista


@app.get("/")
def index():
    return render_template("index.html")


@app.post("/api/analizar")
def api_analizar():
    f = request.files.get("archivo")
    if not f or not f.filename:
        return jsonify(error="Sube un archivo .xlsx, .xls o .csv"), 400
    ext = os.path.splitext(f.filename)[1].lower()
    if ext not in (".xlsx", ".xls", ".csv"):
        return jsonify(error="Formato no soportado"), 400

    fd, ruta = tempfile.mkstemp(suffix=ext)
    os.close(fd)
    try:
        f.save(ruta)
        with open(ruta, "rb") as fh:
            sha = hashlib.sha256(fh.read()).hexdigest()
        resultado = analyze(load_table(ruta))
    except Exception as e:
        return jsonify(error=f"No se pudo procesar el archivo: {e}"), 422
    finally:
        os.remove(ruta)

    resultado["meta"] = {"filename": f.filename, "sha256": sha}
    for hallazgo in resultado["findings"]:
        hallazgo.update(explain_finding(hallazgo))
    resultado["resumen"] = global_summary(resultado)
    ESTADO["r"] = resultado
    return jsonify(resultado)


@app.get("/api/informe/<tipo>")
def informe(tipo):
    if "r" not in ESTADO:
        abort(404)
    r = ESTADO["r"]
    ruta = os.path.join(tempfile.gettempdir(), f"informe_{tipo}.pdf")
    if tipo == "ejecutivo":
        build_executive(r, r["resumen"], r["meta"], ruta)
    elif tipo == "tecnico":
        build_technical(r, r["resumen"], r["meta"], ruta)
    else:
        abort(404)
    return send_file(ruta, as_attachment=True, download_name=f"informe_{tipo}.pdf")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)