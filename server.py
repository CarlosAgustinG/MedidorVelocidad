"""
Servidor central - Medidor de Velocidad (versión Postgres / Neon)
-------------------------------------------------------------------
Recibe los resultados de los celulares y los guarda en una base Postgres
(por ejemplo, Neon). Cada evento importante queda registrado en una tabla
de auditoría que no se puede modificar ni borrar.

Variables de entorno necesarias:
    DATABASE_URL    cadena de conexión de Neon (postgresql://...?sslmode=require)
    API_KEY         clave que usa la app del celular para enviar resultados
    PANEL_PASSWORD  contraseña para ver el panel (usuario: admin)

Local:    python server.py
En Render: gunicorn server:app
"""

import hmac
import os
import re

import psycopg
from flask import Flask, Response, jsonify, render_template_string, request

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 16 * 1024  # máximo 16 KB por envío

DATABASE_URL = os.environ.get("DATABASE_URL", "")
API_KEY = os.environ.get("API_KEY", "")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")

print("¿PANEL_PASSWORD configurada?:", bool(PANEL_PASSWORD))

ZONA_HORARIA = "America/Argentina/Tucuman"
MAX_TEXTO = 300

# Campos de texto que manda la app (clave JSON -> columna)
CAMPOS_TEXTO = {
    "fecha": "fecha",
    "dispositivo": "dispositivo",
    "sistema": "sistema",
    "operador": "operador",
    "wifiNombre": "wifi_nombre",
    "wifiInfo": "wifi_info",
    "ping": "ping",
    "bajada": "bajada",
    "subida": "subida",
    "latitud": "latitud",
    "longitud": "longitud",
    "direccion": "direccion",
    "servidorCiudad": "servidor_ciudad",
}


def conectar():
    # Neon puede estar dormido: damos hasta 20 s para que despierte.
    return psycopg.connect(DATABASE_URL, connect_timeout=20)


def init_db():
    with conectar() as conn:
        with conn.cursor() as cur:
            cur.execute("SELECT pg_advisory_xact_lock(42)")  # evita carreras al arrancar
            cur.execute("""
                CREATE TABLE IF NOT EXISTS resultados (
                    id BIGSERIAL PRIMARY KEY,
                    recibido_en TIMESTAMPTZ NOT NULL DEFAULT now(),
                    fecha TEXT, dispositivo TEXT, sistema TEXT, operador TEXT,
                    wifi_nombre TEXT, wifi_info TEXT,
                    ping TEXT, bajada TEXT, subida TEXT,
                    latitud TEXT, longitud TEXT, direccion TEXT,
                    servidor_ciudad TEXT,
                    ping_ms DOUBLE PRECISION,
                    bajada_mbps DOUBLE PRECISION,
                    subida_mbps DOUBLE PRECISION,
                    lat DOUBLE PRECISION,
                    lon DOUBLE PRECISION
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS auditoria (
                    id BIGSERIAL PRIMARY KEY,
                    momento TIMESTAMPTZ NOT NULL DEFAULT now(),
                    evento TEXT NOT NULL,
                    ip_origen TEXT,
                    resultado_id BIGINT,
                    detalle TEXT
                )
            """)
            # La auditoría es de solo inserción: prohibido modificar o borrar filas.
            cur.execute("""
                CREATE OR REPLACE FUNCTION auditoria_inmutable() RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION 'La tabla auditoria es de solo insercion';
                END;
                $$ LANGUAGE plpgsql
            """)
            cur.execute("DROP TRIGGER IF EXISTS trg_auditoria_inmutable ON auditoria")
            cur.execute("""
                CREATE TRIGGER trg_auditoria_inmutable
                BEFORE UPDATE OR DELETE ON auditoria
                FOR EACH ROW EXECUTE FUNCTION auditoria_inmutable()
            """)
            cur.execute("DROP TRIGGER IF EXISTS trg_auditoria_truncate ON auditoria")
            cur.execute("""
                CREATE TRIGGER trg_auditoria_truncate
                BEFORE TRUNCATE ON auditoria
                FOR EACH STATEMENT EXECUTE FUNCTION auditoria_inmutable()
            """)


def ip_origen():
    reenviada = request.headers.get("X-Forwarded-For", "")
    return (reenviada.split(",")[0].strip() or request.remote_addr or "")[:60]


def auditar(evento, resultado_id=None, detalle=""):
    try:
        with conectar() as conn:
            conn.execute(
                "INSERT INTO auditoria (evento, ip_origen, resultado_id, detalle) "
                "VALUES (%s, %s, %s, %s)",
                (evento, ip_origen(), resultado_id, detalle[:MAX_TEXTO]),
            )
    except Exception:
        pass  # la auditoría nunca debe tumbar el servidor


def numero(texto):
    """'12,34 Mbps' -> 12.34 ; 'No disponible' -> None"""
    if not texto:
        return None
    m = re.search(r"-?\d+(?:[.,]\d+)?", str(texto))
    if not m:
        return None
    try:
        return float(m.group(0).replace(",", "."))
    except ValueError:
        return None


def clave_valida():
    enviada = request.headers.get("X-API-Key", "")
    return bool(API_KEY) and hmac.compare_digest(enviada, API_KEY)


def panel_autorizado():
    auth = request.authorization

    print("----- DEBUG LOGIN -----")
    print("Autenticacion recibida:", auth is not None)
    print("Tipo:", getattr(auth, "type", None))
    print("Usuario:", getattr(auth, "username", None))
    print(
        "Contraseña correcta:",
        bool(auth and hmac.compare_digest(
            auth.password or "", PANEL_PASSWORD
        ))
    )
    print("PANEL_PASSWORD configurada:", bool(PANEL_PASSWORD))
    print("-----------------------")

    return (
        bool(PANEL_PASSWORD)
        and auth is not None
        and hmac.compare_digest(auth.password or "", PANEL_PASSWORD)
    )


def pedir_login():
    return Response(
        "Acceso restringido", 401,
        {"WWW-Authenticate": 'Basic realm="Panel Medidor de Velocidad"'},
    )


@app.route("/api/resultados", methods=["POST"])
def recibir_resultado():
    if not API_KEY:
        return jsonify({"error": "servidor sin configurar"}), 503
    if not clave_valida():
        auditar("AUTH_FALLIDA_API")
        return jsonify({"error": "clave incorrecta"}), 401

    datos = request.get_json(force=True, silent=True)
    if not isinstance(datos, dict):
        auditar("PAYLOAD_INVALIDO", detalle="no es un objeto JSON")
        return jsonify({"error": "JSON invalido"}), 400

    valores = {col: str(datos.get(clave, ""))[:MAX_TEXTO] for clave, col in CAMPOS_TEXTO.items()}
    valores["ping_ms"] = numero(valores["ping"])
    valores["bajada_mbps"] = numero(valores["bajada"])
    valores["subida_mbps"] = numero(valores["subida"])
    valores["lat"] = numero(valores["latitud"])
    valores["lon"] = numero(valores["longitud"])

    columnas = list(valores.keys())
    with conectar() as conn:
        fila = conn.execute(
            f"INSERT INTO resultados ({', '.join(columnas)}) "
            f"VALUES ({', '.join(['%s'] * len(columnas))}) RETURNING id",
            [valores[c] for c in columnas],
        ).fetchone()
        conn.execute(
            "INSERT INTO auditoria (evento, ip_origen, resultado_id, detalle) "
            "VALUES (%s, %s, %s, %s)",
            ("RESULTADO_RECIBIDO", ip_origen(), fila[0], valores["dispositivo"][:MAX_TEXTO]),
        )
    return jsonify({"estado": "ok", "id": fila[0]}), 201


def leer_resultados(limite=500):
    with conectar() as conn:
        cur = conn.execute(
            f"""SELECT id, to_char(recibido_en AT TIME ZONE '{ZONA_HORARIA}', 'DD/MM/YYYY HH24:MI:SS'),
                       fecha, dispositivo, sistema, operador, wifi_nombre, ping, bajada, subida,
                       direccion, servidor_ciudad
                FROM resultados ORDER BY id DESC LIMIT %s""",
            (limite,),
        )
        return cur.fetchall()


@app.route("/api/resultados", methods=["GET"])
def listar_json():
    if not panel_autorizado():
        auditar("AUTH_FALLIDA_PANEL", detalle="GET /api/resultados")
        return pedir_login()
    columnas = ["id", "recibido_en", "fecha", "dispositivo", "sistema", "operador",
                "wifi_nombre", "ping", "bajada", "subida", "direccion", "servidor_ciudad"]
    return jsonify([dict(zip(columnas, f)) for f in leer_resultados()])


PLANTILLA_PANEL = """
<html><head><meta charset="utf-8"><title>Panel de resultados</title>
<style>
  body { font-family: Arial, sans-serif; margin: 24px; background:#fafafa; }
  table { border-collapse: collapse; width: 100%; background: white; }
  th, td { border: 1px solid #ddd; padding: 6px 10px; font-size: 13px; text-align: left; }
  th { background: #222; color: white; position: sticky; top: 0; }
  tr:nth-child(even) { background: #f5f5f5; }
</style></head><body>
<h2>{{ titulo }}</h2>
<p><a href="/">Resultados</a> &nbsp;|&nbsp; <a href="/auditoria">Auditoría</a>
&nbsp;|&nbsp; Filas mostradas: {{ filas|length }}</p>
<table>
  <tr>{% for c in cabeceras %}<th>{{ c }}</th>{% endfor %}</tr>
  {% for f in filas %}<tr>{% for v in f %}<td>{{ v if v is not none else '' }}</td>{% endfor %}</tr>{% endfor %}
</table></body></html>
"""

CABECERAS_RESULTADOS = ["ID", "Recibido (Tucumán)", "Fecha celular", "Dispositivo", "Android",
                        "Compañía", "WiFi", "Ping", "Bajada", "Subida", "Ubicación celular",
                        "Servidor"]


@app.route("/")
def panel():
    if not panel_autorizado():
        auditar("AUTH_FALLIDA_PANEL", detalle="GET /")
        return pedir_login()
    auditar("PANEL_CONSULTADO", detalle="resultados")
    return render_template_string(
        PLANTILLA_PANEL, titulo="Resultados del medidor de velocidad",
        cabeceras=CABECERAS_RESULTADOS, filas=leer_resultados(),
    )


@app.route("/auditoria")
def ver_auditoria():
    if not panel_autorizado():
        auditar("AUTH_FALLIDA_PANEL", detalle="GET /auditoria")
        return pedir_login()
    with conectar() as conn:
        filas = conn.execute(
            f"""SELECT id, to_char(momento AT TIME ZONE '{ZONA_HORARIA}', 'DD/MM/YYYY HH24:MI:SS'),
                       evento, ip_origen, resultado_id, detalle
                FROM auditoria ORDER BY id DESC LIMIT 500"""
        ).fetchall()
    return render_template_string(
        PLANTILLA_PANEL, titulo="Registro de auditoría",
        cabeceras=["ID", "Momento (Tucumán)", "Evento", "IP de origen", "Resultado", "Detalle"],
        filas=filas,
    )


@app.route("/salud")
def salud():
    return jsonify({"estado": "ok"})


DATABASE_URL = "postgresql://neondb_owner:npg_ruTxlMo0CS6R@ep-soft-haze-bewpdxxi-pooler.c-9.us-east-2.aws.neon.tech/neondb?sslmode=require&channel_binding=require"

if DATABASE_URL:
    print("DATABASE_URL configurada correctamente")
if __name__ == "__main__":
    if not DATABASE_URL:
        raise SystemExit("Falta la variable de entorno DATABASE_URL")

    try:
        print("Intentando conectar con Neon...")

        with conectar() as conn:
            resultado = conn.execute("SELECT version()").fetchone()
            print("CONEXION EXITOSA")
            print("PostgreSQL:", resultado[0])

    except Exception as e:
        print("ERROR DE CONEXION:")
        print(type(e).__name__, str(e))
        raise

        print("Inicializando tablas...")

    init_db()

    print("Tablas creadas correctamente")

    print("Servidor corriendo en http://localhost:%s" % os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))

    try:
        with conectar() as conn:
            conn.execute("SELECT 1")

        print("CONEXION A NEON EXITOSA")

    except Exception as e:
        print("ERROR AL CONECTAR A NEON:")
        print(type(e).__name__, str(e))
        raise