
"""
Servidor central - Medidor de Velocidad
Flask + PostgreSQL (Neon)

Variables de entorno:
    DATABASE_URL
    API_KEY
    PANEL_PASSWORD

Ejecución local:
    python server.py

Ejecución en Render:
    gunicorn server:app
"""

import os
import re
import hmac
import threading

import psycopg
from flask import (
    Flask,
    Response,
    jsonify,
    render_template_string,
    request
)


# ============================================================
# CONFIGURACION
# ============================================================

app = Flask(__name__)

app.config["MAX_CONTENT_LENGTH"] = 16 * 1024

DATABASE_URL = os.environ.get("DATABASE_URL", "")
API_KEY = os.environ.get("API_KEY", "")
PANEL_PASSWORD = os.environ.get("PANEL_PASSWORD", "")

ZONA_HORARIA = "America/Argentina/Tucuman"
MAX_TEXTO = 300

# Evita inicializaciones simultáneas dentro de un mismo proceso.
_db_lock = threading.Lock()
_db_initialized = False


# ============================================================
# CAMPOS RECIBIDOS DESDE EL CELULAR
# ============================================================

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


# ============================================================
# CONEXION A NEON
# ============================================================

def conectar():

    if not DATABASE_URL:
        raise RuntimeError("Falta configurar DATABASE_URL")

    return psycopg.connect(
        DATABASE_URL,
        connect_timeout=20
    )


# ============================================================
# INICIALIZACION DE BASE DE DATOS
# ============================================================

def init_db():

    global _db_initialized

    if _db_initialized:
        return

    with _db_lock:

        if _db_initialized:
            return

        with conectar() as conn:

            with conn.cursor() as cur:

                # Evita inicializaciones simultáneas entre procesos.
                cur.execute(
                    "SELECT pg_advisory_xact_lock(42)"
                )

                # Tabla de resultados.
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS resultados (

                        id BIGSERIAL PRIMARY KEY,

                        recibido_en TIMESTAMPTZ
                            NOT NULL DEFAULT now(),

                        fecha TEXT,
                        dispositivo TEXT,
                        sistema TEXT,
                        operador TEXT,

                        wifi_nombre TEXT,
                        wifi_info TEXT,

                        ping TEXT,
                        bajada TEXT,
                        subida TEXT,

                        latitud TEXT,
                        longitud TEXT,
                        direccion TEXT,

                        servidor_ciudad TEXT,

                        ping_ms DOUBLE PRECISION,
                        bajada_mbps DOUBLE PRECISION,
                        subida_mbps DOUBLE PRECISION,

                        lat DOUBLE PRECISION,
                        lon DOUBLE PRECISION
                    )
                """)

                # Tabla de auditoría.
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS auditoria (

                        id BIGSERIAL PRIMARY KEY,

                        momento TIMESTAMPTZ
                            NOT NULL DEFAULT now(),

                        evento TEXT NOT NULL,

                        ip_origen TEXT,

                        resultado_id BIGINT,

                        detalle TEXT
                    )
                """)

                # Función que impide modificar la auditoría.
                cur.execute("""
                    CREATE OR REPLACE FUNCTION auditoria_inmutable()
                    RETURNS trigger AS $$

                    BEGIN
                        RAISE EXCEPTION
                            'La tabla auditoria es de solo insercion';
                    END;

                    $$ LANGUAGE plpgsql
                """)

                # Trigger para UPDATE y DELETE.
                cur.execute("""
                    DROP TRIGGER IF EXISTS
                    trg_auditoria_inmutable ON auditoria
                """)

                cur.execute("""
                    CREATE TRIGGER trg_auditoria_inmutable

                    BEFORE UPDATE OR DELETE ON auditoria

                    FOR EACH ROW

                    EXECUTE FUNCTION auditoria_inmutable()
                """)

                # Trigger para TRUNCATE.
                cur.execute("""
                    DROP TRIGGER IF EXISTS
                    trg_auditoria_truncate ON auditoria
                """)

                cur.execute("""
                    CREATE TRIGGER trg_auditoria_truncate

                    BEFORE TRUNCATE ON auditoria

                    FOR EACH STATEMENT

                    EXECUTE FUNCTION auditoria_inmutable()
                """)

        _db_initialized = True

        print("Tablas inicializadas correctamente.")


# ============================================================
# AUDITORIA
# ============================================================

def ip_origen():

    reenviada = request.headers.get(
        "X-Forwarded-For", ""
    )

    return (
        reenviada.split(",")[0].strip()
        or request.remote_addr
        or ""
    )[:60]


def auditar(evento, resultado_id=None, detalle=""):

    try:

        with conectar() as conn:

            conn.execute(
                """
                INSERT INTO auditoria
                (evento, ip_origen, resultado_id, detalle)

                VALUES (%s, %s, %s, %s)
                """,

                (
                    evento,
                    ip_origen(),
                    resultado_id,
                    detalle[:MAX_TEXTO]
                )
            )

    except Exception as e:

        # La auditoría no debe tumbar el servidor.
        print("Error al registrar auditoría:", type(e).__name__)


# ============================================================
# FUNCIONES AUXILIARES
# ============================================================

def numero(texto):

    """
    '12,34 Mbps' -> 12.34
    'No disponible' -> None
    """

    if not texto:
        return None

    m = re.search(
        r"-?\d+(?:[.,]\d+)?",
        str(texto)
    )

    if not m:
        return None

    try:

        return float(
            m.group(0).replace(",", ".")
        )

    except ValueError:

        return None


# ============================================================
# AUTENTICACION
# ============================================================

def clave_valida():

    enviada = request.headers.get(
        "X-API-Key", ""
    )

    return (
        bool(API_KEY)
        and hmac.compare_digest(enviada, API_KEY)
    )


def panel_autorizado():

    auth = request.authorization

    return (
        bool(PANEL_PASSWORD)
        and auth is not None
        and auth.username == "admin"
        and hmac.compare_digest(
            auth.password or "",
            PANEL_PASSWORD
        )
    )


def pedir_login():

    return Response(
        "Acceso restringido",
        401,
        {
            "WWW-Authenticate":
            'Basic realm="Panel Medidor de Velocidad"'
        }
    )


# ============================================================
# API: RECIBIR RESULTADOS
# ============================================================

@app.route("/api/resultados", methods=["POST"])
def recibir_resultado():

    if not API_KEY:

        return jsonify({
            "error": "servidor sin configurar"
        }), 503

    if not clave_valida():

        auditar("AUTH_FALLIDA_API")

        return jsonify({
            "error": "clave incorrecta"
        }), 401

    datos = request.get_json(
        force=True,
        silent=True
    )

    if not isinstance(datos, dict):

        auditar(
            "PAYLOAD_INVALIDO",
            detalle="no es un objeto JSON"
        )

        return jsonify({
            "error": "JSON invalido"
        }), 400

    valores = {

        columna: str(
            datos.get(campo, "")
        )[:MAX_TEXTO]

        for campo, columna in CAMPOS_TEXTO.items()
    }

    # Conversiones numéricas.
    valores["ping_ms"] = numero(
        valores["ping"]
    )

    valores["bajada_mbps"] = numero(
        valores["bajada"]
    )

    valores["subida_mbps"] = numero(
        valores["subida"]
    )

    valores["lat"] = numero(
        valores["latitud"]
    )

    valores["lon"] = numero(
        valores["longitud"]
    )

    columnas = list(valores.keys())

    with conectar() as conn:

        fila = conn.execute(

            f"""
            INSERT INTO resultados
            ({', '.join(columnas)})

            VALUES
            ({', '.join(['%s'] * len(columnas))})

            RETURNING id
            """,

            [
                valores[columna]
                for columna in columnas
            ]

        ).fetchone()

        conn.execute(
            """
            INSERT INTO auditoria
            (evento, ip_origen, resultado_id, detalle)

            VALUES (%s, %s, %s, %s)
            """,

            (
                "RESULTADO_RECIBIDO",
                ip_origen(),
                fila[0],
                valores["dispositivo"]
            )
        )

    return jsonify({
        "estado": "ok",
        "id": fila[0]
    }), 201


# ============================================================
# CONSULTAR RESULTADOS
# ============================================================

def leer_resultados(limite=500):

    with conectar() as conn:

        cur = conn.execute(

            f"""
            SELECT

                id,

                to_char(
                    recibido_en AT TIME ZONE '{ZONA_HORARIA}',
                    'DD/MM/YYYY HH24:MI:SS'
                ),

                fecha,
                dispositivo,
                sistema,
                operador,

                wifi_nombre,

                ping,
                bajada,
                subida,

                direccion,
                servidor_ciudad

            FROM resultados

            ORDER BY id DESC

            LIMIT %s
            """,

            (limite,)
        )

        return cur.fetchall()


# ============================================================
# API: LISTAR RESULTADOS EN JSON
# ============================================================

@app.route("/api/resultados", methods=["GET"])
def listar_json():

    if not panel_autorizado():

        auditar(
            "AUTH_FALLIDA_PANEL",
            detalle="GET /api/resultados"
        )

        return pedir_login()

    columnas = [

        "id",
        "recibido_en",
        "fecha",
        "dispositivo",
        "sistema",
        "operador",
        "wifi_nombre",
        "ping",
        "bajada",
        "subida",
        "direccion",
        "servidor_ciudad"
    ]

    return jsonify([

        dict(zip(columnas, fila))

        for fila in leer_resultados()

    ])


# ============================================================
# PLANTILLA DEL PANEL
# ============================================================

PLANTILLA_PANEL = """

<html>

<head>

<meta charset="utf-8">

<title>Panel de resultados</title>

<style>

body {
    font-family: Arial, sans-serif;
    margin: 24px;
    background: #fafafa;
}

table {
    border-collapse: collapse;
    width: 100%;
    background: white;
}

th, td {
    border: 1px solid #ddd;
    padding: 6px 10px;
    font-size: 13px;
    text-align: left;
}

th {
    background: #222;
    color: white;
    position: sticky;
    top: 0;
}

tr:nth-child(even) {
    background: #f5f5f5;
}

</style>

</head>

<body>

<h2>{{ titulo }}</h2>

<p>

<a href="/">Resultados</a>

&nbsp;|&nbsp;

<a href="/auditoria">Auditoría</a>

&nbsp;|&nbsp;

Filas mostradas: {{ filas|length }}

</p>

<table>

<tr>

{% for c in cabeceras %}

<th>{{ c }}</th>

{% endfor %}

</tr>

{% for f in filas %}

<tr>

{% for v in f %}

<td>{{ v if v is not none else '' }}</td>

{% endfor %}

</tr>

{% endfor %}

</table>

</body>

</html>

"""


CABECERAS_RESULTADOS = [

    "ID",
    "Recibido (Tucumán)",
    "Fecha celular",
    "Dispositivo",
    "Android",
    "Compañía",
    "WiFi",
    "Ping",
    "Bajada",
    "Subida",
    "Ubicación celular",
    "Servidor"

]


# ============================================================
# PANEL PRINCIPAL
# ============================================================

@app.route("/")
def panel():

    if not panel_autorizado():

        auditar(
            "AUTH_FALLIDA_PANEL",
            detalle="GET /"
        )

        return pedir_login()

    auditar(
        "PANEL_CONSULTADO",
        detalle="resultados"
    )

    return render_template_string(

        PLANTILLA_PANEL,

        titulo="Resultados del medidor de velocidad",

        cabeceras=CABECERAS_RESULTADOS,

        filas=leer_resultados()

    )


# ============================================================
# PANEL DE AUDITORIA
# ============================================================

@app.route("/auditoria")
def ver_auditoria():

    if not panel_autorizado():

        auditar(
            "AUTH_FALLIDA_PANEL",
            detalle="GET /auditoria"
        )

        return pedir_login()

    with conectar() as conn:

        filas = conn.execute(

            f"""
            SELECT

                id,

                to_char(
                    momento AT TIME ZONE '{ZONA_HORARIA}',
                    'DD/MM/YYYY HH24:MI:SS'
                ),

                evento,
                ip_origen,
                resultado_id,
                detalle

            FROM auditoria

            ORDER BY id DESC

            LIMIT 500
            """

        ).fetchall()

    return render_template_string(

        PLANTILLA_PANEL,

        titulo="Registro de auditoría",

        cabeceras=[

            "ID",
            "Momento (Tucumán)",
            "Evento",
            "IP de origen",
            "Resultado",
            "Detalle"

        ],

        filas=filas

    )


# ============================================================
# RUTA DE SALUD
# ============================================================

@app.route("/salud")
def salud():

    return jsonify({
        "estado": "ok"
    })


# ============================================================
# INICIALIZAR AL ARRANCAR
# ============================================================

# Gunicorn importa server.py al iniciar.
# Por eso inicializamos las tablas aquí y no solamente
# dentro del bloque if __name__ == "__main__".

init_db()


# ============================================================
# EJECUCION LOCAL
# ============================================================

if __name__ == "__main__":

    puerto = int(
        os.environ.get("PORT", 5000)
    )

    print("Servidor iniciado correctamente.")

    app.run(
        host="0.0.0.0",
        port=puerto
    )
