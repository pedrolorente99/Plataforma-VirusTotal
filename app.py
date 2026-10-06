"""Plataforma de detección de archivos - registro, login y panel."""
import os
import secrets
import shutil
import sqlite3
import threading
import time
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from flask import (Flask, abort, flash, g, make_response, redirect, render_template,
                   request, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

import inspector

BASE_DIR = Path(__file__).parent
load_dotenv(BASE_DIR / ".env")

# Modo demo: sin VT_API_KEY se usa un motor local (sin API ni internet).
MODO_DEMO = not os.getenv("VT_API_KEY")
if MODO_DEMO:
    import motor_local as motor
else:
    import motor_virustotal as motor

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY")
if not app.secret_key:
    if not MODO_DEMO:
        raise SystemExit("Falta SECRET_KEY en el archivo .env")
    app.secret_key = secrets.token_hex(32)   # demo: aleatoria; las sesiones caducan al reiniciar
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

DB_PATH = BASE_DIR / "plataforma.db"
DATOS_DIR = BASE_DIR / "datos"                      # datos/<id_usuario>/<carpeta>
CARPETAS = ("archivos", "sanos", "infectados")
DEPARTAMENTOS = ("Recursos Humanos", "Finanzas", "Marketing", "Ventas", "IT", "Ciberseguridad")
ROLES = ("usuario", "admin")
DEPARTAMENTOS_EDITABLES = DEPARTAMENTOS + ("Administración", "Sin asignar")  # lo que puede asignar un admin
RESPUESTA = ("IT", "Ciberseguridad")                # departamentos que reciben incidentes
# En el registro público NO se pueden elegir los departamentos de respuesta:
# reciben archivos infectados y pueden inspeccionarlos, así que solo los asigna un admin.
DEPARTAMENTOS_REGISTRO = tuple(d for d in DEPARTAMENTOS if d not in RESPUESTA)
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024  # máx. 64 MB por subida


# ------------------------------ Base de datos ------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def cerrar_db(_):
    db = g.pop("db", None)
    if db:
        db.close()


def iniciar_db():
    with sqlite3.connect(DB_PATH) as db:
        db.execute("""CREATE TABLE IF NOT EXISTS usuarios (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            creado TEXT DEFAULT CURRENT_TIMESTAMP)""")
        columnas = [c[1] for c in db.execute("PRAGMA table_info(usuarios)")]
        if "departamento" not in columnas:       # bases creadas antes de esta versión
            db.execute("ALTER TABLE usuarios ADD COLUMN departamento "
                       "TEXT NOT NULL DEFAULT 'Sin asignar'")
        if "rol" not in columnas:
            db.execute("ALTER TABLE usuarios ADD COLUMN rol TEXT NOT NULL DEFAULT 'usuario'")
        db.execute("""CREATE TABLE IF NOT EXISTS derivaciones (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            remitente_id INTEGER NOT NULL,
            destinatario_id INTEGER NOT NULL,
            archivo TEXT NOT NULL,
            sha256 TEXT NOT NULL,
            detecciones INTEGER,
            nota TEXT,
            estado TEXT NOT NULL DEFAULT 'pendiente',
            creado TEXT DEFAULT CURRENT_TIMESTAMP)""")


# ------------------------------- Seguridad --------------------------------
@app.before_request
def comprobar_csrf():
    """Todo formulario POST debe llevar el token de la sesión."""
    token = session.get("csrf")
    if request.method == "POST" and (not token or request.form.get("csrf") != token):
        flash("La sesión de la página ha caducado. Inténtalo de nuevo.")
        return redirect(url_for("panel" if "usuario_id" in session else "login"))


@app.context_processor
def inyectar_csrf():
    session.setdefault("csrf", secrets.token_hex(16))
    return {"csrf_token": session["csrf"]}


def login_requerido(vista):
    @wraps(vista)
    def envoltura(*args, **kwargs):
        usuario = None
        if "usuario_id" in session:
            usuario = get_db().execute(
                "SELECT id, nombre, email, departamento, rol, creado FROM usuarios WHERE id = ?",
                (session["usuario_id"],)).fetchone()
        if usuario is None:          # sin sesión, o el usuario ya no existe
            session.clear()
            return redirect(url_for("login"))
        g.usuario = usuario          # disponible dentro de la vista
        return vista(*args, **kwargs)
    return envoltura


def admin_requerido(vista):
    """Solo administradores; el rol se comprueba siempre contra la base de datos."""
    @wraps(vista)
    def envoltura(*args, **kwargs):
        if g.usuario["rol"] != "admin":
            abort(403)
        return vista(*args, **kwargs)
    return login_requerido(envoltura)


# --------------------------------- Rutas ----------------------------------
@app.route("/")
def inicio():
    return redirect(url_for("panel" if "usuario_id" in session else "login"))


@app.route("/registro", methods=["GET", "POST"])
def registro():
    if request.method == "POST":
        nombre = request.form.get("nombre", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        departamento = request.form.get("departamento", "")

        if not nombre or "@" not in email:
            flash("Escribe tu nombre y un correo válido.")
        elif departamento in RESPUESTA:
            flash("IT y Ciberseguridad los asigna un administrador. "
                  "Elige otro departamento y pídele el cambio después.")
        elif departamento not in DEPARTAMENTOS_REGISTRO:
            flash("Elige tu departamento.")
        elif len(password) < 8:
            flash("La contraseña debe tener al menos 8 caracteres.")
        else:
            try:
                get_db().execute(
                    "INSERT INTO usuarios (nombre, email, password, departamento) VALUES (?, ?, ?, ?)",
                    (nombre, email, generate_password_hash(password, method="pbkdf2:sha256"),
                     departamento))
                get_db().commit()
                flash("Cuenta creada. Ya puedes iniciar sesión.", "ok")
                return redirect(url_for("login"))
            except sqlite3.IntegrityError:
                flash("Ya existe una cuenta con ese correo.")
    return render_template("registro.html", departamentos=DEPARTAMENTOS_REGISTRO)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        usuario = get_db().execute(
            "SELECT * FROM usuarios WHERE lower(email) = ?", (email,)).fetchone()

        if usuario and check_password_hash(usuario["password"], password):
            session.clear()
            session["usuario_id"] = usuario["id"]
            session["nombre"] = usuario["nombre"]
            return redirect(url_for("panel"))
        flash("Correo o contraseña incorrectos.")
    return render_template("login.html")


# ------------------------- Carpetas de cada usuario -------------------------
def carpeta_usuario(uid, nombre):
    """Ruta de una carpeta del usuario; se crea si no existe."""
    ruta = DATOS_DIR / str(uid) / nombre
    ruta.mkdir(parents=True, exist_ok=True)
    return ruta


def tam_legible(n):
    for unidad in ("B", "KB", "MB", "GB"):
        if n < 1024 or unidad == "GB":
            return f"{n:.0f} {unidad}" if unidad == "B" else f"{n:.1f} {unidad}"
        n /= 1024


app.add_template_filter(tam_legible, "tam")


def listar(uid, nombre):
    carpeta = carpeta_usuario(uid, nombre)
    return [{"nombre": f.name, "tam": tam_legible(f.stat().st_size)}
            for f in sorted(carpeta.iterdir())
            if f.is_file() and not f.name.startswith(".")]


# --------------------- Análisis en segundo plano ---------------------
ESTADOS = {}                       # id_usuario -> progreso del análisis
CANDADO_VT = threading.Lock()      # un análisis a la vez: la cuota de la API es compartida


def tarea_analisis(uid, rutas, api_key, permitir_subida=False):
    est = ESTADOS[uid]
    with CANDADO_VT:
        est["fase"] = "analizando"
        for i, ruta in enumerate(rutas):
            est["actual"] = ruta.name
            try:
                if ruta.exists():
                    stats = motor.analizar(ruta, api_key, permitir_subida)
                    if stats is None:       # VirusTotal no lo conoce y no se ha autorizado subirlo
                        est["resultados"].append({"nombre": ruta.name, "veredicto": "desconocido"})
                    else:
                        veredicto, det = motor.clasificar(stats)
                        destino = carpeta_usuario(uid, "infectados" if veredicto == "infectado" else "sanos")
                        motor.mover_archivo(ruta, destino)
                        est["resultados"].append(
                            {"nombre": ruta.name, "veredicto": veredicto, "detecciones": det})
            except Exception as error:      # el archivo se queda en Archivos
                est["resultados"].append(
                    {"nombre": ruta.name, "veredicto": "error", "detalle": str(error)[:120]})
            est["hechos"] = i + 1
            if i < len(rutas) - 1:
                time.sleep(motor.ESPERA)    # respeta el límite de la API gratuita
    est["fase"] = "fin"
    est["actual"] = ""


@app.route("/panel")
@login_requerido
def panel():
    if g.usuario["rol"] == "admin":          # los administradores tienen su propio panel
        return redirect(url_for("admin_panel"))
    uid = g.usuario["id"]
    listas = {c: listar(uid, c) for c in CARPETAS}
    db = get_db()
    equipo = db.execute(
        "SELECT id, nombre, departamento FROM usuarios "
        "WHERE departamento IN (?, ?) AND id != ? ORDER BY departamento, nombre",
        (*RESPUESTA, uid)).fetchall()
    recibidos = db.execute(
        "SELECT d.*, u.nombre AS remitente, u.departamento AS dep_remitente "
        "FROM derivaciones d JOIN usuarios u ON u.id = d.remitente_id "
        "WHERE d.destinatario_id = ? ORDER BY d.id DESC", (uid,)).fetchall()
    enviados = db.execute(
        "SELECT d.*, u.nombre AS destinatario, u.departamento AS dep_destinatario "
        "FROM derivaciones d JOIN usuarios u ON u.id = d.destinatario_id "
        "WHERE d.remitente_id = ? ORDER BY d.id DESC", (uid,)).fetchall()
    return render_template("panel.html", usuario=g.usuario, listas=listas,
                           estado=ESTADOS.get(uid), equipo=equipo, recibidos=recibidos,
                           enviados=enviados, es_equipo=g.usuario["departamento"] in RESPUESTA)


@app.route("/subir", methods=["POST"])
@login_requerido
def subir():
    destino = carpeta_usuario(g.usuario["id"], "archivos")
    guardados = 0
    for archivo in request.files.getlist("archivos"):
        nombre = secure_filename(archivo.filename or "")
        if not nombre:
            continue
        ruta = destino / nombre
        if ruta.exists():
            ruta = destino / f"{ruta.stem}_{secrets.token_hex(3)}{ruta.suffix}"
        archivo.save(ruta)
        guardados += 1
    if guardados:
        flash(f"{guardados} archivo(s) subido(s) a Archivos.", "ok")
    else:
        flash("No has seleccionado ningún archivo.")
    return redirect(url_for("panel"))


@app.route("/analizar", methods=["POST"])
@login_requerido
def analizar():
    uid = g.usuario["id"]
    est = ESTADOS.get(uid)
    api_key = os.getenv("VT_API_KEY") or "demo"
    if est and est["fase"] in ("cola", "analizando"):
        flash("Ya hay un análisis en curso.")
    elif not api_key:
        flash("El servidor no tiene configurada la clave de VirusTotal.")
    else:
        rutas = [carpeta_usuario(uid, "archivos") / a["nombre"] for a in listar(uid, "archivos")]
        if not rutas:
            flash("La carpeta Archivos está vacía. Sube algún archivo primero.")
        else:
            ESTADOS[uid] = {"fase": "cola", "total": len(rutas), "hechos": 0,
                            "actual": "", "resultados": []}
            threading.Thread(target=tarea_analisis, args=(uid, rutas, api_key),
                             daemon=True).start()
    return redirect(url_for("panel"))


@app.route("/subir-vt", methods=["POST"])
@login_requerido
def subir_a_virustotal():
    """Sube a VirusTotal archivos que no conoce, solo con confirmación explícita del usuario."""
    uid = g.usuario["id"]
    est = ESTADOS.get(uid)
    api_key = os.getenv("VT_API_KEY") or "demo"
    carpeta = carpeta_usuario(uid, "archivos")
    nombres = {secure_filename(n) for n in request.form.getlist("archivos")}
    rutas = [carpeta / a["nombre"] for a in listar(uid, "archivos") if a["nombre"] in nombres]

    if est and est["fase"] in ("cola", "analizando"):
        flash("Ya hay un análisis en curso.")
    elif not api_key:
        flash("El servidor no tiene configurada la clave de VirusTotal.")
    elif request.form.get("confirmo") != "1":
        flash("Para subir archivos a VirusTotal debes confirmar que entiendes que se compartirán.")
    elif not rutas:
        flash("Selecciona al menos un archivo para subir.")
    else:
        elegidos = {r.name for r in rutas}
        previos = [r for r in (est or {}).get("resultados", []) if r["nombre"] not in elegidos]
        ESTADOS[uid] = {"fase": "cola", "total": len(rutas), "hechos": 0,
                        "actual": "", "resultados": previos}      # conserva el informe anterior
        app.logger.info("Usuario %s autoriza subir %d archivo(s) a VirusTotal", uid, len(rutas))
        threading.Thread(target=tarea_analisis, args=(uid, rutas, api_key, True),
                         daemon=True).start()
    return redirect(url_for("panel"))


# ------------------- Envío de archivos infectados al equipo de seguridad -------------------
@app.route("/derivar/<nombre>", methods=["POST"])
@login_requerido
def derivar(nombre):
    uid = g.usuario["id"]
    nombre = secure_filename(nombre)
    origen = carpeta_usuario(uid, "infectados") / nombre
    db = get_db()
    destinatario = db.execute(
        "SELECT id FROM usuarios WHERE id = ? AND departamento IN (?, ?) AND id != ?",
        (request.form.get("destinatario", type=int), *RESPUESTA, uid)).fetchone()

    if not origen.is_file():
        flash("Ese archivo ya no está en Infectados.")
    elif not destinatario:
        flash("Elige un destinatario de IT o Ciberseguridad.")
    else:
        resultados = (ESTADOS.get(uid) or {}).get("resultados", [])
        detecciones = next((r["detecciones"] for r in resultados
                            if r["nombre"] == nombre and r["veredicto"] == "infectado"), None)
        cur = db.execute(
            "INSERT INTO derivaciones (remitente_id, destinatario_id, archivo, sha256, "
            "detecciones, nota) VALUES (?, ?, ?, ?, ?, ?)",
            (uid, destinatario["id"], nombre, motor.calcular_sha256(origen), detecciones,
             request.form.get("nota", "").strip()[:500]))
        db.commit()
        destino = DATOS_DIR / "derivados" / str(cur.lastrowid)
        destino.mkdir(parents=True, exist_ok=True)
        shutil.move(str(origen), str(destino / nombre))
        flash(f"«{nombre}» enviado al equipo de seguridad.", "ok")
    return redirect(url_for("panel"))


def caso_del_destinatario(caso_id):
    """Solo el destinatario de un incidente puede gestionarlo."""
    caso = get_db().execute("SELECT * FROM derivaciones WHERE id = ? AND destinatario_id = ?",
                            (caso_id, g.usuario["id"])).fetchone()
    if not caso:
        abort(404)
    return caso


@app.route("/incidente/<int:caso_id>/revisar", methods=["POST"])
@login_requerido
def revisar(caso_id):
    caso_del_destinatario(caso_id)
    get_db().execute("UPDATE derivaciones SET estado = 'en_revision' "
                     "WHERE id = ? AND estado = 'pendiente'", (caso_id,))
    get_db().commit()
    return redirect(url_for("panel"))


@app.route("/incidente/<int:caso_id>/resolver", methods=["POST"])
@login_requerido
def resolver(caso_id):
    caso_del_destinatario(caso_id)
    shutil.rmtree(DATOS_DIR / "derivados" / str(caso_id), ignore_errors=True)  # elimina el archivo
    get_db().execute("UPDATE derivaciones SET estado = 'resuelto' WHERE id = ?", (caso_id,))
    get_db().commit()
    flash("Incidente resuelto y archivo eliminado del servidor.", "ok")
    return redirect(url_for("panel"))


@app.route("/incidente/<int:caso_id>/contenido")
@login_requerido
def contenido_incidente(caso_id):
    """Vista de solo lectura del interior de un archivo infectado: no se ejecuta ni se descarga."""
    caso = caso_del_destinatario(caso_id)
    desde_visor = request.headers.get("X-Requested-With") == "fetch"   # ventana emergente del panel
    ruta = DATOS_DIR / "derivados" / str(caso_id) / secure_filename(caso["archivo"])
    if caso["estado"] == "resuelto" or not ruta.is_file():
        if desde_visor:
            abort(410)
        flash("El archivo de este incidente ya no está en el servidor.")
        return redirect(url_for("panel"))
    try:
        info = inspector.inspeccionar(ruta, caso["archivo"])
    except Exception as error:
        app.logger.warning("No se pudo inspeccionar el incidente %s: %s", caso_id, error)
        if desde_visor:
            abort(500)
        flash("No se pudo inspeccionar este archivo.")
        return redirect(url_for("panel"))
    app.logger.info("Inspección del incidente %s por el usuario %s", caso_id, g.usuario["id"])
    plantilla = "_contenido.html" if desde_visor else "contenido.html"
    respuesta = make_response(render_template(plantilla, usuario=g.usuario, caso=caso, info=info))
    respuesta.headers["Cache-Control"] = "no-store"          # no dejar cadenas del malware en la caché
    respuesta.headers["X-Content-Type-Options"] = "nosniff"
    return respuesta


# ------------------------- Panel de administración -------------------------
@app.route("/admin")
@admin_requerido
def admin_panel():
    db = get_db()
    usuarios = db.execute(
        "SELECT u.id, u.nombre, u.email, u.departamento, u.rol, u.creado, "
        "(SELECT COUNT(*) FROM derivaciones WHERE remitente_id = u.id) AS enviados, "
        "(SELECT COUNT(*) FROM derivaciones WHERE destinatario_id = u.id) AS recibidos "
        "FROM usuarios u ORDER BY u.id").fetchall()
    por_depto = db.execute("SELECT departamento, COUNT(*) AS n FROM usuarios "
                           "GROUP BY departamento ORDER BY n DESC, departamento").fetchall()
    abiertos = db.execute("SELECT COUNT(*) FROM derivaciones WHERE estado != 'resuelto'").fetchone()[0]
    historial = db.execute(            # todos los archivos enviados: quién, a quién y en qué estado
        "SELECT d.id, d.archivo, d.sha256, d.detecciones, d.nota, d.estado, d.creado, "
        "r.nombre AS remitente, r.email AS email_remitente, r.departamento AS dep_remitente, "
        "t.nombre AS destinatario, t.email AS email_destinatario, t.departamento AS dep_destinatario "
        "FROM derivaciones d "
        "LEFT JOIN usuarios r ON r.id = d.remitente_id "
        "LEFT JOIN usuarios t ON t.id = d.destinatario_id "
        "ORDER BY d.id DESC").fetchall()
    return render_template("admin.html", usuario=g.usuario, usuarios=usuarios, por_depto=por_depto,
                           abiertos=abiertos, historial=historial,
                           admins=sum(u["rol"] == "admin" for u in usuarios),
                           departamentos=DEPARTAMENTOS_EDITABLES, roles=ROLES)


@app.route("/admin/usuario/<int:uid>/guardar", methods=["POST"])
@admin_requerido
def admin_guardar(uid):
    db = get_db()
    if not db.execute("SELECT 1 FROM usuarios WHERE id = ?", (uid,)).fetchone():
        abort(404)
    nombre = request.form.get("nombre", "").strip()
    email = request.form.get("email", "").strip().lower()
    departamento = request.form.get("departamento", "")
    rol = request.form.get("rol", "")
    password = request.form.get("password", "")

    if not nombre or "@" not in email:
        flash("El nombre y un correo válido son obligatorios.")
    elif departamento not in DEPARTAMENTOS_EDITABLES or rol not in ROLES:
        flash("Departamento o rol no válidos.")
    elif uid == g.usuario["id"] and rol != "admin":
        flash("No puedes quitarte a ti mismo el rol de administrador.")
    elif password and len(password) < 8:
        flash("La nueva contraseña debe tener al menos 8 caracteres.")
    else:
        try:
            db.execute("UPDATE usuarios SET nombre = ?, email = ?, departamento = ?, rol = ? "
                       "WHERE id = ?", (nombre, email, departamento, rol, uid))
            if password:
                db.execute("UPDATE usuarios SET password = ? WHERE id = ?",
                           (generate_password_hash(password, method="pbkdf2:sha256"), uid))
            db.commit()
            flash(f"Usuario «{nombre}» actualizado.", "ok")
        except sqlite3.IntegrityError:
            flash("Ese correo ya lo usa otro usuario.")
    return redirect(url_for("admin_panel"))


@app.route("/admin/usuario/<int:uid>/eliminar", methods=["POST"])
@admin_requerido
def admin_eliminar(uid):
    db = get_db()
    objetivo = db.execute("SELECT nombre FROM usuarios WHERE id = ?", (uid,)).fetchone()
    if not objetivo:
        abort(404)
    if uid == g.usuario["id"]:
        flash("No puedes eliminar tu propia cuenta.")
        return redirect(url_for("admin_panel"))
    # Borra al usuario, sus incidentes (enviados y recibidos) y todos sus archivos
    casos = db.execute("SELECT id FROM derivaciones WHERE remitente_id = ? OR destinatario_id = ?",
                       (uid, uid)).fetchall()
    for caso in casos:
        shutil.rmtree(DATOS_DIR / "derivados" / str(caso["id"]), ignore_errors=True)
    db.execute("DELETE FROM derivaciones WHERE remitente_id = ? OR destinatario_id = ?", (uid, uid))
    db.execute("DELETE FROM usuarios WHERE id = ?", (uid,))
    db.commit()
    shutil.rmtree(DATOS_DIR / str(uid), ignore_errors=True)
    ESTADOS.pop(uid, None)
    flash(f"Usuario «{objetivo['nombre']}» eliminado junto con sus archivos e incidentes.", "ok")
    return redirect(url_for("admin_panel"))


@app.route("/estado")
@login_requerido
def estado():
    return ESTADOS.get(g.usuario["id"]) or {"fase": "inactivo"}


@app.route("/borrar/<carpeta>/<nombre>", methods=["POST"])
@login_requerido
def borrar(carpeta, nombre):
    if carpeta not in CARPETAS:
        abort(404)
    ruta = carpeta_usuario(g.usuario["id"], carpeta) / secure_filename(nombre)
    if ruta.is_file():
        ruta.unlink()
    return redirect(url_for("panel"))


@app.errorhandler(413)
def demasiado_grande(_):
    flash("Los archivos superan el máximo de 64 MB por subida.")
    return redirect(url_for("panel"))


@app.route("/salir", methods=["POST"])
def salir():
    session.clear()
    return redirect(url_for("login"))


iniciar_db()

if __name__ == "__main__":
    # Puerto 5001: en macOS el 5000 lo ocupa AirPlay y devuelve un error 403
    app.run(port=int(os.getenv("PORT", "5001")), debug=os.getenv("FLASK_DEBUG") == "1")   # el modo debug expone un depurador: solo en local
