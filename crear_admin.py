"""Crea un administrador, o convierte en administrador a un usuario existente.

Uso:  python3 crear_admin.py
"""
import sqlite3
from getpass import getpass

from werkzeug.security import generate_password_hash

import app as plataforma   # al importarlo se crea o actualiza la base de datos

email = input("Correo del administrador: ").strip().lower()
db = sqlite3.connect(plataforma.DB_PATH)

if db.execute("SELECT 1 FROM usuarios WHERE email = ?", (email,)).fetchone():
    db.execute("UPDATE usuarios SET rol = 'admin' WHERE email = ?", (email,))
    print(f"{email} ya existía y ahora es administrador.")
else:
    nombre = input("Nombre: ").strip()
    password = getpass("Contraseña (mínimo 8 caracteres): ")
    if not nombre or "@" not in email or len(password) < 8 or password != getpass("Repite la contraseña: "):
        raise SystemExit("Datos no válidos o las contraseñas no coinciden. No se ha creado nada.")
    db.execute("INSERT INTO usuarios (nombre, email, password, departamento, rol) VALUES (?, ?, ?, ?, 'admin')",
               (nombre, email, generate_password_hash(password, method="pbkdf2:sha256"), "Administración"))
    print(f"Administrador {email} creado.")
db.commit()
