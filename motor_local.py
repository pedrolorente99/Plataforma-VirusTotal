"""Motor de análisis LOCAL para el modo demo (no necesita API ni internet).

Devuelve el mismo formato que motor_virustotal ({"malicious": n, "suspicious": n, ...}),
así que el resto de la aplicación funciona igual. NO sustituye a un antivirus: usa
firmas básicas (hash, EICAR) y heurísticas simples. Solo LEE bytes; nunca ejecuta nada.
"""
import hashlib
import math
import re
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

import inspector

ESPERA = 0                      # sin límite de peticiones: no hay API
LEER_MAX = 2 * 1024 * 1024
HASHES_FILE = Path(__file__).parent / "hashes_conocidos.txt"
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

PATRONES_SCRIPT = [                     # (regex, descripción)
    (rb"powershell[^\n]{0,40}-(enc|encodedcommand)\b", "PowerShell codificado"),
    (rb"invoke-expression|\biex\s*\(", "Ejecución dinámica (IEX)"),
    (rb"certutil[^\n]{0,40}-urlcache", "Descarga con certutil"),
    (rb"downloadstring|downloadfile", "Descarga de ficheros remotos"),
    (rb"wscript\.shell|createobject\(\s*[\"']wscript", "Ejecución vía WScript"),
    (rb"frombase64string", "Contenido en Base64 decodificado en ejecución"),
    (rb"/dev/tcp/|nc\s+-e\s", "Posible reverse shell"),
    (rb"autoopen|document_open|shell\(", "Macro con ejecución automática"),
]


def calcular_sha256(ruta: Path) -> str:
    sha = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(bloque)
    return sha.hexdigest()


def _hashes_conocidos():
    if not HASHES_FILE.exists():
        return set()
    lineas = (l.split("#")[0].strip().lower() for l in HASHES_FILE.read_text().splitlines())
    return {l for l in lineas if re.fullmatch(r"[0-9a-f]{64}", l)}


def _entropia(datos):
    if not datos:
        return 0.0
    n = len(datos)
    return -sum(c / n * math.log2(c / n) for c in (datos.count(bytes([b])) for b in set(datos)))


def examinar(ruta: Path):
    """Devuelve (fuertes, debiles): listas de motivos de detección."""
    ruta = Path(ruta)
    with open(ruta, "rb") as f:
        datos = f.read(LEER_MAX)
    fuertes, debiles = [], []
    nombre, ext = ruta.name, ruta.suffix.lower()

    if calcular_sha256(ruta) in _hashes_conocidos():
        fuertes.append("Hash presente en la lista local de malware conocido")
    if EICAR in datos:
        fuertes.append("Cadena de prueba EICAR")
    if inspector.DOBLE_EXTENSION.search(nombre):
        fuertes.append("Doble extensión engañosa")
    if any(c in inspector.BIDI for c in nombre):
        fuertes.append("Nombre con caracteres de inversión de texto")

    es_ejecutable = datos.startswith((b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe"))
    if es_ejecutable:
        debiles.append("Ejecutable binario")
        if _entropia(datos[:65536]) > 7.2:
            debiles.append("Entropía muy alta (posible empaquetado/cifrado)")
    if es_ejecutable and ext not in inspector.EXT_EJECUTABLES:
        fuertes.append("Ejecutable con extensión que no corresponde")

    if ext in inspector.EXT_PELIGROSAS - inspector.EXT_EJECUTABLES:
        debiles.append("Script ejecutable")
    if ext in inspector.EXT_PELIGROSAS or datos.startswith(b"#!") or ext in {".txt", ".docm", ".xlsm"}:
        for patron, desc in PATRONES_SCRIPT:
            if re.search(patron, datos, re.I):
                fuertes.append(desc)

    if zipfile.is_zipfile(ruta):
        try:
            with zipfile.ZipFile(ruta) as z:
                infos = z.infolist()[:inspector.MAX_ENTRADAS_ZIP]
            for i in infos:
                avisos = inspector._alertas_entrada(i.filename, i)
                for a in ("Macros VBA", "Ruta sospechosa", "Compresión extrema", "Doble extensión"):
                    if a in avisos:
                        (debiles if a == "Macros VBA" else fuertes).append(f"ZIP: {a} ({i.filename[:40]})")
                if "Ejecutable o script" in avisos and ext in {".zip", ".rar", ".7z"}:
                    debiles.append(f"ZIP con ejecutable/script ({i.filename[:40]})")
        except (zipfile.BadZipFile, NotImplementedError):
            debiles.append("ZIP corrupto o no estándar")
    return list(dict.fromkeys(fuertes)), list(dict.fromkeys(debiles))


def analizar(ruta: Path, api_key=None, permitir_subida: bool = False) -> dict:
    fuertes, debiles = examinar(ruta)
    return {"malicious": len(fuertes), "suspicious": len(debiles),
            "harmless": 0 if (fuertes or debiles) else 1, "undetected": 0,
            "motivos": fuertes + debiles}


def clasificar(stats: dict):
    det = stats.get("malicious", 0) + stats.get("suspicious", 0)
    return ("infectado" if det > 0 else "sano"), det


def mover_archivo(ruta: Path, destino: Path):
    nuevo = destino / ruta.name
    if nuevo.exists():
        nuevo = destino / f"{ruta.stem}_{datetime.now():%Y%m%d_%H%M%S}{ruta.suffix}"
    shutil.move(str(ruta), str(nuevo))
