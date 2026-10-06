"""Motor de análisis con VirusTotal (misma lógica que el script original)."""
import hashlib
import shutil
import time
from datetime import datetime
from pathlib import Path

import requests

URL_API = "https://www.virustotal.com/api/v3"
LIMITE_SUBIDA = 32 * 1024 * 1024     # 32 MB: límite de subida normal
ESPERA = 16                          # API gratuita: 4 peticiones/min
TIMEOUT_ANALISIS = 600               # máximo 10 min esperando un resultado


def _cabeceras(api_key):
    return {"x-apikey": api_key}


def calcular_sha256(ruta: Path) -> str:
    sha = hashlib.sha256()
    with open(ruta, "rb") as f:
        for bloque in iter(lambda: f.read(1024 * 1024), b""):
            sha.update(bloque)
    return sha.hexdigest()


def consultar_hash(hash_archivo, api_key):
    """Estadísticas si VirusTotal ya conoce el archivo; None si no."""
    r = requests.get(f"{URL_API}/files/{hash_archivo}", headers=_cabeceras(api_key), timeout=60)
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()["data"]["attributes"]["last_analysis_stats"]


def subir_archivo(ruta: Path, api_key) -> str:
    """Sube el archivo y devuelve el ID del análisis."""
    url = f"{URL_API}/files"
    if ruta.stat().st_size > LIMITE_SUBIDA:
        r = requests.get(f"{URL_API}/files/upload_url", headers=_cabeceras(api_key), timeout=60)
        r.raise_for_status()
        url = r.json()["data"]
    with open(ruta, "rb") as f:
        r = requests.post(url, headers=_cabeceras(api_key), files={"file": (ruta.name, f)}, timeout=300)
    r.raise_for_status()
    return r.json()["data"]["id"]


def esperar_resultado(id_analisis, api_key) -> dict:
    inicio = time.time()
    while time.time() - inicio < TIMEOUT_ANALISIS:
        r = requests.get(f"{URL_API}/analyses/{id_analisis}", headers=_cabeceras(api_key), timeout=60)
        r.raise_for_status()
        atributos = r.json()["data"]["attributes"]
        if atributos["status"] == "completed":
            return atributos["stats"]
        time.sleep(ESPERA)
    raise TimeoutError("VirusTotal tardó demasiado en responder")


def analizar(ruta: Path, api_key, permitir_subida: bool = False):
    """Estadísticas de VirusTotal para un archivo.

    Por privacidad, por defecto SOLO se consulta el hash (SHA-256): el contenido del
    archivo no sale del servidor. Si VirusTotal no conoce el archivo devuelve None, y
    únicamente se sube cuando el llamador pasa permitir_subida=True (confirmación
    explícita del usuario).
    """
    stats = consultar_hash(calcular_sha256(ruta), api_key)
    if stats:
        return stats
    if not permitir_subida:
        return None
    return esperar_resultado(subir_archivo(ruta, api_key), api_key)


def clasificar(stats: dict):
    """('infectado' | 'sano', nº de detecciones)."""
    detecciones = stats.get("malicious", 0) + stats.get("suspicious", 0)
    return ("infectado" if detecciones > 0 else "sano"), detecciones


def mover_archivo(ruta: Path, destino: Path):
    nuevo = destino / ruta.name
    if nuevo.exists():
        marca = datetime.now().strftime("%Y%m%d_%H%M%S")
        nuevo = destino / f"{ruta.stem}_{marca}{ruta.suffix}"
    shutil.move(str(ruta), str(nuevo))
