"""Inspección estática y segura de archivos sospechosos.

Solo LEE bytes del archivo: no lo ejecuta, no lo descomprime y no extrae nada.
Todo lo que devuelve es texto que la plantilla muestra escapado (nunca como HTML).
"""
import math
import re
import struct
import zipfile
from pathlib import Path

LEER_MAX = 1024 * 1024           # bytes que se leen para entropía, cadenas y firma
MAX_FILAS = 300                  # filas que se muestran de un ZIP
MAX_ENTRADAS_ZIP = 5000          # un ZIP con más entradas no se abre (evita agotar memoria)
MAX_CADENAS = 80

EXT_EJECUTABLES = {".exe", ".dll", ".scr", ".sys", ".com"}
EXT_PELIGROSAS = EXT_EJECUTABLES | {".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse",
                                    ".wsf", ".hta", ".lnk", ".jar", ".msi", ".reg", ".sh"}
DOBLE_EXTENSION = re.compile(r"\.(pdf|docx?|xlsx?|pptx?|jpe?g|png|gif|txt)\.(exe|scr|bat|cmd|com|js|vbs|lnk|hta)$", re.I)
BIDI = set("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")   # trucos de texto invertido

FIRMAS = [
    (b"MZ", "Ejecutable de Windows (PE)"),
    (b"\x7fELF", "Ejecutable de Linux (ELF)"),
    (b"\xcf\xfa\xed\xfe", "Ejecutable de macOS (Mach-O)"),
    (b"%PDF", "Documento PDF"),
    (b"PK\x03\x04", "Archivo ZIP"),
    (b"PK\x05\x06", "Archivo ZIP vacío"),
    (b"Rar!", "Archivo RAR"),
    (b"7z\xbc\xaf\x27\x1c", "Archivo 7-Zip"),
    (b"\x1f\x8b", "Archivo comprimido gzip"),
    (b"\xd0\xcf\x11\xe0", "Documento antiguo de Office (OLE2)"),
    (b"#!", "Script con intérprete"),
    (b"\x89PNG", "Imagen PNG"),
    (b"\xff\xd8\xff", "Imagen JPEG"),
    (b"GIF8", "Imagen GIF"),
]


def _limpio(texto, maximo=200):
    """Quita caracteres de control y de inversión de texto; recorta."""
    texto = "".join(c if c.isprintable() and c not in BIDI else "\ufffd" for c in texto)
    return texto[:maximo] + ("…" if len(texto) > maximo else "")


def _entropia(datos):
    if not datos:
        return 0.0
    total = len(datos)
    cuentas = [0] * 256
    for b in datos:
        cuentas[b] += 1
    return -sum(c / total * math.log2(c / total) for c in cuentas if c)


def _volcado_hex(datos, n=256):
    filas = []
    for i in range(0, min(len(datos), n), 16):
        trozo = datos[i:i + 16]
        hexa = " ".join(f"{b:02x}" for b in trozo)
        ascii_ = "".join(chr(b) if 32 <= b < 127 else "." for b in trozo)
        filas.append(f"{i:08x}  {hexa:<47}  {ascii_}")
    return "\n".join(filas)


def _cadenas(datos):
    vistas, salida = set(), []
    for m in re.finditer(rb"[\x20-\x7e]{6,}", datos):
        s = m.group().decode("ascii")[:140]
        s = s.replace("http", "hxxp").replace("HTTP", "HXXP").replace("://", "[://]")  # enlaces inofensivos
        if s not in vistas:
            vistas.add(s)
            salida.append(s)
            if len(salida) >= MAX_CADENAS:
                break
    return salida


def _alertas_entrada(nombre_real, info):
    avisos = []
    ruta = nombre_real.replace("\\", "/")
    ext = Path(ruta).suffix.lower()
    if ext in EXT_PELIGROSAS:
        avisos.append("Ejecutable o script")
    if ruta.lower().endswith("vbaproject.bin"):
        avisos.append("Macros VBA")
    if ".." in ruta.split("/") or ruta.startswith("/") or re.match(r"^[a-zA-Z]:", ruta):
        avisos.append("Ruta sospechosa")
    if DOBLE_EXTENSION.search(ruta):
        avisos.append("Doble extensión")
    if info.flag_bits & 0x1:
        avisos.append("Cifrado")
    if info.file_size > 10 * 1024 * 1024 and info.file_size > 100 * max(info.compress_size, 1):
        avisos.append("Compresión extrema")
    return avisos


def _listar_zip(ruta):
    """Lee solo el directorio central del ZIP; devuelve (entradas, total) o (None, total)."""
    with open(ruta, "rb") as f:
        f.seek(0, 2)
        f.seek(max(0, f.tell() - 65557))
        cola = f.read()
    pos = cola.rfind(b"PK\x05\x06")
    if pos < 0 or len(cola) < pos + 22:
        raise zipfile.BadZipFile("no se encontró el directorio central")
    total = struct.unpack("<H", cola[pos + 10:pos + 12])[0]
    if total == 0xFFFF or total > MAX_ENTRADAS_ZIP:
        return None, total
    with zipfile.ZipFile(ruta) as z:
        infos = z.infolist()
    entradas = [{"nombre": _limpio(i.filename), "tamano": i.file_size, "comprimido": i.compress_size,
                 "alertas": _alertas_entrada(i.filename, i), "real": i.filename} for i in infos]
    return entradas, len(infos)


def _subtipo_zip(nombres):
    if "[Content_Types].xml" in nombres:
        if any(n.startswith("word/") for n in nombres):
            return "Documento Word (Office Open XML)"
        if any(n.startswith("xl/") for n in nombres):
            return "Hoja de Excel (Office Open XML)"
        if any(n.startswith("ppt/") for n in nombres):
            return "Presentación de PowerPoint (Office Open XML)"
    if "META-INF/MANIFEST.MF" in nombres:
        return "Paquete Java (JAR)"
    if "AndroidManifest.xml" in nombres:
        return "Aplicación Android (APK)"
    return None


def inspeccionar(ruta: Path, nombre_original: str = "") -> dict:
    ruta = Path(ruta)
    with open(ruta, "rb") as f:
        datos = f.read(LEER_MAX)

    tipo = next((t for firma, t in FIRMAS if datos.startswith(firma)), None)
    if tipo is None:
        if not datos:
            tipo = "Archivo vacío"
        elif sum(32 <= b < 127 or b in (9, 10, 13) for b in datos[:4096]) / len(datos[:4096]) > 0.95:
            tipo = "Texto plano"
        else:
            tipo = "Binario sin firma conocida"

    info = {"tamano": ruta.stat().st_size, "tipo": tipo, "entradas": None, "total_entradas": 0,
            "oculto": 0, "nota_zip": None, "alertas": [],
            "hex": _volcado_hex(datos), "cadenas": _cadenas(datos)}

    entropia = _entropia(datos)
    info["entropia"] = round(entropia, 2)
    info["entropia_texto"] = ("muy alta: probablemente cifrado o empaquetado" if entropia > 7.5 else
                              "alta" if entropia > 6.8 else "normal")
    if entropia > 7.5 and not tipo.startswith(("Archivo ZIP", "Imagen", "Archivo comprimido", "Archivo RAR", "Archivo 7-Zip")):
        info["alertas"].append("Entropía muy alta: el contenido parece cifrado u ofuscado.")

    if tipo == "Archivo ZIP":
        try:
            entradas, total = _listar_zip(ruta)
            info["total_entradas"] = total
            if entradas is None:
                info["nota_zip"] = f"Tiene {total} entradas o más; no se lista por seguridad."
            else:
                subtipo = _subtipo_zip({e["real"] for e in entradas})
                if subtipo:
                    info["tipo"] = subtipo
                entradas.sort(key=lambda e: not e["alertas"])        # primero las sospechosas
                info["oculto"] = max(0, len(entradas) - MAX_FILAS)
                info["entradas"] = entradas[:MAX_FILAS]
                if any("Macros VBA" in e["alertas"] for e in entradas):
                    info["alertas"].append("Contiene macros VBA: es la vía habitual de los documentos maliciosos.")
                if any(e["alertas"] and e["alertas"] != ["Cifrado"] for e in entradas):
                    info["alertas"].append("Hay entradas marcadas como sospechosas en la lista de contenido.")
        except (zipfile.BadZipFile, struct.error, OSError, ValueError):
            info["nota_zip"] = "El ZIP está dañado o es inusual: no se pudo leer su lista de contenido."

    ext = Path(nombre_original).suffix.lower()
    if tipo.startswith("Ejecutable") and ext not in EXT_EJECUTABLES and ext != "":
        info["alertas"].append(f"Es un ejecutable, pero su extensión dice «{_limpio(ext, 20)}»: posible disfraz.")
    if tipo.startswith("Documento antiguo de Office"):
        info["alertas"].append("Formato antiguo de Office: puede contener macros ocultas.")
    return info
