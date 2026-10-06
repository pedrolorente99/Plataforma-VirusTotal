# Plataforma de detección de archivos

Aplicación web (Flask) donde los usuarios suben archivos para detectar posible malware.

📖 **[Guía de uso paso a paso, con capturas](docs/GUIA.md)**

## Dos modos de funcionamiento

| Modo | Cuándo se activa | Qué hace |
|------|------------------|----------|
| **Demo (local)** | No hay `VT_API_KEY` | Análisis local con firmas (hash, EICAR) y heurísticas. Sin API ni internet. |
| **VirusTotal** | `VT_API_KEY` definida en `.env` | Consulta el hash en VirusTotal y, con permiso del usuario, sube el archivo. |

> El modo demo es **solo para probar la plataforma**; no sustituye a un antivirus real.

## Probarlo (modo demo)

```bash
git clone https://github.com/pedrolorente99/Plataforma-VirusTotal.git
cd Plataforma-VirusTotal
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 generar_muestras_demo.py     # crea archivos inofensivos de prueba
python3 app.py                       # abre http://127.0.0.1:5001
```

Regístrate, sube los archivos de `muestras_demo/` y pulsa **Analizar**.
Para crear un administrador: `python3 crear_admin.py`.

## Modo VirusTotal

Copia `.env.example` a `.env` y rellena `VT_API_KEY` y `SECRET_KEY`.
